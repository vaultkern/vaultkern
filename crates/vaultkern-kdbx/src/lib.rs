use std::collections::{BTreeMap, HashMap};
use std::io::{Cursor as IoCursor, Read, Write};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use flate2::{Compression as GzipCompression, read::GzDecoder, write::GzEncoder};
use thiserror::Error;
use uuid::Uuid;
use vaultkern_crypto::{
    ChaCha20Stream, CompositeKey, CryptoError, KdfProfile, Salsa20Stream, aes256_cbc_decrypt,
    aes256_cbc_encrypt, chacha20_ietf_decrypt, chacha20_ietf_encrypt, hmac_sha256, random_bytes,
    sha256_bytes, sha512_bytes, twofish_cbc_decrypt, twofish_cbc_encrypt,
};
use vaultkern_model::{
    Attachment, AutoTypeAssociation, AutoTypeConfig, CustomDataBlock, CustomDataItem, CustomField,
    CustomIcon, DeletedObject, Entry, EntryRawState, Group, GroupRawState, GroupTimes,
    MemoryProtection, MetaRawState, OpaqueXmlAnchor, OpaqueXmlFragment, PasskeyRecord,
    RootRawState, TotpAlgorithm, TotpSpec, Vault,
};
use xmltree::{Element, XMLNode};

#[derive(Debug, Error)]
pub enum KdbxError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("invalid value")]
    InvalidValue,
    #[error("header hash mismatch")]
    HeaderHashMismatch,
    #[error("header hmac mismatch")]
    HeaderHmacMismatch,
    #[error("payload block hmac mismatch")]
    PayloadHmacMismatch,
    #[error("payload block hash mismatch")]
    PayloadHashMismatch,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("unsupported KDF")]
    UnsupportedKdf,
    #[error("unsupported inner stream")]
    UnsupportedInnerStream,
    #[error("xml error: {0}")]
    Xml(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

pub type Result<T> = std::result::Result<T, KdbxError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxVersion {
    V2_0,
    V3_0,
    V3_1,
    V4_0,
    V4_1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxCipher {
    Aes256,
    ChaCha20,
    Twofish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantValue {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VariantDictionary {
    items: BTreeMap<String, VariantValue>,
}

impl VariantDictionary {
    pub fn insert(&mut self, key: impl Into<String>, value: VariantValue) {
        self.items.insert(key.into(), value);
    }

    pub fn get(&self, key: &str) -> Option<&VariantValue> {
        self.items.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &VariantValue)> {
        self.items.iter()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(0x0100_u16.to_le_bytes());

        for (key, value) in &self.items {
            let name = key.as_bytes();
            let (kind, value_bytes) = encode_variant_value(value);
            bytes.push(kind);
            bytes.extend((name.len() as i32).to_le_bytes());
            bytes.extend(name);
            bytes.extend((value_bytes.len() as i32).to_le_bytes());
            bytes.extend(value_bytes);
        }

        bytes.push(0);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let version = cursor.read_u16()?;
        if version != 0x0100 {
            return Err(KdbxError::InvalidValue);
        }

        let mut items = BTreeMap::new();
        loop {
            let kind = cursor.read_u8()?;
            if kind == 0 {
                break;
            }
            let name_len = cursor.read_i32()? as usize;
            let name = String::from_utf8(cursor.read_exact(name_len)?.to_vec())
                .map_err(|_| KdbxError::InvalidValue)?;
            let value_len = cursor.read_i32()? as usize;
            let value_bytes = cursor.read_exact(value_len)?;
            let value = decode_variant_value(kind, value_bytes)?;
            items.insert(name, value);
        }

        Ok(Self { items })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownHeaderField {
    pub id: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdbxHeader {
    pub version: KdbxVersion,
    pub cipher: KdbxCipher,
    pub compression: Compression,
    pub master_seed: [u8; 32],
    pub encryption_iv: Vec<u8>,
    pub kdf_parameters: VariantDictionary,
    pub public_custom_data: VariantDictionary,
    pub unknown_fields: Vec<UnknownHeaderField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Kdbx3Header {
    version: KdbxVersion,
    cipher: KdbxCipher,
    compression: Compression,
    master_seed: [u8; 32],
    transform_seed: [u8; 32],
    transform_rounds: u64,
    encryption_iv: Vec<u8>,
    protected_stream_key: Vec<u8>,
    stream_start_bytes: Vec<u8>,
    inner_random_stream_id: u32,
    unknown_fields: Vec<UnknownHeaderField>,
}

impl KdbxHeader {
    pub fn new(version: KdbxVersion, cipher: KdbxCipher) -> Self {
        Self {
            version,
            cipher,
            compression: Compression::Gzip,
            master_seed: [0_u8; 32],
            encryption_iv: Vec::new(),
            kdf_parameters: VariantDictionary::default(),
            public_custom_data: VariantDictionary::default(),
            unknown_fields: Vec::new(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(0x9AA2_D903_u32.to_le_bytes());
        bytes.extend(0xB54B_FB67_u32.to_le_bytes());
        bytes.extend(version_to_u32(self.version).to_le_bytes());
        write_field(&mut bytes, 2, cipher_uuid(self.cipher).as_bytes());
        write_field(
            &mut bytes,
            3,
            &(match self.compression {
                Compression::None => 0_u32,
                Compression::Gzip => 1_u32,
            })
            .to_le_bytes(),
        );
        write_field(&mut bytes, 4, &self.master_seed);
        write_field(&mut bytes, 7, &self.encryption_iv);
        write_field(&mut bytes, 11, &self.kdf_parameters.encode()?);
        write_field(&mut bytes, 12, &self.public_custom_data.encode()?);
        for field in &self.unknown_fields {
            write_field(&mut bytes, field.id, &field.data);
        }
        write_field(&mut bytes, 0, b"\r\n\r\n");
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (header, _) = Self::decode_with_consumed(bytes)?;
        Ok(header)
    }

    pub fn decode_with_consumed(bytes: &[u8]) -> Result<(Self, usize)> {
        let mut cursor = Cursor::new(bytes);
        let sig1 = cursor.read_u32()?;
        let sig2 = cursor.read_u32()?;
        if sig1 != 0x9AA2_D903 || sig2 != 0xB54B_FB67 {
            return Err(KdbxError::InvalidValue);
        }
        let version = u32_to_version(cursor.read_u32()?)?;
        if version != KdbxVersion::V4_1 && version != KdbxVersion::V4_0 {
            return Err(KdbxError::UnsupportedVersion);
        }

        let mut header = KdbxHeader::new(version, KdbxCipher::Aes256);
        loop {
            let id = cursor.read_u8()?;
            let len = cursor.read_i32()? as usize;
            let data = cursor.read_exact(len)?.to_vec();
            match id {
                0 => break,
                2 => {
                    header.cipher = uuid_to_cipher(
                        Uuid::from_slice(&data).map_err(|_| KdbxError::InvalidValue)?,
                    )?
                }
                3 => {
                    let value =
                        u32::from_le_bytes(data.try_into().map_err(|_| KdbxError::InvalidValue)?);
                    header.compression = match value {
                        0 => Compression::None,
                        1 => Compression::Gzip,
                        _ => return Err(KdbxError::InvalidValue),
                    };
                }
                4 => {
                    header.master_seed = data.try_into().map_err(|_| KdbxError::InvalidValue)?;
                }
                7 => header.encryption_iv = data,
                11 => header.kdf_parameters = VariantDictionary::decode(&data)?,
                12 => header.public_custom_data = VariantDictionary::decode(&data)?,
                _ => header.unknown_fields.push(UnknownHeaderField { id, data }),
            }
        }

        Ok((header, cursor.position()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveKdf {
    AesKdbx4 {
        rounds: u64,
    },
    Argon2id {
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveProfile {
    pub version: KdbxVersion,
    pub cipher: KdbxCipher,
    pub compression: Compression,
    pub kdf: SaveKdf,
}

impl SaveProfile {
    pub fn recommended() -> Self {
        Self {
            version: KdbxVersion::V4_1,
            cipher: KdbxCipher::Aes256,
            compression: Compression::Gzip,
            kdf: SaveKdf::Argon2id {
                iterations: 2,
                memory_kib: 64 * 1024,
                parallelism: 1,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdbxHeaderSummary {
    pub version: KdbxVersion,
    pub cipher: KdbxCipher,
    pub compression: Compression,
    pub public_custom_data: BTreeMap<String, Vec<u8>>,
}

pub fn required_version(vault: &Vault) -> KdbxVersion {
    if group_requires_41(&vault.root) {
        KdbxVersion::V4_1
    } else {
        KdbxVersion::V4_0
    }
}

pub fn inspect_kdbx_header(bytes: &[u8]) -> Result<KdbxHeaderSummary> {
    match detect_file_version(bytes)? {
        KdbxVersion::V2_0 | KdbxVersion::V3_0 | KdbxVersion::V3_1 => {
            let (header, _) = decode_kdbx3_header(bytes)?;
            Ok(KdbxHeaderSummary {
                version: header.version,
                cipher: header.cipher,
                compression: header.compression,
                public_custom_data: BTreeMap::new(),
            })
        }
        KdbxVersion::V4_0 | KdbxVersion::V4_1 => {
            let (header, _) = KdbxHeader::decode_with_consumed(bytes)?;
            Ok(KdbxHeaderSummary {
                version: header.version,
                cipher: header.cipher,
                compression: header.compression,
                public_custom_data: header
                    .public_custom_data
                    .iter()
                    .filter_map(|(key, value)| match value {
                        VariantValue::Bytes(bytes) => Some((key.clone(), bytes.clone())),
                        _ => None,
                    })
                    .collect(),
            })
        }
    }
}

pub fn save_kdbx(
    vault: &Vault,
    composite_key: &CompositeKey,
    profile: &SaveProfile,
) -> Result<Vec<u8>> {
    let mut header = KdbxHeader::new(profile.version, profile.cipher);
    header.compression = profile.compression;
    header.master_seed = random_array_32();
    header.encryption_iv = random_iv(profile.cipher);
    let kdf = build_kdf_profile(&profile.kdf);
    header.kdf_parameters = kdf_to_variant_dict(&kdf);
    for (key, value) in &vault.public_custom_data {
        header
            .public_custom_data
            .insert(key.clone(), VariantValue::Bytes(value.clone()));
    }

    let raw_key = composite_key.raw_key()?;
    let transformed = kdf.derive_key(&raw_key)?;
    let encryption_key = sha256_seeded(&header.master_seed, &transformed);
    let mac_seed = mac_seed(&header.master_seed, &transformed);

    let mut binaries = Vec::new();
    let attachment_refs = collect_attachment_refs(vault, &mut binaries);
    let inner_key = random_bytes(64);
    let inner_header = build_inner_header(&inner_key, &binaries);
    let xml = build_xml(vault, &attachment_refs, &inner_key, profile.version)?;

    let mut payload = Vec::new();
    payload.extend(inner_header);
    payload.extend(xml);

    let payload = match profile.compression {
        Compression::None => payload,
        Compression::Gzip => gzip_compress(&payload)?,
    };

    let encrypted_payload = encrypt_payload(
        profile.cipher,
        &encryption_key,
        &header.encryption_iv,
        &payload,
    )?;
    let block_stream = encode_block_stream(&mac_seed, &encrypted_payload)?;

    let header_bytes = header.encode()?;
    let header_hash = sha256_bytes(&header_bytes);
    let header_hmac = header_hmac(&mac_seed, &header_bytes)?;

    let mut file = Vec::new();
    file.extend(header_bytes);
    file.extend(header_hash);
    file.extend(header_hmac);
    file.extend(block_stream);
    Ok(file)
}

pub fn load_kdbx(bytes: &[u8], composite_key: &CompositeKey) -> Result<Vault> {
    match detect_file_version(bytes)? {
        KdbxVersion::V2_0 | KdbxVersion::V3_0 | KdbxVersion::V3_1 => {
            load_kdbx3(bytes, composite_key)
        }
        KdbxVersion::V4_0 | KdbxVersion::V4_1 => load_kdbx4(bytes, composite_key),
    }
}

fn load_kdbx4(bytes: &[u8], composite_key: &CompositeKey) -> Result<Vault> {
    let (header, header_len) = KdbxHeader::decode_with_consumed(bytes)?;
    let mut cursor = Cursor::new(&bytes[header_len..]);
    let stored_header_hash = cursor.read_exact(32)?.to_vec();
    let stored_header_hmac = cursor.read_exact(32)?.to_vec();
    let payload_bytes = cursor.read_remaining().to_vec();

    let header_bytes = &bytes[..header_len];
    if sha256_bytes(header_bytes).as_slice() != stored_header_hash.as_slice() {
        return Err(KdbxError::HeaderHashMismatch);
    }

    let raw_key = composite_key.raw_key()?;
    let kdf = kdf_from_variant_dict(&header.kdf_parameters)?;
    let transformed = kdf.derive_key(&raw_key)?;
    let encryption_key = sha256_seeded(&header.master_seed, &transformed);
    let mac_seed = mac_seed(&header.master_seed, &transformed);

    if header_hmac(&mac_seed, header_bytes)?.as_slice() != stored_header_hmac.as_slice() {
        return Err(KdbxError::HeaderHmacMismatch);
    }

    let encrypted_payload = decode_block_stream(&mac_seed, &payload_bytes)?;
    let payload = decrypt_payload(
        header.cipher,
        &encryption_key,
        &header.encryption_iv,
        &encrypted_payload,
    )?;
    let payload = match header.compression {
        Compression::None => payload,
        Compression::Gzip => gzip_decompress(&payload)?,
    };

    let (inner_algorithm, inner_key, binaries, consumed) = parse_inner_header(&payload)?;
    let xml_bytes = &payload[consumed..];
    parse_xml(xml_bytes, &header, inner_algorithm, &inner_key, &binaries)
}

fn load_kdbx3(bytes: &[u8], composite_key: &CompositeKey) -> Result<Vault> {
    let (header, header_len) = decode_kdbx3_header(bytes)?;
    let raw_key = composite_key.raw_key()?;
    let transformed = KdfProfile::AesKdbx3 {
        rounds: header.transform_rounds,
        salt: header.transform_seed,
    }
    .derive_key(&raw_key)?;
    let encryption_key = sha256_seeded(&header.master_seed, &transformed);
    let encrypted_payload = &bytes[header_len..];
    let payload = decrypt_payload(
        header.cipher,
        &encryption_key,
        &header.encryption_iv,
        encrypted_payload,
    )?;

    if payload.len() < header.stream_start_bytes.len()
        || &payload[..header.stream_start_bytes.len()] != header.stream_start_bytes.as_slice()
    {
        return Err(KdbxError::HeaderHashMismatch);
    }

    let block_payload = decode_legacy_block_stream(&payload[header.stream_start_bytes.len()..])?;
    let xml_bytes = match header.compression {
        Compression::None => block_payload,
        Compression::Gzip => gzip_decompress(&block_payload)?,
    };

    parse_kdbx3_xml(
        &xml_bytes,
        &bytes[..header_len],
        &header.protected_stream_key,
        header.inner_random_stream_id,
    )
}

fn detect_file_version(bytes: &[u8]) -> Result<KdbxVersion> {
    let mut cursor = Cursor::new(bytes);
    let sig1 = cursor.read_u32()?;
    let sig2 = cursor.read_u32()?;
    if sig1 != 0x9AA2_D903 || sig2 != 0xB54B_FB67 {
        return Err(KdbxError::InvalidValue);
    }
    u32_to_version(cursor.read_u32()?)
}

fn decode_kdbx3_header(bytes: &[u8]) -> Result<(Kdbx3Header, usize)> {
    let mut cursor = Cursor::new(bytes);
    let sig1 = cursor.read_u32()?;
    let sig2 = cursor.read_u32()?;
    if sig1 != 0x9AA2_D903 || sig2 != 0xB54B_FB67 {
        return Err(KdbxError::InvalidValue);
    }
    let version = u32_to_version(cursor.read_u32()?)?;
    if version != KdbxVersion::V2_0 && version != KdbxVersion::V3_0 && version != KdbxVersion::V3_1
    {
        return Err(KdbxError::UnsupportedVersion);
    }

    let mut header = Kdbx3Header {
        version,
        cipher: KdbxCipher::Aes256,
        compression: Compression::Gzip,
        master_seed: [0_u8; 32],
        transform_seed: [0_u8; 32],
        transform_rounds: 0,
        encryption_iv: Vec::new(),
        protected_stream_key: Vec::new(),
        stream_start_bytes: Vec::new(),
        inner_random_stream_id: 0,
        unknown_fields: Vec::new(),
    };

    loop {
        let id = cursor.read_u8()?;
        let len = cursor.read_u16()? as usize;
        let data = cursor.read_exact(len)?.to_vec();
        match id {
            0 => break,
            2 => {
                header.cipher =
                    uuid_to_cipher(Uuid::from_slice(&data).map_err(|_| KdbxError::InvalidValue)?)?
            }
            3 => {
                let value =
                    u32::from_le_bytes(data.try_into().map_err(|_| KdbxError::InvalidValue)?);
                header.compression = match value {
                    0 => Compression::None,
                    1 => Compression::Gzip,
                    _ => return Err(KdbxError::InvalidValue),
                };
            }
            4 => header.master_seed = data.try_into().map_err(|_| KdbxError::InvalidValue)?,
            5 => header.transform_seed = data.try_into().map_err(|_| KdbxError::InvalidValue)?,
            6 => {
                header.transform_rounds =
                    u64::from_le_bytes(data.try_into().map_err(|_| KdbxError::InvalidValue)?)
            }
            7 => header.encryption_iv = data,
            8 => header.protected_stream_key = data,
            9 => header.stream_start_bytes = data,
            10 => {
                header.inner_random_stream_id =
                    u32::from_le_bytes(data.try_into().map_err(|_| KdbxError::InvalidValue)?)
            }
            _ => header.unknown_fields.push(UnknownHeaderField { id, data }),
        }
    }

    Ok((header, cursor.position()))
}

pub const AES256_UUID: Uuid = Uuid::from_bytes([
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
]);
pub const CHACHA20_UUID: Uuid = Uuid::from_bytes([
    0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A,
]);
pub const TWOFISH_UUID: Uuid = Uuid::from_bytes([
    0xAD, 0x68, 0xF2, 0x9F, 0x57, 0x6F, 0x4B, 0xB9, 0xA3, 0x6A, 0xD4, 0x7A, 0xF9, 0x65, 0x34, 0x6C,
]);
pub const KDF_AES_KDBX4_UUID: Uuid = Uuid::from_bytes([
    0x7C, 0x02, 0xBB, 0x82, 0x79, 0xA7, 0x4A, 0xC0, 0x92, 0x7D, 0x11, 0x4A, 0x00, 0x69, 0x2E, 0xB7,
]);
pub const KDF_AES_KDBX3_UUID: Uuid = Uuid::from_bytes([
    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
]);
pub const KDF_ARGON2D_UUID: Uuid = Uuid::from_bytes([
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
]);
pub const KDF_ARGON2ID_UUID: Uuid = Uuid::from_bytes([
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
]);

fn encode_variant_value(value: &VariantValue) -> (u8, Vec<u8>) {
    match value {
        VariantValue::UInt32(value) => (0x04, value.to_le_bytes().to_vec()),
        VariantValue::UInt64(value) => (0x05, value.to_le_bytes().to_vec()),
        VariantValue::Bool(value) => (0x08, vec![u8::from(*value)]),
        VariantValue::Int32(value) => (0x0C, value.to_le_bytes().to_vec()),
        VariantValue::Int64(value) => (0x0D, value.to_le_bytes().to_vec()),
        VariantValue::String(value) => (0x18, value.as_bytes().to_vec()),
        VariantValue::Bytes(value) => (0x42, value.clone()),
    }
}

fn decode_variant_value(kind: u8, bytes: &[u8]) -> Result<VariantValue> {
    Ok(match kind {
        0x04 => VariantValue::UInt32(u32::from_le_bytes(
            bytes.try_into().map_err(|_| KdbxError::InvalidValue)?,
        )),
        0x05 => VariantValue::UInt64(u64::from_le_bytes(
            bytes.try_into().map_err(|_| KdbxError::InvalidValue)?,
        )),
        0x08 => VariantValue::Bool(bytes.first().copied().ok_or(KdbxError::UnexpectedEof)? != 0),
        0x0C => VariantValue::Int32(i32::from_le_bytes(
            bytes.try_into().map_err(|_| KdbxError::InvalidValue)?,
        )),
        0x0D => VariantValue::Int64(i64::from_le_bytes(
            bytes.try_into().map_err(|_| KdbxError::InvalidValue)?,
        )),
        0x18 => VariantValue::String(
            String::from_utf8(bytes.to_vec()).map_err(|_| KdbxError::InvalidValue)?,
        ),
        0x42 => VariantValue::Bytes(bytes.to_vec()),
        _ => return Err(KdbxError::InvalidValue),
    })
}

fn build_kdf_profile(profile: &SaveKdf) -> KdfProfile {
    match profile {
        SaveKdf::AesKdbx4 { rounds } => KdfProfile::AesKdbx4 {
            rounds: *rounds,
            salt: random_array_32(),
        },
        SaveKdf::Argon2id {
            iterations,
            memory_kib,
            parallelism,
        } => KdfProfile::Argon2id {
            iterations: *iterations,
            memory_kib: *memory_kib,
            parallelism: *parallelism,
            salt: random_bytes(32),
        },
    }
}

fn kdf_to_variant_dict(kdf: &KdfProfile) -> VariantDictionary {
    let mut dict = VariantDictionary::default();
    match kdf {
        KdfProfile::AesKdbx4 { rounds, salt } => {
            dict.insert(
                "$UUID",
                VariantValue::Bytes(KDF_AES_KDBX4_UUID.into_bytes().to_vec()),
            );
            dict.insert("R", VariantValue::UInt64(*rounds));
            dict.insert("S", VariantValue::Bytes(salt.to_vec()));
        }
        KdfProfile::Argon2id {
            iterations,
            memory_kib,
            parallelism,
            salt,
        } => {
            dict.insert(
                "$UUID",
                VariantValue::Bytes(KDF_ARGON2ID_UUID.into_bytes().to_vec()),
            );
            dict.insert("V", VariantValue::UInt32(0x13));
            dict.insert("I", VariantValue::UInt64(u64::from(*iterations)));
            dict.insert("M", VariantValue::UInt64(u64::from(*memory_kib) * 1024));
            dict.insert("P", VariantValue::UInt32(*parallelism));
            dict.insert("S", VariantValue::Bytes(salt.clone()));
        }
        KdfProfile::AesKdbx3 { .. } | KdfProfile::Argon2d { .. } => {}
    }
    dict
}

fn kdf_from_variant_dict(dict: &VariantDictionary) -> Result<KdfProfile> {
    let uuid = match dict.get("$UUID") {
        Some(VariantValue::Bytes(bytes)) => {
            Uuid::from_slice(bytes).map_err(|_| KdbxError::InvalidValue)?
        }
        _ => return Err(KdbxError::UnsupportedKdf),
    };

    if uuid == KDF_AES_KDBX4_UUID || uuid == KDF_AES_KDBX3_UUID {
        let rounds = match dict.get("R") {
            Some(VariantValue::UInt64(value)) => *value,
            _ => return Err(KdbxError::UnsupportedKdf),
        };
        let salt = match dict.get("S") {
            Some(VariantValue::Bytes(bytes)) => bytes
                .clone()
                .try_into()
                .map_err(|_| KdbxError::InvalidValue)?,
            _ => return Err(KdbxError::UnsupportedKdf),
        };
        Ok(KdfProfile::AesKdbx4 { rounds, salt })
    } else if uuid == KDF_ARGON2D_UUID || uuid == KDF_ARGON2ID_UUID {
        let iterations = match dict.get("I") {
            Some(VariantValue::UInt64(value)) => *value as u32,
            _ => return Err(KdbxError::UnsupportedKdf),
        };
        let memory_kib = match dict.get("M") {
            Some(VariantValue::UInt64(value)) => (*value / 1024) as u32,
            _ => return Err(KdbxError::UnsupportedKdf),
        };
        let parallelism = match dict.get("P") {
            Some(VariantValue::UInt32(value)) => *value,
            _ => return Err(KdbxError::UnsupportedKdf),
        };
        let salt = match dict.get("S") {
            Some(VariantValue::Bytes(bytes)) => bytes.clone(),
            _ => return Err(KdbxError::UnsupportedKdf),
        };
        if uuid == KDF_ARGON2D_UUID {
            Ok(KdfProfile::Argon2d {
                iterations,
                memory_kib,
                parallelism,
                salt,
            })
        } else {
            Ok(KdfProfile::Argon2id {
                iterations,
                memory_kib,
                parallelism,
                salt,
            })
        }
    } else {
        Err(KdbxError::UnsupportedKdf)
    }
}

fn encrypt_payload(
    cipher: KdbxCipher,
    key: &[u8; 32],
    iv: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    match cipher {
        KdbxCipher::Aes256 => aes256_cbc_encrypt(
            key,
            &iv.try_into().map_err(|_| KdbxError::InvalidValue)?,
            payload,
        )
        .map_err(KdbxError::from),
        KdbxCipher::Twofish => twofish_cbc_encrypt(
            key,
            &iv.try_into().map_err(|_| KdbxError::InvalidValue)?,
            payload,
        )
        .map_err(KdbxError::from),
        KdbxCipher::ChaCha20 => chacha20_ietf_encrypt(
            key,
            &iv.try_into().map_err(|_| KdbxError::InvalidValue)?,
            payload,
        )
        .map_err(KdbxError::from),
    }
}

fn decrypt_payload(
    cipher: KdbxCipher,
    key: &[u8; 32],
    iv: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    match cipher {
        KdbxCipher::Aes256 => aes256_cbc_decrypt(
            key,
            &iv.try_into().map_err(|_| KdbxError::InvalidValue)?,
            payload,
        )
        .map_err(KdbxError::from),
        KdbxCipher::Twofish => twofish_cbc_decrypt(
            key,
            &iv.try_into().map_err(|_| KdbxError::InvalidValue)?,
            payload,
        )
        .map_err(KdbxError::from),
        KdbxCipher::ChaCha20 => chacha20_ietf_decrypt(
            key,
            &iv.try_into().map_err(|_| KdbxError::InvalidValue)?,
            payload,
        )
        .map_err(KdbxError::from),
    }
}

fn build_inner_header(inner_key: &[u8], binaries: &[InnerBinary]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_field(&mut bytes, 1, &3_i32.to_le_bytes());
    write_field(&mut bytes, 2, inner_key);
    for binary in binaries {
        let mut payload = Vec::with_capacity(binary.data.len() + 1);
        payload.push(if binary.protect_in_memory { 0x01 } else { 0x00 });
        payload.extend(&binary.data);
        write_field(&mut bytes, 3, &payload);
    }
    write_field(&mut bytes, 0, &[]);
    bytes
}

fn parse_inner_header(payload: &[u8]) -> Result<(u32, Vec<u8>, Vec<InnerBinary>, usize)> {
    let mut cursor = Cursor::new(payload);
    let mut inner_algorithm = 3_u32;
    let mut inner_key = None;
    let mut binaries = Vec::new();

    loop {
        let field_id = cursor.read_u8()?;
        let len = cursor.read_i32()? as usize;
        let data = cursor.read_exact(len)?.to_vec();
        match field_id {
            0 => break,
            1 => {
                inner_algorithm =
                    u32::from_le_bytes(data.try_into().map_err(|_| KdbxError::InvalidValue)?);
                if inner_algorithm != 2 && inner_algorithm != 3 {
                    return Err(KdbxError::UnsupportedInnerStream);
                }
            }
            2 => inner_key = Some(data),
            3 => {
                let (flag, bytes) = data.split_first().ok_or(KdbxError::InvalidValue)?;
                binaries.push(InnerBinary {
                    protect_in_memory: *flag & 0x01 == 0x01,
                    data: bytes.to_vec(),
                });
            }
            _ => {}
        }
    }

    Ok((
        inner_algorithm,
        inner_key.ok_or(KdbxError::InvalidValue)?,
        binaries,
        cursor.position(),
    ))
}

fn build_xml(
    vault: &Vault,
    attachment_refs: &HashMap<(usize, String), usize>,
    inner_key: &[u8],
    version: KdbxVersion,
) -> Result<Vec<u8>> {
    let mut root = Element::new("KeePassFile");

    let mut meta = Element::new("Meta");
    if let Some(generator) = &vault.generator {
        meta.children
            .push(XMLNode::Element(text_element("Generator", generator)));
    }
    if let Some(settings_changed) = vault.settings_changed {
        meta.children.push(XMLNode::Element(text_element(
            "SettingsChanged",
            &datetime_text(version, settings_changed),
        )));
    }
    meta.children
        .push(XMLNode::Element(text_element("DatabaseName", &vault.name)));
    if let Some(database_name_changed) = vault.database_name_changed {
        meta.children.push(XMLNode::Element(text_element(
            "DatabaseNameChanged",
            &datetime_text(version, database_name_changed),
        )));
    }
    if let Some(description) = &vault.description {
        meta.children.push(XMLNode::Element(text_element(
            "DatabaseDescription",
            description,
        )));
    } else if let Some(raw_description) = &vault.meta_raw_state.description_raw {
        meta.children.push(XMLNode::Element(text_element(
            "DatabaseDescription",
            raw_description,
        )));
    }
    if let Some(description_changed) = vault.description_changed {
        meta.children.push(XMLNode::Element(text_element(
            "DatabaseDescriptionChanged",
            &datetime_text(version, description_changed),
        )));
    }
    if let Some(default_username) = &vault.default_username {
        meta.children.push(XMLNode::Element(text_element(
            "DefaultUserName",
            default_username,
        )));
    } else if let Some(raw_default_username) = &vault.meta_raw_state.default_username_raw {
        meta.children.push(XMLNode::Element(text_element(
            "DefaultUserName",
            raw_default_username,
        )));
    }
    if let Some(default_username_changed) = vault.default_username_changed {
        meta.children.push(XMLNode::Element(text_element(
            "DefaultUserNameChanged",
            &datetime_text(version, default_username_changed),
        )));
    }
    if let Some(maintenance_history_days) = vault.maintenance_history_days {
        meta.children.push(XMLNode::Element(text_element(
            "MaintenanceHistoryDays",
            &maintenance_history_days.to_string(),
        )));
    }
    if let Some(color) = &vault.color {
        meta.children
            .push(XMLNode::Element(text_element("Color", color)));
    } else if let Some(raw_color) = &vault.meta_raw_state.color_raw {
        meta.children
            .push(XMLNode::Element(text_element("Color", raw_color)));
    }
    if let Some(memory_protection) = vault.memory_protection {
        meta.children
            .push(XMLNode::Element(memory_protection_to_xml(
                memory_protection,
            )));
    }
    if !vault.custom_icons.is_empty() || vault.meta_raw_state.has_custom_icons_node {
        meta.children.push(XMLNode::Element(custom_icons_to_xml(
            &vault.custom_icons,
            version,
        )));
    }
    if let Some(recycle_bin_enabled) = vault.recycle_bin_enabled {
        meta.children.push(XMLNode::Element(text_element(
            "RecycleBinEnabled",
            if recycle_bin_enabled { "True" } else { "False" },
        )));
    }
    if let Some(recycle_bin_group) = vault.recycle_bin_group {
        meta.children.push(XMLNode::Element(text_element(
            "RecycleBinUUID",
            &encode_uuid(recycle_bin_group),
        )));
    } else if let Some(raw_recycle_bin_group) = &vault.meta_raw_state.recycle_bin_group_raw {
        meta.children.push(XMLNode::Element(text_element(
            "RecycleBinUUID",
            raw_recycle_bin_group,
        )));
    }
    if let Some(recycle_bin_changed) = vault.recycle_bin_changed {
        meta.children.push(XMLNode::Element(text_element(
            "RecycleBinChanged",
            &datetime_text(version, recycle_bin_changed),
        )));
    }
    if let Some(entry_templates_group) = vault.entry_templates_group {
        meta.children.push(XMLNode::Element(text_element(
            "EntryTemplatesGroup",
            &encode_uuid(entry_templates_group),
        )));
    } else if let Some(raw_entry_templates_group) = &vault.meta_raw_state.entry_templates_group_raw
    {
        meta.children.push(XMLNode::Element(text_element(
            "EntryTemplatesGroup",
            raw_entry_templates_group,
        )));
    }
    if let Some(entry_templates_group_changed) = vault.entry_templates_group_changed {
        meta.children.push(XMLNode::Element(text_element(
            "EntryTemplatesGroupChanged",
            &datetime_text(version, entry_templates_group_changed),
        )));
    }
    if let Some(master_key_changed) = vault.master_key_changed {
        meta.children.push(XMLNode::Element(text_element(
            "MasterKeyChanged",
            &datetime_text(version, master_key_changed),
        )));
    }
    if let Some(master_key_change_rec) = vault.master_key_change_rec {
        meta.children.push(XMLNode::Element(text_element(
            "MasterKeyChangeRec",
            &master_key_change_rec.to_string(),
        )));
    }
    if let Some(master_key_change_force) = vault.master_key_change_force {
        meta.children.push(XMLNode::Element(text_element(
            "MasterKeyChangeForce",
            &master_key_change_force.to_string(),
        )));
    }
    if let Some(master_key_change_force_once) = vault.master_key_change_force_once {
        meta.children.push(XMLNode::Element(text_element(
            "MasterKeyChangeForceOnce",
            bool_text(master_key_change_force_once),
        )));
    }
    if let Some(last_selected_group) = vault.last_selected_group {
        meta.children.push(XMLNode::Element(text_element(
            "LastSelectedGroup",
            &encode_uuid(last_selected_group),
        )));
    }
    if let Some(last_top_visible_group) = vault.last_top_visible_group {
        meta.children.push(XMLNode::Element(text_element(
            "LastTopVisibleGroup",
            &encode_uuid(last_top_visible_group),
        )));
    }
    if let Some(history_max_items) = vault.history_max_items {
        meta.children.push(XMLNode::Element(text_element(
            "HistoryMaxItems",
            &history_max_items.to_string(),
        )));
    }
    if let Some(history_max_size) = vault.history_max_size {
        meta.children.push(XMLNode::Element(text_element(
            "HistoryMaxSize",
            &history_max_size.to_string(),
        )));
    }
    append_custom_data_blocks(
        &mut meta,
        &vault.meta_custom_data_blocks,
        &vault.meta_custom_data,
        true,
        version,
    )?;
    reorder_known_xml_nodes(&mut meta.children, &vault.meta_raw_state.node_order);
    append_opaque_xml(&mut meta, &vault.meta_opaque_xml)?;
    root.children.push(XMLNode::Element(meta));

    let mut root_node = Element::new("Root");
    let mut protected = ProtectedStream::new_chacha(inner_key)?;
    root_node.children.push(XMLNode::Element(group_to_xml(
        &vault.root,
        attachment_refs,
        &mut protected,
        version,
    )?));
    root_node
        .children
        .push(XMLNode::Element(deleted_objects_to_xml(
            &vault.deleted_objects,
            version,
        )));
    append_opaque_xml(&mut root_node, &vault.root_opaque_xml)?;
    root.children.push(XMLNode::Element(root_node));

    let mut bytes = Vec::new();
    root.write(&mut bytes)
        .map_err(|error| KdbxError::Xml(error.to_string()))?;
    Ok(bytes)
}

fn group_to_xml(
    group: &Group,
    attachment_refs: &HashMap<(usize, String), usize>,
    protected: &mut ProtectedStream,
    version: KdbxVersion,
) -> Result<Element> {
    let mut element = Element::new("Group");
    element.children.push(XMLNode::Element(text_element(
        "UUID",
        &encode_uuid(group.id),
    )));
    element
        .children
        .push(XMLNode::Element(text_element("Name", &group.title)));
    element
        .children
        .push(XMLNode::Element(text_element("Notes", &group.notes)));
    element.children.push(XMLNode::Element(text_element(
        "IconID",
        &group.icon_id.unwrap_or(0).to_string(),
    )));
    if let Some(custom_icon_id) = group.custom_icon_id {
        element.children.push(XMLNode::Element(text_element(
            "CustomIconUUID",
            &encode_uuid(custom_icon_id),
        )));
    }
    if !group.tags.is_empty() {
        element.children.push(XMLNode::Element(text_element(
            "Tags",
            &group.tags.iter().cloned().collect::<Vec<_>>().join(";"),
        )));
    }
    element.children.push(XMLNode::Element(group_times_to_xml(
        group.times.unwrap_or_else(default_group_times),
        version,
    )));
    element.children.push(XMLNode::Element(text_element(
        "IsExpanded",
        bool_text(group.flags.is_expanded.unwrap_or(true)),
    )));
    if let Some(default_sequence) = &group.default_auto_type_sequence {
        element.children.push(XMLNode::Element(text_element(
            "DefaultAutoTypeSequence",
            default_sequence,
        )));
    } else if let Some(default_sequence_raw) = &group.raw_state.default_auto_type_sequence_raw {
        element.children.push(XMLNode::Element(text_element(
            "DefaultAutoTypeSequence",
            default_sequence_raw,
        )));
    } else {
        element.children.push(XMLNode::Element(text_element(
            "DefaultAutoTypeSequence",
            "",
        )));
    }
    if let Some(enable_auto_type) = group.flags.enable_auto_type {
        element.children.push(XMLNode::Element(text_element(
            "EnableAutoType",
            bool_text(enable_auto_type),
        )));
    } else if let Some(enable_auto_type_raw) = &group.raw_state.enable_auto_type_raw {
        element.children.push(XMLNode::Element(text_element(
            "EnableAutoType",
            enable_auto_type_raw,
        )));
    } else {
        element
            .children
            .push(XMLNode::Element(text_element("EnableAutoType", "null")));
    }
    if let Some(enable_searching) = group.flags.enable_searching {
        element.children.push(XMLNode::Element(text_element(
            "EnableSearching",
            bool_text(enable_searching),
        )));
    } else if let Some(enable_searching_raw) = &group.raw_state.enable_searching_raw {
        element.children.push(XMLNode::Element(text_element(
            "EnableSearching",
            enable_searching_raw,
        )));
    } else {
        element
            .children
            .push(XMLNode::Element(text_element("EnableSearching", "null")));
    }
    if let Some(last_top_visible_entry) = group.last_top_visible_entry {
        element.children.push(XMLNode::Element(text_element(
            "LastTopVisibleEntry",
            &encode_uuid(last_top_visible_entry),
        )));
    } else if let Some(last_top_visible_entry_raw) = &group.raw_state.last_top_visible_entry_raw {
        element.children.push(XMLNode::Element(text_element(
            "LastTopVisibleEntry",
            last_top_visible_entry_raw,
        )));
    } else {
        element.children.push(XMLNode::Element(text_element(
            "LastTopVisibleEntry",
            &encode_uuid(Uuid::nil()),
        )));
    }
    append_custom_data_blocks(
        &mut element,
        &group.custom_data_blocks,
        &group.custom_data,
        true,
        version,
    )?;
    if version == KdbxVersion::V4_1
        && let Some(previous_parent) = group.previous_parent
    {
        element.children.push(XMLNode::Element(text_element(
            "PreviousParentGroup",
            &encode_uuid(previous_parent),
        )));
    }
    for entry in &group.entries {
        element.children.push(XMLNode::Element(entry_to_xml(
            entry,
            attachment_refs,
            protected,
            true,
            version,
        )?));
    }
    for child in &group.children {
        element.children.push(XMLNode::Element(group_to_xml(
            child,
            attachment_refs,
            protected,
            version,
        )?));
    }
    reorder_known_xml_nodes(&mut element.children, &group.raw_state.node_order);
    append_opaque_xml(&mut element, &group.opaque_xml)?;
    Ok(element)
}

fn entry_to_xml(
    entry: &Entry,
    attachment_refs: &HashMap<(usize, String), usize>,
    protected: &mut ProtectedStream,
    include_history: bool,
    version: KdbxVersion,
) -> Result<Element> {
    let mut element = Element::new("Entry");
    element.children.push(XMLNode::Element(text_element(
        "UUID",
        &encode_uuid(entry.id),
    )));
    element.children.push(XMLNode::Element(text_element(
        "IconID",
        &entry.icon_id.unwrap_or(0).to_string(),
    )));
    if let Some(custom_icon_id) = entry.custom_icon_id {
        element.children.push(XMLNode::Element(text_element(
            "CustomIconUUID",
            &encode_uuid(custom_icon_id),
        )));
    }
    if let Some(foreground_color) = &entry.foreground_color {
        element.children.push(XMLNode::Element(text_element(
            "ForegroundColor",
            foreground_color,
        )));
    } else if let Some(foreground_color_raw) = &entry.raw_state.foreground_color_raw {
        element.children.push(XMLNode::Element(text_element(
            "ForegroundColor",
            foreground_color_raw,
        )));
    }
    if let Some(background_color) = &entry.background_color {
        element.children.push(XMLNode::Element(text_element(
            "BackgroundColor",
            background_color,
        )));
    } else if let Some(background_color_raw) = &entry.raw_state.background_color_raw {
        element.children.push(XMLNode::Element(text_element(
            "BackgroundColor",
            background_color_raw,
        )));
    }
    if let Some(override_url) = &entry.override_url {
        element
            .children
            .push(XMLNode::Element(text_element("OverrideURL", override_url)));
    } else if let Some(override_url_raw) = &entry.raw_state.override_url_raw {
        element.children.push(XMLNode::Element(text_element(
            "OverrideURL",
            override_url_raw,
        )));
    }
    if !entry.tags.is_empty() {
        element.children.push(XMLNode::Element(text_element(
            "Tags",
            &entry.tags.iter().cloned().collect::<Vec<_>>().join(";"),
        )));
    } else if let Some(tags_raw) = &entry.raw_state.tags_raw {
        element
            .children
            .push(XMLNode::Element(text_element("Tags", tags_raw)));
    }
    if version == KdbxVersion::V4_1
        && let Some(previous_parent) = entry.previous_parent
    {
        element.children.push(XMLNode::Element(text_element(
            "PreviousParentGroup",
            &encode_uuid(previous_parent),
        )));
    }
    if version == KdbxVersion::V4_1 {
        if entry.exclude_from_reports {
            element
                .children
                .push(XMLNode::Element(text_element("QualityCheck", "False")));
        } else if let Some(quality_check_raw) = &entry.raw_state.quality_check_raw
            && parse_bool_text(quality_check_raw)
        {
            element.children.push(XMLNode::Element(text_element(
                "QualityCheck",
                quality_check_raw,
            )));
        }
    }

    element
        .children
        .push(XMLNode::Element(entry_times_to_xml(entry, version)));

    let mut fields = entry.attributes.clone();
    fields.insert(
        "Title".into(),
        CustomField {
            value: entry.title.clone(),
            protected: entry.field_protection.protect_title,
        },
    );
    fields.insert(
        "UserName".into(),
        CustomField {
            value: entry.username.clone(),
            protected: entry.field_protection.protect_username,
        },
    );
    fields.insert(
        "Password".into(),
        CustomField {
            value: entry.password.clone(),
            protected: entry.field_protection.protect_password,
        },
    );
    fields.insert(
        "URL".into(),
        CustomField {
            value: entry.url.clone(),
            protected: entry.field_protection.protect_url,
        },
    );
    fields.insert(
        "Notes".into(),
        CustomField {
            value: entry.notes.clone(),
            protected: entry.field_protection.protect_notes,
        },
    );
    if let Some(totp) = &entry.totp {
        fields.insert(
            "otp".into(),
            CustomField {
                value: build_otpauth_uri(entry, totp),
                protected: true,
            },
        );
        fields.insert(
            "TimeOtp-Secret-Base32".into(),
            CustomField {
                value: totp.secret_base32.clone(),
                protected: true,
            },
        );
        fields.insert(
            "TimeOtp-Algorithm".into(),
            CustomField {
                value: match totp.algorithm {
                    TotpAlgorithm::Sha1 => "HMAC-SHA-1",
                    TotpAlgorithm::Sha256 => "HMAC-SHA-256",
                    TotpAlgorithm::Sha512 => "HMAC-SHA-512",
                }
                .into(),
                protected: false,
            },
        );
        fields.insert(
            "TimeOtp-Length".into(),
            CustomField {
                value: totp.digits.to_string(),
                protected: false,
            },
        );
        fields.insert(
            "TimeOtp-Period".into(),
            CustomField {
                value: totp.period_seconds.to_string(),
                protected: false,
            },
        );
    }
    if let Some(passkey) = &entry.passkey {
        passkey.write_to_attributes(&mut fields);
    }

    for (key, field) in fields {
        element.children.push(XMLNode::Element(string_field_to_xml(
            &key, &field, protected,
        )));
    }

    for attachment in entry.attachments.values() {
        let mut binary = Element::new("Binary");
        binary
            .children
            .push(XMLNode::Element(text_element("Key", &attachment.name)));
        let mut value = Element::new("Value");
        value.attributes.insert(
            "Ref".into(),
            attachment_refs[&(entry_ref_key(entry), attachment.name.clone())].to_string(),
        );
        binary.children.push(XMLNode::Element(value));
        element.children.push(XMLNode::Element(binary));
    }

    let auto_type = entry.auto_type.as_ref().cloned().unwrap_or_default();
    element
        .children
        .push(XMLNode::Element(auto_type_to_xml(&auto_type)));
    append_custom_data_blocks(
        &mut element,
        &entry.custom_data_blocks,
        &entry.custom_data,
        true,
        version,
    )?;

    if include_history && !entry.history.is_empty() {
        let mut history = Element::new("History");
        for old_entry in &entry.history {
            history.children.push(XMLNode::Element(entry_to_xml(
                old_entry,
                attachment_refs,
                protected,
                false,
                version,
            )?));
        }
        element.children.push(XMLNode::Element(history));
    } else if include_history {
        element
            .children
            .push(XMLNode::Element(Element::new("History")));
    }

    reorder_known_xml_nodes(&mut element.children, &entry.raw_state.node_order);
    append_opaque_xml(&mut element, &entry.opaque_xml)?;
    Ok(element)
}

fn group_times_to_xml(times: GroupTimes, version: KdbxVersion) -> Element {
    let mut element = Element::new("Times");
    element.children.push(XMLNode::Element(text_element(
        "LastModificationTime",
        &datetime_text(version, times.modified_at),
    )));
    element.children.push(XMLNode::Element(text_element(
        "CreationTime",
        &datetime_text(version, times.created_at),
    )));
    if let Some(last_accessed_at) = times.last_accessed_at {
        element.children.push(XMLNode::Element(text_element(
            "LastAccessTime",
            &datetime_text(version, last_accessed_at),
        )));
    }
    if let Some(expiry_time) = times.expiry_time {
        element.children.push(XMLNode::Element(text_element(
            "ExpiryTime",
            &datetime_text(version, expiry_time),
        )));
    }
    element.children.push(XMLNode::Element(text_element(
        "Expires",
        bool_text(times.expires),
    )));
    if let Some(usage_count) = times.usage_count {
        element.children.push(XMLNode::Element(text_element(
            "UsageCount",
            &usage_count.to_string(),
        )));
    }
    if let Some(location_changed_at) = times.location_changed_at {
        element.children.push(XMLNode::Element(text_element(
            "LocationChanged",
            &datetime_text(version, location_changed_at),
        )));
    }
    element
}

fn default_group_times() -> GroupTimes {
    GroupTimes {
        created_at: 0,
        modified_at: 0,
        expires: false,
        expiry_time: None,
        last_accessed_at: None,
        usage_count: None,
        location_changed_at: None,
    }
}

fn entry_times_to_xml(entry: &Entry, version: KdbxVersion) -> Element {
    let mut times = Element::new("Times");
    times.children.push(XMLNode::Element(text_element(
        "LastModificationTime",
        &datetime_text(version, entry.modified_at),
    )));
    times.children.push(XMLNode::Element(text_element(
        "CreationTime",
        &datetime_text(version, entry.created_at),
    )));
    if let Some(last_accessed_at) = entry.last_accessed_at {
        times.children.push(XMLNode::Element(text_element(
            "LastAccessTime",
            &datetime_text(version, last_accessed_at),
        )));
    }
    if let Some(expiry_time) = entry.expiry_time {
        times.children.push(XMLNode::Element(text_element(
            "ExpiryTime",
            &datetime_text(version, expiry_time),
        )));
    }
    times.children.push(XMLNode::Element(text_element(
        "Expires",
        bool_text(entry.expires),
    )));
    if let Some(usage_count) = entry.usage_count {
        times.children.push(XMLNode::Element(text_element(
            "UsageCount",
            &usage_count.to_string(),
        )));
    }
    if let Some(location_changed_at) = entry.location_changed_at {
        times.children.push(XMLNode::Element(text_element(
            "LocationChanged",
            &datetime_text(version, location_changed_at),
        )));
    }
    times
}

fn auto_type_to_xml(auto_type: &AutoTypeConfig) -> Element {
    let mut element = Element::new("AutoType");
    if let Some(enabled) = auto_type.enabled {
        element.children.push(XMLNode::Element(text_element(
            "Enabled",
            bool_text(enabled),
        )));
    }
    if let Some(obfuscation) = auto_type.obfuscation {
        element.children.push(XMLNode::Element(text_element(
            "DataTransferObfuscation",
            &obfuscation.to_string(),
        )));
    }
    if let Some(default_sequence) = &auto_type.default_sequence {
        element.children.push(XMLNode::Element(text_element(
            "DefaultSequence",
            default_sequence,
        )));
    }
    for association in &auto_type.associations {
        let mut child = Element::new("Association");
        child.children.push(XMLNode::Element(text_element(
            "Window",
            &association.window,
        )));
        child.children.push(XMLNode::Element(text_element(
            "KeystrokeSequence",
            &association.sequence,
        )));
        element.children.push(XMLNode::Element(child));
    }
    element
}

fn custom_data_to_xml(custom_data: &BTreeMap<String, String>) -> Element {
    let mut element = Element::new("CustomData");
    for (key, value) in custom_data {
        let mut item = Element::new("Item");
        item.children
            .push(XMLNode::Element(text_element("Key", key)));
        item.children
            .push(XMLNode::Element(text_element("Value", value)));
        element.children.push(XMLNode::Element(item));
    }
    element
}

fn custom_data_block_to_xml(
    block: &CustomDataBlock,
    include_item_times: bool,
    version: KdbxVersion,
) -> Element {
    let mut element = Element::new("CustomData");
    for custom_item in &block.items {
        let mut item = Element::new("Item");
        item.children
            .push(XMLNode::Element(text_element("Key", &custom_item.key)));
        item.children
            .push(XMLNode::Element(text_element("Value", &custom_item.value)));
        if include_item_times && version == KdbxVersion::V4_1 {
            if let Some(last_modified) = custom_item.last_modified {
                item.children.push(XMLNode::Element(text_element(
                    "LastModificationTime",
                    &datetime_text(version, last_modified),
                )));
            }
        }
        element.children.push(XMLNode::Element(item));
    }
    element
}

fn merge_custom_data_blocks(blocks: &[CustomDataBlock]) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::new();
    for block in blocks {
        for item in &block.items {
            merged.insert(item.key.clone(), item.value.clone());
        }
    }
    merged
}

fn append_custom_data_blocks(
    target: &mut Element,
    blocks: &[CustomDataBlock],
    merged: &BTreeMap<String, String>,
    include_item_times: bool,
    version: KdbxVersion,
) -> Result<()> {
    if !matches!(version, KdbxVersion::V4_0 | KdbxVersion::V4_1) {
        return Ok(());
    }

    if blocks.is_empty() {
        if !merged.is_empty() {
            target
                .children
                .push(XMLNode::Element(custom_data_to_xml(merged)));
        }
        return Ok(());
    }

    let has_empty_blocks = blocks.iter().any(|block| block.items.is_empty());
    let has_non_empty_blocks = blocks.iter().any(|block| !block.items.is_empty());
    if has_empty_blocks && has_non_empty_blocks {
        if !merged.is_empty() {
            target
                .children
                .push(XMLNode::Element(custom_data_to_xml(merged)));
        }
        return Ok(());
    }

    if merge_custom_data_blocks(blocks) != *merged {
        if !merged.is_empty() {
            target
                .children
                .push(XMLNode::Element(custom_data_to_xml(merged)));
        }
        return Ok(());
    }

    let mut rebuilt = Vec::new();
    let mut anchored = Vec::new();
    for block in blocks {
        let node = XMLNode::Element(custom_data_block_to_xml(block, include_item_times, version));
        if let Some(anchor) = &block.after {
            anchored.push((anchor.clone(), node));
        } else {
            rebuilt.push(node);
        }
    }

    let original_children = std::mem::take(&mut target.children);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for child in original_children {
        let current_anchor = match &child {
            XMLNode::Element(element) => {
                let occurrence = counts.entry(element.name.clone()).or_insert(0);
                *occurrence += 1;
                Some(OpaqueXmlAnchor {
                    element_name: element.name.clone(),
                    occurrence: *occurrence,
                })
            }
            _ => None,
        };
        rebuilt.push(child);

        if let Some(current_anchor) = current_anchor {
            let mut index = 0;
            while index < anchored.len() {
                if anchored[index].0 == current_anchor {
                    let (_, node) = anchored.remove(index);
                    rebuilt.push(node);
                } else {
                    index += 1;
                }
            }
        }
    }

    rebuilt.extend(anchored.into_iter().map(|(_, node)| node));
    target.children = rebuilt;
    Ok(())
}

fn reorder_known_xml_nodes(children: &mut Vec<XMLNode>, original_order: &[String]) {
    if original_order.is_empty() {
        return;
    }

    let original_children = std::mem::take(children);
    let mut known_nodes = original_children
        .into_iter()
        .filter_map(|child| match child {
            XMLNode::Element(element) => Some((element.name.clone(), XMLNode::Element(element))),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut rebuilt = Vec::new();

    for name in original_order {
        if let Some(index) = known_nodes
            .iter()
            .position(|(node_name, _)| node_name == name)
        {
            let (_, node) = known_nodes.remove(index);
            rebuilt.push(node);
        }
    }

    rebuilt.extend(known_nodes.into_iter().map(|(_, node)| node));
    *children = rebuilt;
}

fn string_field_to_xml(key: &str, field: &CustomField, protected: &mut ProtectedStream) -> Element {
    let mut string = Element::new("String");
    string
        .children
        .push(XMLNode::Element(text_element("Key", key)));
    let mut value = Element::new("Value");
    if field.protected {
        value.attributes.insert("Protected".into(), "True".into());
        let mut bytes = field.value.as_bytes().to_vec();
        protected.apply(&mut bytes);
        value.children.push(XMLNode::Text(STANDARD.encode(bytes)));
    } else {
        value.children.push(XMLNode::Text(field.value.clone()));
    }
    string.children.push(XMLNode::Element(value));
    string
}

fn parse_xml(
    bytes: &[u8],
    header: &KdbxHeader,
    inner_algorithm: u32,
    inner_key: &[u8],
    binaries: &[InnerBinary],
) -> Result<Vault> {
    let root = Element::parse(IoCursor::new(strip_utf8_bom(bytes)))
        .map_err(|error| KdbxError::Xml(error.to_string()))?;
    let meta = child(&root, "Meta")?;
    let generator = child_text(&meta, "Generator");
    let settings_changed = child_text(&meta, "SettingsChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let name = child_text(&meta, "DatabaseName").unwrap_or_default();
    let database_name_changed = child_text(&meta, "DatabaseNameChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let description = child_text(&meta, "DatabaseDescription");
    let description_changed = child_text(&meta, "DatabaseDescriptionChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let default_username = child_text(&meta, "DefaultUserName");
    let default_username_changed = child_text(&meta, "DefaultUserNameChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let maintenance_history_days =
        child_text(&meta, "MaintenanceHistoryDays").and_then(|value| value.parse::<i32>().ok());
    let color = child_text(&meta, "Color");
    let memory_protection = parse_memory_protection(&meta);
    let custom_icons = parse_custom_icons(&meta)?;
    let recycle_bin_enabled =
        child_text(&meta, "RecycleBinEnabled").map(|value| parse_bool_text(&value));
    let recycle_bin_group = child_text(&meta, "RecycleBinUUID")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    let recycle_bin_changed = child_text(&meta, "RecycleBinChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let entry_templates_group = child_text(&meta, "EntryTemplatesGroup")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    let entry_templates_group_changed = child_text(&meta, "EntryTemplatesGroupChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let master_key_changed = child_text(&meta, "MasterKeyChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let master_key_change_rec =
        child_text(&meta, "MasterKeyChangeRec").and_then(|value| value.parse::<i64>().ok());
    let master_key_change_force =
        child_text(&meta, "MasterKeyChangeForce").and_then(|value| value.parse::<i64>().ok());
    let master_key_change_force_once =
        child_text(&meta, "MasterKeyChangeForceOnce").map(|value| parse_bool_text(&value));
    let last_selected_group = child_text(&meta, "LastSelectedGroup")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    let last_top_visible_group = child_text(&meta, "LastTopVisibleGroup")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    let history_max_items =
        child_text(&meta, "HistoryMaxItems").and_then(|value| value.parse::<i32>().ok());
    let history_max_size =
        child_text(&meta, "HistoryMaxSize").and_then(|value| value.parse::<i64>().ok());
    let (meta_custom_data, meta_custom_data_blocks) = parse_meta_custom_data(&meta)?;
    let meta_raw_state = MetaRawState {
        node_order: collect_meta_known_node_order(&meta),
        description_raw: child_optional(&meta, "DatabaseDescription").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        default_username_raw: child_optional(&meta, "DefaultUserName").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        color_raw: child_optional(&meta, "Color").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        has_custom_icons_node: child_optional(&meta, "CustomIcons").is_some(),
        recycle_bin_group_raw: child_optional(&meta, "RecycleBinUUID").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        entry_templates_group_raw: child_optional(&meta, "EntryTemplatesGroup").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
    };
    let root_group = child(&child(&root, "Root")?, "Group")?;

    let mut protected = ProtectedStream::from_stream(inner_algorithm, inner_key)?;
    let group = parse_group(&root_group, binaries, &mut protected)?;

    Ok(Vault {
        generator,
        settings_changed,
        name,
        database_name_changed,
        description,
        description_changed,
        default_username,
        default_username_changed,
        meta_custom_data,
        meta_custom_data_blocks,
        meta_raw_state,
        root_raw_state: RootRawState {
            node_order: collect_root_known_node_order(&root),
            has_deleted_objects_node: child_optional(&root, "Root")
                .and_then(|root_node| child_optional(&root_node, "DeletedObjects"))
                .is_some(),
        },
        root: group,
        public_custom_data: header
            .public_custom_data
            .iter()
            .filter_map(|(key, value)| match value {
                VariantValue::Bytes(bytes) => Some((key.clone(), bytes.clone())),
                _ => None,
            })
            .collect(),
        deleted_objects: parse_deleted_objects(&root)?,
        maintenance_history_days,
        color,
        master_key_changed,
        master_key_change_rec,
        master_key_change_force,
        master_key_change_force_once,
        custom_icons,
        history_max_items,
        history_max_size,
        last_selected_group,
        last_top_visible_group,
        memory_protection,
        recycle_bin_enabled,
        recycle_bin_group,
        recycle_bin_changed,
        entry_templates_group,
        entry_templates_group_changed,
        meta_opaque_xml: collect_meta_opaque_xml(&meta)?,
        root_opaque_xml: collect_root_opaque_xml(&root)?,
    })
}

fn parse_kdbx3_xml(
    bytes: &[u8],
    header_bytes: &[u8],
    protected_stream_key: &[u8],
    inner_random_stream_id: u32,
) -> Result<Vault> {
    let xml_bytes = strip_utf8_bom(bytes);
    let root = Element::parse(IoCursor::new(xml_bytes))
        .map_err(|error| KdbxError::Xml(error.to_string()))?;
    let meta = child(&root, "Meta")?;

    if let Some(header_hash) = child_text(&meta, "HeaderHash") {
        if !header_hash.is_empty() {
            let expected = STANDARD
                .decode(header_hash.as_bytes())
                .map_err(|_| KdbxError::InvalidValue)?;
            if expected.as_slice() != sha256_bytes(header_bytes).as_slice() {
                return Err(KdbxError::HeaderHashMismatch);
            }
        }
    }

    let name = child_text(&meta, "DatabaseName").unwrap_or_default();
    let generator = child_text(&meta, "Generator");
    let settings_changed = child_text(&meta, "SettingsChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let database_name_changed = child_text(&meta, "DatabaseNameChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let description = child_text(&meta, "DatabaseDescription");
    let description_changed = child_text(&meta, "DatabaseDescriptionChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let default_username = child_text(&meta, "DefaultUserName");
    let default_username_changed = child_text(&meta, "DefaultUserNameChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let maintenance_history_days =
        child_text(&meta, "MaintenanceHistoryDays").and_then(|value| value.parse::<i32>().ok());
    let color = child_text(&meta, "Color");
    let memory_protection = parse_memory_protection(&meta);
    let custom_icons = parse_custom_icons(&meta)?;
    let recycle_bin_enabled =
        child_text(&meta, "RecycleBinEnabled").map(|value| parse_bool_text(&value));
    let recycle_bin_group = child_text(&meta, "RecycleBinUUID")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    let recycle_bin_changed = child_text(&meta, "RecycleBinChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let entry_templates_group = child_text(&meta, "EntryTemplatesGroup")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    let entry_templates_group_changed = child_text(&meta, "EntryTemplatesGroupChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let master_key_changed = child_text(&meta, "MasterKeyChanged")
        .as_deref()
        .and_then(parse_optional_datetime);
    let master_key_change_rec =
        child_text(&meta, "MasterKeyChangeRec").and_then(|value| value.parse::<i64>().ok());
    let master_key_change_force =
        child_text(&meta, "MasterKeyChangeForce").and_then(|value| value.parse::<i64>().ok());
    let master_key_change_force_once =
        child_text(&meta, "MasterKeyChangeForceOnce").map(|value| parse_bool_text(&value));
    let last_selected_group = child_text(&meta, "LastSelectedGroup")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    let last_top_visible_group = child_text(&meta, "LastTopVisibleGroup")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    let history_max_items =
        child_text(&meta, "HistoryMaxItems").and_then(|value| value.parse::<i32>().ok());
    let history_max_size =
        child_text(&meta, "HistoryMaxSize").and_then(|value| value.parse::<i64>().ok());
    let (meta_custom_data, meta_custom_data_blocks) = parse_meta_custom_data(&meta)?;
    let meta_raw_state = MetaRawState {
        node_order: collect_meta_known_node_order(&meta),
        description_raw: child_optional(&meta, "DatabaseDescription").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        default_username_raw: child_optional(&meta, "DefaultUserName").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        color_raw: child_optional(&meta, "Color").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        has_custom_icons_node: child_optional(&meta, "CustomIcons").is_some(),
        recycle_bin_group_raw: child_optional(&meta, "RecycleBinUUID").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        entry_templates_group_raw: child_optional(&meta, "EntryTemplatesGroup").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
    };
    let root_group = child(&child(&root, "Root")?, "Group")?;
    let mut protected = ProtectedStream::from_stream(inner_random_stream_id, protected_stream_key)?;
    let binaries = parse_kdbx3_binaries(&meta, &mut protected)?;
    let group = parse_group(&root_group, &binaries, &mut protected)?;
    let deleted_objects = parse_deleted_objects(&root)?;

    Ok(Vault {
        generator,
        settings_changed,
        name,
        database_name_changed,
        description,
        description_changed,
        default_username,
        default_username_changed,
        meta_custom_data,
        meta_custom_data_blocks,
        meta_raw_state,
        root_raw_state: RootRawState {
            node_order: collect_root_known_node_order(&root),
            has_deleted_objects_node: child_optional(&root, "Root")
                .and_then(|root_node| child_optional(&root_node, "DeletedObjects"))
                .is_some(),
        },
        root: group,
        public_custom_data: BTreeMap::new(),
        deleted_objects,
        maintenance_history_days,
        color,
        master_key_changed,
        master_key_change_rec,
        master_key_change_force,
        master_key_change_force_once,
        custom_icons,
        history_max_items,
        history_max_size,
        last_selected_group,
        last_top_visible_group,
        memory_protection,
        recycle_bin_enabled,
        recycle_bin_group,
        recycle_bin_changed,
        entry_templates_group,
        entry_templates_group_changed,
        meta_opaque_xml: collect_meta_opaque_xml(&meta)?,
        root_opaque_xml: collect_root_opaque_xml(&root)?,
    })
}

fn parse_deleted_objects(root: &Element) -> Result<Vec<DeletedObject>> {
    let root_node = child(root, "Root")?;
    let Some(deleted_objects) = child_optional(&root_node, "DeletedObjects") else {
        return Ok(Vec::new());
    };

    let mut objects = Vec::new();
    for child in &deleted_objects.children {
        let XMLNode::Element(child) = child else {
            continue;
        };
        if child.name != "DeletedObject" {
            continue;
        }

        let id = decode_uuid(&child_text(child, "UUID").ok_or(KdbxError::InvalidValue)?)?;
        let deleted_at = child_text(child, "DeletionTime")
            .and_then(|value| parse_datetime_value(&value).map(|value| value as i64))
            .ok_or(KdbxError::InvalidValue)?;
        objects.push(DeletedObject { id, deleted_at });
    }

    Ok(objects)
}

fn collect_meta_opaque_xml(meta: &Element) -> Result<Vec<OpaqueXmlFragment>> {
    let mut opaque = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut last_anchor: Option<OpaqueXmlAnchor> = None;
    for child in &meta.children {
        let XMLNode::Element(child) = child else {
            continue;
        };
        match child.name.as_str() {
            "Generator"
            | "DatabaseName"
            | "DatabaseNameChanged"
            | "HeaderHash"
            | "Binaries"
            | "DatabaseDescription"
            | "DatabaseDescriptionChanged"
            | "DefaultUserName"
            | "DefaultUserNameChanged"
            | "MaintenanceHistoryDays"
            | "Color"
            | "MemoryProtection"
            | "CustomIcons"
            | "RecycleBinEnabled"
            | "RecycleBinUUID"
            | "RecycleBinChanged"
            | "EntryTemplatesGroup"
            | "EntryTemplatesGroupChanged"
            | "MasterKeyChanged"
            | "MasterKeyChangeRec"
            | "MasterKeyChangeForce"
            | "LastSelectedGroup"
            | "LastTopVisibleGroup"
            | "HistoryMaxItems"
            | "HistoryMaxSize"
            | "CustomData" => {
                let occurrence = counts.entry(child.name.clone()).or_insert(0);
                *occurrence += 1;
                last_anchor = Some(OpaqueXmlAnchor {
                    element_name: child.name.clone(),
                    occurrence: *occurrence,
                });
            }
            _ => opaque.push(OpaqueXmlFragment {
                xml: element_to_xml_string(child)?,
                after: last_anchor.clone(),
            }),
        }
    }
    Ok(opaque)
}

fn collect_meta_known_node_order(meta: &Element) -> Vec<String> {
    meta.children
        .iter()
        .filter_map(|child| match child {
            XMLNode::Element(child) if meta_known_child_name(child.name.as_str()) => {
                Some(child.name.clone())
            }
            _ => None,
        })
        .collect()
}

fn collect_root_opaque_xml(root: &Element) -> Result<Vec<OpaqueXmlFragment>> {
    let root_node = child(root, "Root")?;
    let mut opaque = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut last_anchor: Option<OpaqueXmlAnchor> = None;
    for child in &root_node.children {
        let XMLNode::Element(child) = child else {
            continue;
        };
        match child.name.as_str() {
            "Group" | "DeletedObjects" => {
                let occurrence = counts.entry(child.name.clone()).or_insert(0);
                *occurrence += 1;
                last_anchor = Some(OpaqueXmlAnchor {
                    element_name: child.name.clone(),
                    occurrence: *occurrence,
                });
            }
            _ => opaque.push(OpaqueXmlFragment {
                xml: element_to_xml_string(child)?,
                after: last_anchor.clone(),
            }),
        }
    }
    Ok(opaque)
}

fn collect_root_known_node_order(root: &Element) -> Vec<String> {
    child(root, "Root")
        .map(|root_node| {
            root_node
                .children
                .iter()
                .filter_map(|child| match child {
                    XMLNode::Element(child)
                        if matches!(child.name.as_str(), "Group" | "DeletedObjects") =>
                    {
                        Some(child.name.clone())
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn deleted_objects_to_xml(deleted_objects: &[DeletedObject], version: KdbxVersion) -> Element {
    let mut element = Element::new("DeletedObjects");
    for deleted_object in deleted_objects {
        let mut child = Element::new("DeletedObject");
        child.children.push(XMLNode::Element(text_element(
            "UUID",
            &encode_uuid(deleted_object.id),
        )));
        child.children.push(XMLNode::Element(text_element(
            "DeletionTime",
            &datetime_text(version, deleted_object.deleted_at),
        )));
        element.children.push(XMLNode::Element(child));
    }
    element
}

fn append_opaque_xml(target: &mut Element, opaque_xml: &[OpaqueXmlFragment]) -> Result<()> {
    if opaque_xml.is_empty() {
        return Ok(());
    }

    let mut rebuilt = Vec::new();
    let mut anchored = Vec::new();
    for fragment in opaque_xml {
        let node = XMLNode::Element(parse_xml_fragment(&fragment.xml)?);
        if let Some(anchor) = &fragment.after {
            anchored.push((anchor.clone(), node));
        } else {
            rebuilt.push(node);
        }
    }

    let original_children = std::mem::take(&mut target.children);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for child in original_children {
        let current_anchor = match &child {
            XMLNode::Element(element) => {
                let occurrence = counts.entry(element.name.clone()).or_insert(0);
                *occurrence += 1;
                Some(OpaqueXmlAnchor {
                    element_name: element.name.clone(),
                    occurrence: *occurrence,
                })
            }
            _ => None,
        };
        rebuilt.push(child);

        if let Some(current_anchor) = current_anchor {
            let mut index = 0;
            while index < anchored.len() {
                if anchored[index].0 == current_anchor {
                    let (_, node) = anchored.remove(index);
                    rebuilt.push(node);
                } else {
                    index += 1;
                }
            }
        }
    }
    rebuilt.extend(anchored.into_iter().map(|(_, node)| node));
    target.children = rebuilt;
    Ok(())
}

fn memory_protection_to_xml(memory_protection: MemoryProtection) -> Element {
    let mut element = Element::new("MemoryProtection");
    element.children.push(XMLNode::Element(text_element(
        "ProtectTitle",
        if memory_protection.protect_title {
            "True"
        } else {
            "False"
        },
    )));
    element.children.push(XMLNode::Element(text_element(
        "ProtectUserName",
        if memory_protection.protect_username {
            "True"
        } else {
            "False"
        },
    )));
    element.children.push(XMLNode::Element(text_element(
        "ProtectPassword",
        if memory_protection.protect_password {
            "True"
        } else {
            "False"
        },
    )));
    element.children.push(XMLNode::Element(text_element(
        "ProtectURL",
        if memory_protection.protect_url {
            "True"
        } else {
            "False"
        },
    )));
    element.children.push(XMLNode::Element(text_element(
        "ProtectNotes",
        if memory_protection.protect_notes {
            "True"
        } else {
            "False"
        },
    )));
    element
}

fn parse_memory_protection(meta: &Element) -> Option<MemoryProtection> {
    let memory_protection = child_optional(meta, "MemoryProtection")?;
    Some(MemoryProtection {
        protect_title: child_text(&memory_protection, "ProtectTitle")
            .map(|value| parse_bool_text(&value))
            .unwrap_or(false),
        protect_username: child_text(&memory_protection, "ProtectUserName")
            .map(|value| parse_bool_text(&value))
            .unwrap_or(false),
        protect_password: child_text(&memory_protection, "ProtectPassword")
            .map(|value| parse_bool_text(&value))
            .unwrap_or(false),
        protect_url: child_text(&memory_protection, "ProtectURL")
            .map(|value| parse_bool_text(&value))
            .unwrap_or(false),
        protect_notes: child_text(&memory_protection, "ProtectNotes")
            .map(|value| parse_bool_text(&value))
            .unwrap_or(false),
    })
}

fn custom_icons_to_xml(custom_icons: &[CustomIcon], version: KdbxVersion) -> Element {
    let mut element = Element::new("CustomIcons");
    for custom_icon in custom_icons {
        let mut icon = Element::new("Icon");
        icon.children.push(XMLNode::Element(text_element(
            "UUID",
            &encode_uuid(custom_icon.id),
        )));
        if version == KdbxVersion::V4_1
            && let Some(name) = &custom_icon.name
        {
            icon.children
                .push(XMLNode::Element(text_element("Name", name)));
        }
        if version == KdbxVersion::V4_1
            && let Some(last_modified) = custom_icon.last_modified
        {
            icon.children.push(XMLNode::Element(text_element(
                "LastModificationTime",
                &datetime_text(version, last_modified),
            )));
        }
        icon.children.push(XMLNode::Element(text_element(
            "Data",
            &STANDARD.encode(&custom_icon.data),
        )));
        element.children.push(XMLNode::Element(icon));
    }
    element
}

fn parse_custom_icons(meta: &Element) -> Result<Vec<CustomIcon>> {
    let Some(custom_icons) = child_optional(meta, "CustomIcons") else {
        return Ok(Vec::new());
    };

    let mut parsed = Vec::new();
    for child in &custom_icons.children {
        let XMLNode::Element(icon) = child else {
            continue;
        };
        if icon.name != "Icon" {
            continue;
        }

        let id = decode_uuid(&child_text(icon, "UUID").ok_or(KdbxError::InvalidValue)?)?;
        let data = child_text(icon, "Data")
            .map(|value| STANDARD.decode(value.trim().as_bytes()))
            .transpose()
            .map_err(|_| KdbxError::InvalidValue)?
            .ok_or(KdbxError::InvalidValue)?;
        let name = child_text(icon, "Name");
        let last_modified = child_text(icon, "LastModificationTime")
            .as_deref()
            .and_then(parse_optional_datetime);
        parsed.push(CustomIcon {
            id,
            data,
            name,
            last_modified,
        });
    }

    Ok(parsed)
}

fn parse_xml_fragment(fragment: &str) -> Result<Element> {
    Element::parse(IoCursor::new(fragment.as_bytes()))
        .map_err(|error| KdbxError::Xml(error.to_string()))
}

fn element_to_xml_string(element: &Element) -> Result<String> {
    let mut bytes = Vec::new();
    element
        .write(&mut bytes)
        .map_err(|error| KdbxError::Xml(error.to_string()))?;
    String::from_utf8(bytes).map_err(|_| KdbxError::InvalidValue)
}

fn parse_kdbx3_binaries(
    meta: &Element,
    protected: &mut ProtectedStream,
) -> Result<Vec<InnerBinary>> {
    let Some(binaries_element) = child_optional(meta, "Binaries") else {
        return Ok(Vec::new());
    };

    let mut binaries = Vec::new();
    for child in &binaries_element.children {
        let XMLNode::Element(binary) = child else {
            continue;
        };
        if binary.name != "Binary" {
            continue;
        }

        let index = binary
            .attributes
            .get("ID")
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(KdbxError::InvalidValue)?;
        let compressed = binary
            .attributes
            .get("Compressed")
            .map(|value| parse_bool_text(value))
            .unwrap_or(false);
        let protected_in_memory = binary
            .attributes
            .get("Protected")
            .map(|value| parse_bool_text(value))
            .unwrap_or(false);

        let encoded = binary
            .get_text()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let mut data = STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| KdbxError::InvalidValue)?;
        if protected_in_memory {
            protected.apply(&mut data);
        }
        if compressed {
            data = gzip_decompress(&data)?;
        }

        if binaries.len() <= index {
            binaries.resize_with(index + 1, || InnerBinary {
                protect_in_memory: false,
                data: Vec::new(),
            });
        }
        binaries[index] = InnerBinary {
            protect_in_memory: protected_in_memory,
            data,
        };
    }

    Ok(binaries)
}

fn parse_group(
    element: &Element,
    binaries: &[InnerBinary],
    protected: &mut ProtectedStream,
) -> Result<Group> {
    let mut group = Group::new(child_text(element, "Name").unwrap_or_else(|| "Group".into()));
    group.id = decode_uuid(&child_text(element, "UUID").ok_or(KdbxError::InvalidValue)?)?;
    group.notes = child_text(element, "Notes").unwrap_or_default();
    group.icon_id = child_text(element, "IconID").and_then(|value| value.parse::<u32>().ok());
    group.custom_icon_id = child_text(element, "CustomIconUUID")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    if let Some(tags) = child_text(element, "Tags") {
        group.tags = parse_tags(&tags);
    }
    group.times = child_optional(element, "Times")
        .map(|times| parse_group_times(&times))
        .transpose()?;
    group.flags.is_expanded = child_text(element, "IsExpanded")
        .as_deref()
        .and_then(parse_nullable_bool);
    group.default_auto_type_sequence = child_text(element, "DefaultAutoTypeSequence");
    group.flags.enable_auto_type = child_text(element, "EnableAutoType")
        .as_deref()
        .and_then(parse_nullable_bool);
    group.flags.enable_searching = child_text(element, "EnableSearching")
        .as_deref()
        .and_then(parse_nullable_bool);
    group.last_top_visible_entry = child_text(element, "LastTopVisibleEntry")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    let (custom_data, custom_data_blocks) = parse_group_custom_data(element)?;
    group.custom_data = custom_data;
    group.custom_data_blocks = custom_data_blocks;
    if let Some(previous_parent) = child_text(element, "PreviousParentGroup") {
        group.previous_parent = Some(decode_uuid(&previous_parent)?);
    }
    group.raw_state = GroupRawState {
        node_order: collect_group_known_node_order(element),
        default_auto_type_sequence_raw: child_optional(element, "DefaultAutoTypeSequence").map(
            |child| {
                child
                    .get_text()
                    .map(|text| text.to_string())
                    .unwrap_or_default()
            },
        ),
        enable_auto_type_raw: child_optional(element, "EnableAutoType").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        enable_searching_raw: child_optional(element, "EnableSearching").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        last_top_visible_entry_raw: child_optional(element, "LastTopVisibleEntry").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
    };

    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut last_anchor: Option<OpaqueXmlAnchor> = None;
    for child in &element.children {
        if let XMLNode::Element(child) = child {
            match child.name.as_str() {
                "Group" => {
                    group
                        .children
                        .push(parse_group(child, binaries, protected)?);
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                "Entry" => {
                    group.entries.push(parse_entry(child, binaries, protected)?);
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                "UUID"
                | "Name"
                | "Notes"
                | "IconID"
                | "CustomIconUUID"
                | "Tags"
                | "Times"
                | "IsExpanded"
                | "DefaultAutoTypeSequence"
                | "EnableAutoType"
                | "EnableSearching"
                | "LastTopVisibleEntry"
                | "CustomData"
                | "PreviousParentGroup" => {
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                _ => group.opaque_xml.push(OpaqueXmlFragment {
                    xml: element_to_xml_string(child)?,
                    after: last_anchor.clone(),
                }),
            }
        }
    }

    Ok(group)
}

fn collect_group_known_node_order(group: &Element) -> Vec<String> {
    group
        .children
        .iter()
        .filter_map(|child| match child {
            XMLNode::Element(child)
                if matches!(
                    child.name.as_str(),
                    "UUID"
                        | "Name"
                        | "Notes"
                        | "IconID"
                        | "CustomIconUUID"
                        | "Tags"
                        | "Times"
                        | "IsExpanded"
                        | "DefaultAutoTypeSequence"
                        | "EnableAutoType"
                        | "EnableSearching"
                        | "LastTopVisibleEntry"
                        | "CustomData"
                        | "PreviousParentGroup"
                        | "Entry"
                        | "Group"
                ) =>
            {
                Some(child.name.clone())
            }
            _ => None,
        })
        .collect()
}

fn parse_entry(
    element: &Element,
    binaries: &[InnerBinary],
    protected: &mut ProtectedStream,
) -> Result<Entry> {
    let mut entry = Entry::new("");
    entry.id = decode_uuid(&child_text(element, "UUID").ok_or(KdbxError::InvalidValue)?)?;
    entry.icon_id = child_text(element, "IconID").and_then(|value| value.parse::<u32>().ok());
    entry.custom_icon_id = child_text(element, "CustomIconUUID")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    entry.foreground_color = child_text(element, "ForegroundColor");
    entry.background_color = child_text(element, "BackgroundColor");
    entry.override_url = child_text(element, "OverrideURL");
    let (custom_data, custom_data_blocks) = parse_entry_custom_data(element)?;
    entry.custom_data = custom_data;
    entry.custom_data_blocks = custom_data_blocks;
    let legacy_known_bad = entry.custom_data.remove("KnownBad");
    if legacy_known_bad.is_some() {
        let mut cleaned_blocks = Vec::with_capacity(entry.custom_data_blocks.len());
        for mut block in std::mem::take(&mut entry.custom_data_blocks) {
            let original_item_count = block.items.len();
            block.items.retain(|item| item.key != "KnownBad");
            if original_item_count == block.items.len() || !block.items.is_empty() {
                cleaned_blocks.push(block);
            }
        }
        entry.custom_data_blocks = cleaned_blocks;
    }
    if let Some(tags) = child_text(element, "Tags") {
        entry.tags = parse_tags(&tags);
    }
    if let Some(previous_parent) = child_text(element, "PreviousParentGroup") {
        entry.previous_parent = Some(decode_uuid(&previous_parent)?);
    }
    let quality_check_raw = child_optional(element, "QualityCheck").map(|child| {
        child
            .get_text()
            .map(|text| text.to_string())
            .unwrap_or_default()
    });
    entry.exclude_from_reports = quality_check_raw
        .as_deref()
        .map(|value| !parse_bool_text(value))
        .unwrap_or(false);
    if let Some(known_bad) = legacy_known_bad {
        entry.exclude_from_reports = parse_bool_text(&known_bad);
    }
    entry.raw_state = EntryRawState {
        node_order: collect_entry_known_node_order(element),
        foreground_color_raw: child_optional(element, "ForegroundColor").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        background_color_raw: child_optional(element, "BackgroundColor").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        override_url_raw: child_optional(element, "OverrideURL").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        tags_raw: child_optional(element, "Tags").map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        }),
        quality_check_raw,
        has_history_node: child_optional(element, "History").is_some(),
    };

    if let Some(times) = child_optional(element, "Times") {
        entry.created_at = child_text(&times, "CreationTime")
            .and_then(|value| parse_datetime_value(&value))
            .unwrap_or(0);
        entry.modified_at = child_text(&times, "LastModificationTime")
            .and_then(|value| parse_datetime_value(&value))
            .unwrap_or(0);
        entry.expires = child_text(&times, "Expires")
            .map(|value| parse_bool_text(&value))
            .unwrap_or(false);
        entry.expiry_time = child_text(&times, "ExpiryTime")
            .and_then(|value| parse_datetime_value(&value).map(|value| value as i64));
        entry.last_accessed_at =
            child_text(&times, "LastAccessTime").and_then(|value| parse_datetime_value(&value));
        entry.usage_count = child_text(&times, "UsageCount").and_then(|value| value.parse().ok());
        entry.location_changed_at =
            child_text(&times, "LocationChanged").and_then(|value| parse_datetime_value(&value));
    }

    let mut raw_fields = BTreeMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut last_anchor: Option<OpaqueXmlAnchor> = None;
    for child in &element.children {
        if let XMLNode::Element(child) = child {
            match child.name.as_str() {
                "String" => {
                    let (key, field) = parse_string_field(child, protected)?;
                    raw_fields.insert(key, field);
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                "Binary" => {
                    let attachment_name =
                        child_text(child, "Key").ok_or(KdbxError::InvalidValue)?;
                    let value = child_optional(child, "Value").ok_or(KdbxError::InvalidValue)?;
                    let attachment = if let Some(index) = value
                        .attributes
                        .get("Ref")
                        .and_then(|value| value.parse::<usize>().ok())
                    {
                        let binary = binaries.get(index).ok_or(KdbxError::InvalidValue)?;
                        Attachment {
                            name: attachment_name.clone(),
                            data: binary.data.clone(),
                            protect_in_memory: binary.protect_in_memory,
                        }
                    } else {
                        let encoded = value
                            .get_text()
                            .map(|text| text.to_string())
                            .unwrap_or_default();
                        let data = STANDARD
                            .decode(encoded.as_bytes())
                            .map_err(|_| KdbxError::InvalidValue)?;
                        Attachment {
                            name: attachment_name.clone(),
                            data,
                            protect_in_memory: false,
                        }
                    };
                    entry.attachments.insert(attachment_name, attachment);
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                "History" => {
                    for history_child in &child.children {
                        if let XMLNode::Element(history_entry) = history_child {
                            if history_entry.name == "Entry" {
                                entry.history.push(parse_entry(
                                    history_entry,
                                    binaries,
                                    protected,
                                )?);
                            }
                        }
                    }
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                "AutoType" => {
                    entry.auto_type = Some(parse_auto_type(child));
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                "UUID"
                | "IconID"
                | "CustomIconUUID"
                | "ForegroundColor"
                | "BackgroundColor"
                | "OverrideURL"
                | "Tags"
                | "PreviousParentGroup"
                | "QualityCheck"
                | "Times" => {
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                "CustomData" => {
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                _ => entry.opaque_xml.push(OpaqueXmlFragment {
                    xml: element_to_xml_string(child)?,
                    after: last_anchor.clone(),
                }),
            }
        }
    }

    if let Some(field) = raw_fields.remove("Title") {
        entry.title = field.value;
        entry.field_protection.protect_title = field.protected;
    }
    if let Some(field) = raw_fields.remove("UserName") {
        entry.username = field.value;
        entry.field_protection.protect_username = field.protected;
    }
    if let Some(field) = raw_fields.remove("Password") {
        entry.password = field.value;
        entry.field_protection.protect_password = field.protected;
    }
    if let Some(field) = raw_fields.remove("URL") {
        entry.url = field.value;
        entry.field_protection.protect_url = field.protected;
    }
    if let Some(field) = raw_fields.remove("Notes") {
        entry.notes = field.value;
        entry.field_protection.protect_notes = field.protected;
    }

    entry.totp = build_totp(&raw_fields);
    entry.passkey = PasskeyRecord::from_attributes(&raw_fields);
    let has_complete_passkey = entry.passkey.is_some();
    entry.attributes = raw_fields
        .into_iter()
        .filter(|(key, _)| {
            !is_totp_attribute_key(key) && !(has_complete_passkey && is_passkey_attribute_key(key))
        })
        .collect();

    Ok(entry)
}

fn is_totp_attribute_key(key: &str) -> bool {
    matches!(
        key,
        "otp" | "TimeOtp-Secret-Base32" | "TimeOtp-Algorithm" | "TimeOtp-Length" | "TimeOtp-Period"
    )
}

fn is_passkey_attribute_key(key: &str) -> bool {
    matches!(
        key,
        PasskeyRecord::USERNAME_KEY
            | PasskeyRecord::CREDENTIAL_ID_KEY
            | PasskeyRecord::GENERATED_USER_ID_KEY
            | PasskeyRecord::PRIVATE_KEY_PEM_KEY
            | PasskeyRecord::RELYING_PARTY_KEY
            | PasskeyRecord::USER_HANDLE_KEY
            | PasskeyRecord::FLAG_BE_KEY
            | PasskeyRecord::FLAG_BS_KEY
    )
}

fn collect_entry_known_node_order(entry: &Element) -> Vec<String> {
    entry
        .children
        .iter()
        .filter_map(|child| match child {
            XMLNode::Element(child)
                if matches!(
                    child.name.as_str(),
                    "UUID"
                        | "IconID"
                        | "CustomIconUUID"
                        | "ForegroundColor"
                        | "BackgroundColor"
                        | "OverrideURL"
                        | "Tags"
                        | "PreviousParentGroup"
                        | "QualityCheck"
                        | "Times"
                        | "String"
                        | "Binary"
                        | "AutoType"
                        | "CustomData"
                        | "History"
                ) =>
            {
                Some(child.name.clone())
            }
            _ => None,
        })
        .collect()
}

fn parse_group_times(element: &Element) -> Result<GroupTimes> {
    Ok(GroupTimes {
        created_at: child_text(element, "CreationTime")
            .and_then(|value| parse_datetime_value(&value))
            .unwrap_or(0),
        modified_at: child_text(element, "LastModificationTime")
            .and_then(|value| parse_datetime_value(&value))
            .unwrap_or(0),
        expires: child_text(element, "Expires")
            .map(|value| parse_bool_text(&value))
            .unwrap_or(false),
        expiry_time: child_text(element, "ExpiryTime")
            .and_then(|value| parse_datetime_value(&value).map(|value| value as i64)),
        last_accessed_at: child_text(element, "LastAccessTime")
            .and_then(|value| parse_datetime_value(&value)),
        usage_count: child_text(element, "UsageCount").and_then(|value| value.parse().ok()),
        location_changed_at: child_text(element, "LocationChanged")
            .and_then(|value| parse_datetime_value(&value)),
    })
}

fn parse_auto_type(element: &Element) -> AutoTypeConfig {
    let mut auto_type = AutoTypeConfig::default();
    auto_type.enabled = child_text(element, "Enabled")
        .as_deref()
        .and_then(parse_nullable_bool);
    auto_type.obfuscation =
        child_text(element, "DataTransferObfuscation").and_then(|value| value.parse::<i32>().ok());
    auto_type.default_sequence = child_text(element, "DefaultSequence");

    for child in &element.children {
        let XMLNode::Element(child) = child else {
            continue;
        };
        if child.name != "Association" {
            continue;
        }
        auto_type.associations.push(AutoTypeAssociation {
            window: child_text(child, "Window").unwrap_or_default(),
            sequence: child_text(child, "KeystrokeSequence").unwrap_or_default(),
        });
    }

    auto_type
}

fn meta_known_child_name(name: &str) -> bool {
    matches!(
        name,
        "Generator"
            | "SettingsChanged"
            | "DatabaseName"
            | "DatabaseNameChanged"
            | "HeaderHash"
            | "Binaries"
            | "DatabaseDescription"
            | "DatabaseDescriptionChanged"
            | "DefaultUserName"
            | "DefaultUserNameChanged"
            | "MaintenanceHistoryDays"
            | "Color"
            | "MemoryProtection"
            | "CustomIcons"
            | "RecycleBinEnabled"
            | "RecycleBinUUID"
            | "RecycleBinChanged"
            | "EntryTemplatesGroup"
            | "EntryTemplatesGroupChanged"
            | "MasterKeyChanged"
            | "MasterKeyChangeRec"
            | "MasterKeyChangeForce"
            | "MasterKeyChangeForceOnce"
            | "LastSelectedGroup"
            | "LastTopVisibleGroup"
            | "HistoryMaxItems"
            | "HistoryMaxSize"
            | "CustomData"
    )
}

fn group_known_child_name(name: &str) -> bool {
    matches!(
        name,
        "UUID"
            | "Name"
            | "Notes"
            | "IconID"
            | "CustomIconUUID"
            | "Tags"
            | "Times"
            | "IsExpanded"
            | "DefaultAutoTypeSequence"
            | "EnableAutoType"
            | "EnableSearching"
            | "LastTopVisibleEntry"
            | "CustomData"
            | "PreviousParentGroup"
            | "Entry"
            | "Group"
    )
}

fn entry_known_child_name(name: &str) -> bool {
    matches!(
        name,
        "UUID"
            | "IconID"
            | "CustomIconUUID"
            | "ForegroundColor"
            | "BackgroundColor"
            | "OverrideURL"
            | "Tags"
            | "PreviousParentGroup"
            | "QualityCheck"
            | "Times"
            | "String"
            | "Binary"
            | "AutoType"
            | "CustomData"
            | "History"
    )
}

fn parse_custom_data_items(custom_data: &Element, include_item_times: bool) -> Vec<CustomDataItem> {
    let mut items = Vec::new();
    for item in &custom_data.children {
        let XMLNode::Element(item) = item else {
            continue;
        };
        if item.name != "Item" {
            continue;
        }
        let Some(key) = child_text(item, "Key") else {
            continue;
        };
        let value = child_text(item, "Value").unwrap_or_default();
        let last_modified = if include_item_times {
            child_text(item, "LastModificationTime")
                .as_deref()
                .and_then(parse_optional_datetime)
        } else {
            None
        };
        items.push(CustomDataItem {
            key,
            value,
            last_modified,
        });
    }
    items
}

fn parse_custom_data_blocks_with_known_children(
    element: &Element,
    is_known_child: impl Fn(&str) -> bool,
    include_item_times: bool,
) -> Result<(BTreeMap<String, String>, Vec<CustomDataBlock>)> {
    let mut merged = BTreeMap::new();
    let mut blocks = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut last_anchor: Option<OpaqueXmlAnchor> = None;

    for child in &element.children {
        let XMLNode::Element(child) = child else {
            continue;
        };

        if child.name == "CustomData" {
            let items = parse_custom_data_items(child, include_item_times);
            for item in &items {
                merged.insert(item.key.clone(), item.value.clone());
            }
            blocks.push(CustomDataBlock {
                items,
                after: last_anchor.clone(),
            });
            let occurrence = counts.entry(child.name.clone()).or_insert(0);
            *occurrence += 1;
            last_anchor = Some(OpaqueXmlAnchor {
                element_name: child.name.clone(),
                occurrence: *occurrence,
            });
            continue;
        }

        if is_known_child(child.name.as_str()) {
            let occurrence = counts.entry(child.name.clone()).or_insert(0);
            *occurrence += 1;
            last_anchor = Some(OpaqueXmlAnchor {
                element_name: child.name.clone(),
                occurrence: *occurrence,
            });
        }
    }

    Ok((merged, blocks))
}

fn parse_meta_custom_data(
    element: &Element,
) -> Result<(BTreeMap<String, String>, Vec<CustomDataBlock>)> {
    parse_custom_data_blocks_with_known_children(element, meta_known_child_name, true)
}

fn parse_group_custom_data(
    element: &Element,
) -> Result<(BTreeMap<String, String>, Vec<CustomDataBlock>)> {
    parse_custom_data_blocks_with_known_children(element, group_known_child_name, true)
}

fn parse_entry_custom_data(
    element: &Element,
) -> Result<(BTreeMap<String, String>, Vec<CustomDataBlock>)> {
    parse_custom_data_blocks_with_known_children(element, entry_known_child_name, true)
}

fn parse_string_field(
    element: &Element,
    protected: &mut ProtectedStream,
) -> Result<(String, CustomField)> {
    let key = child_text(element, "Key").ok_or(KdbxError::InvalidValue)?;
    let value_element = child_optional(element, "Value").ok_or(KdbxError::InvalidValue)?;
    let mut value = value_element
        .get_text()
        .map(|text| text.to_string())
        .unwrap_or_default();
    let is_protected = value_element
        .attributes
        .get("Protected")
        .map(|value| parse_bool_text(value))
        .unwrap_or(false);

    if is_protected {
        let mut bytes = STANDARD
            .decode(value.as_bytes())
            .map_err(|_| KdbxError::InvalidValue)?;
        protected.apply(&mut bytes);
        value = String::from_utf8(bytes).map_err(|_| KdbxError::InvalidValue)?;
    }

    Ok((
        key,
        CustomField {
            value,
            protected: is_protected,
        },
    ))
}

fn collect_attachment_refs(
    vault: &Vault,
    binaries: &mut Vec<InnerBinary>,
) -> HashMap<(usize, String), usize> {
    let mut refs = HashMap::new();
    let mut dedup = BTreeMap::<(bool, Vec<u8>), usize>::new();

    fn walk(
        group: &Group,
        refs: &mut HashMap<(usize, String), usize>,
        dedup: &mut BTreeMap<(bool, Vec<u8>), usize>,
        binaries: &mut Vec<InnerBinary>,
    ) {
        for entry in &group.entries {
            for attachment in entry.attachments.values() {
                let dedup_key = (attachment.protect_in_memory, attachment.data.clone());
                let index = if let Some(index) = dedup.get(&dedup_key) {
                    *index
                } else {
                    let index = binaries.len();
                    binaries.push(InnerBinary {
                        protect_in_memory: attachment.protect_in_memory,
                        data: attachment.data.clone(),
                    });
                    dedup.insert(dedup_key, index);
                    index
                };
                refs.insert((entry_ref_key(entry), attachment.name.clone()), index);
            }
            for history in &entry.history {
                for attachment in history.attachments.values() {
                    let dedup_key = (attachment.protect_in_memory, attachment.data.clone());
                    let index = if let Some(index) = dedup.get(&dedup_key) {
                        *index
                    } else {
                        let index = binaries.len();
                        binaries.push(InnerBinary {
                            protect_in_memory: attachment.protect_in_memory,
                            data: attachment.data.clone(),
                        });
                        dedup.insert(dedup_key, index);
                        index
                    };
                    refs.insert((entry_ref_key(history), attachment.name.clone()), index);
                }
            }
        }
        for child in &group.children {
            walk(child, refs, dedup, binaries);
        }
    }

    walk(&vault.root, &mut refs, &mut dedup, binaries);
    refs
}

fn entry_ref_key(entry: &Entry) -> usize {
    entry as *const Entry as usize
}

fn decode_legacy_block_stream(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(bytes);
    let mut plaintext = Vec::new();
    let mut index = 0_u32;

    loop {
        let block_index = cursor.read_u32()?;
        let block_hash = cursor.read_exact(32)?.to_vec();
        let block_size = cursor.read_u32()? as usize;

        if block_index != index {
            return Err(KdbxError::InvalidValue);
        }
        if block_size == 0 {
            break;
        }

        let block = cursor.read_exact(block_size)?.to_vec();
        if sha256_bytes(&block).as_slice() != block_hash.as_slice() {
            return Err(KdbxError::PayloadHashMismatch);
        }

        plaintext.extend(block);
        index = index.saturating_add(1);
    }

    Ok(plaintext)
}

fn encode_block_stream(mac_seed: &[u8; 64], encrypted_payload: &[u8]) -> Result<Vec<u8>> {
    const BLOCK_SIZE: usize = 1024 * 1024;
    let mut bytes = Vec::new();

    for (index, chunk) in encrypted_payload.chunks(BLOCK_SIZE).enumerate() {
        let index_u64 = index as u64;
        let hmac_key = block_hmac_key(mac_seed, index_u64);
        let mut mac_input = Vec::with_capacity(8 + 4 + chunk.len());
        mac_input.extend(index_u64.to_le_bytes());
        mac_input.extend((chunk.len() as i32).to_le_bytes());
        mac_input.extend(chunk);
        let mac = hmac_sha256(&hmac_key, &mac_input)?;
        bytes.extend(mac);
        bytes.extend((chunk.len() as i32).to_le_bytes());
        bytes.extend(chunk);
    }

    let terminator_index = encrypted_payload.chunks(BLOCK_SIZE).count() as u64;
    let hmac_key = block_hmac_key(mac_seed, terminator_index);
    let mut mac_input = Vec::with_capacity(12);
    mac_input.extend(terminator_index.to_le_bytes());
    mac_input.extend(0_i32.to_le_bytes());
    let mac = hmac_sha256(&hmac_key, &mac_input)?;
    bytes.extend(mac);
    bytes.extend(0_i32.to_le_bytes());
    Ok(bytes)
}

fn decode_block_stream(mac_seed: &[u8; 64], bytes: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(bytes);
    let mut plaintext = Vec::new();
    let mut index = 0_u64;

    loop {
        let mac = cursor.read_exact(32)?.to_vec();
        let size = cursor.read_i32()?;
        if size < 0 {
            return Err(KdbxError::InvalidValue);
        }
        let chunk = cursor.read_exact(size as usize)?.to_vec();

        let mut mac_input = Vec::with_capacity(8 + 4 + chunk.len());
        mac_input.extend(index.to_le_bytes());
        mac_input.extend(size.to_le_bytes());
        mac_input.extend(&chunk);
        let expected = hmac_sha256(&block_hmac_key(mac_seed, index), &mac_input)?;
        if expected.as_slice() != mac.as_slice() {
            return Err(KdbxError::PayloadHmacMismatch);
        }

        if size == 0 {
            break;
        }

        plaintext.extend(chunk);
        index += 1;
    }

    Ok(plaintext)
}

fn header_hmac(mac_seed: &[u8; 64], header_bytes: &[u8]) -> Result<[u8; 32]> {
    let mut prefix = [0xFF_u8; 8];
    prefix.reverse();
    let mut material = Vec::with_capacity(8 + mac_seed.len());
    material.extend(prefix);
    material.extend(mac_seed);
    let key = sha512_bytes(&material);
    hmac_sha256(&key, header_bytes).map_err(KdbxError::from)
}

fn block_hmac_key(mac_seed: &[u8; 64], index: u64) -> [u8; 64] {
    let mut material = Vec::with_capacity(8 + mac_seed.len());
    material.extend(index.to_le_bytes());
    material.extend(mac_seed);
    sha512_bytes(&material)
}

fn mac_seed(master_seed: &[u8; 32], transformed: &[u8; 32]) -> [u8; 64] {
    let mut material = Vec::with_capacity(master_seed.len() + transformed.len() + 1);
    material.extend(master_seed);
    material.extend(transformed);
    material.push(0x01);
    sha512_bytes(&material)
}

fn sha256_seeded(master_seed: &[u8; 32], transformed: &[u8; 32]) -> [u8; 32] {
    let mut material = Vec::with_capacity(master_seed.len() + transformed.len());
    material.extend(master_seed);
    material.extend(transformed);
    sha256_bytes(&material)
}

fn derive_chacha20_inner_stream_key(inner_key: &[u8]) -> Result<([u8; 32], [u8; 12])> {
    if inner_key.len() < 32 {
        return Err(KdbxError::InvalidValue);
    }
    let digest = sha512_bytes(inner_key);
    let key = digest[..32]
        .try_into()
        .map_err(|_| KdbxError::InvalidValue)?;
    let nonce = digest[32..44]
        .try_into()
        .map_err(|_| KdbxError::InvalidValue)?;
    Ok((key, nonce))
}

fn derive_salsa20_inner_stream_key(inner_key: &[u8]) -> [u8; 32] {
    sha256_bytes(inner_key)
}

fn gzip_compress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), GzipCompression::default());
    encoder
        .write_all(bytes)
        .map_err(|_| KdbxError::InvalidValue)?;
    encoder.finish().map_err(|_| KdbxError::InvalidValue)
}

fn gzip_decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|_| KdbxError::InvalidValue)?;
    Ok(output)
}

fn random_array_32() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&random_bytes(32));
    bytes
}

fn random_iv(cipher: KdbxCipher) -> Vec<u8> {
    match cipher {
        KdbxCipher::Aes256 | KdbxCipher::Twofish => random_bytes(16),
        KdbxCipher::ChaCha20 => random_bytes(12),
    }
}

fn parse_tags(tags: &str) -> std::collections::BTreeSet<String> {
    tags.split(';')
        .filter(|tag| !tag.is_empty())
        .map(|tag| tag.to_string())
        .collect()
}

fn encode_uuid(uuid: Uuid) -> String {
    STANDARD.encode(uuid.as_bytes())
}

fn decode_uuid(text: &str) -> Result<Uuid> {
    let bytes = STANDARD
        .decode(text.as_bytes())
        .map_err(|_| KdbxError::InvalidValue)?;
    Uuid::from_slice(&bytes).map_err(|_| KdbxError::InvalidValue)
}

fn parse_optional_uuid(text: &str) -> Result<Option<Uuid>> {
    if text.trim().is_empty() {
        Ok(None)
    } else {
        let uuid = decode_uuid(text)?;
        if uuid.is_nil() {
            Ok(None)
        } else {
            Ok(Some(uuid))
        }
    }
}

fn child(element: &Element, name: &str) -> Result<Element> {
    child_optional(element, name).ok_or(KdbxError::InvalidValue)
}

fn child_optional(element: &Element, name: &str) -> Option<Element> {
    element.children.iter().find_map(|child| match child {
        XMLNode::Element(child) if child.name == name => Some(child.clone()),
        _ => None,
    })
}

fn child_text(element: &Element, name: &str) -> Option<String> {
    child_optional(element, name).and_then(|child| child.get_text().map(|text| text.to_string()))
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    }
}

fn parse_bool_text(text: &str) -> bool {
    text.eq_ignore_ascii_case("true") || text == "1"
}

fn parse_nullable_bool(text: &str) -> Option<bool> {
    if text.trim().is_empty() || text.eq_ignore_ascii_case("null") {
        None
    } else {
        Some(parse_bool_text(text))
    }
}

fn bool_text(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

fn datetime_text<T>(version: KdbxVersion, seconds: T) -> String
where
    T: TryInto<i64> + ToString + Copy,
{
    const KDBX4_TIME_OFFSET: i64 = 62_135_596_800;

    match version {
        KdbxVersion::V4_0 | KdbxVersion::V4_1 => seconds
            .try_into()
            .ok()
            .and_then(|seconds| seconds.checked_add(KDBX4_TIME_OFFSET))
            .map(|raw| STANDARD.encode(raw.to_le_bytes()))
            .unwrap_or_else(|| seconds.to_string()),
        KdbxVersion::V2_0 | KdbxVersion::V3_0 | KdbxVersion::V3_1 => seconds
            .try_into()
            .ok()
            .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
            .map(|datetime| datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| seconds.to_string()),
    }
}

fn parse_datetime_value(text: &str) -> Option<u64> {
    const KDBX4_TIME_OFFSET: i64 = 62_135_596_800;

    if let Ok(value) = text.parse::<u64>() {
        return Some(value);
    }

    if let Ok(bytes) = STANDARD.decode(text.as_bytes()) {
        if bytes.len() == 8 {
            let raw = i64::from_le_bytes(bytes.try_into().ok()?);
            return (raw - KDBX4_TIME_OFFSET).try_into().ok();
        }
    }

    let parsed = DateTime::parse_from_rfc3339(text).ok()?;
    parsed.with_timezone(&Utc).timestamp().try_into().ok()
}

fn parse_optional_datetime(text: &str) -> Option<i64> {
    if text.trim().is_empty() {
        None
    } else {
        parse_datetime_value(text).map(|value| value as i64)
    }
}

fn text_element(name: &str, text: &str) -> Element {
    let mut element = Element::new(name);
    element.children.push(XMLNode::Text(text.to_string()));
    element
}

fn version_to_u32(version: KdbxVersion) -> u32 {
    match version {
        KdbxVersion::V2_0 => 0x0002_0004,
        KdbxVersion::V3_0 => 0x0003_0000,
        KdbxVersion::V3_1 => 0x0003_0001,
        KdbxVersion::V4_0 => 0x0004_0000,
        KdbxVersion::V4_1 => 0x0004_0001,
    }
}

fn u32_to_version(version: u32) -> Result<KdbxVersion> {
    match version {
        0x0002_0000 => Ok(KdbxVersion::V2_0),
        0x0002_0004 => Ok(KdbxVersion::V2_0),
        0x0003_0000 => Ok(KdbxVersion::V3_0),
        0x0003_0001 => Ok(KdbxVersion::V3_1),
        0x0004_0000 => Ok(KdbxVersion::V4_0),
        0x0004_0001 => Ok(KdbxVersion::V4_1),
        _ => Err(KdbxError::InvalidValue),
    }
}

fn cipher_uuid(cipher: KdbxCipher) -> Uuid {
    match cipher {
        KdbxCipher::Aes256 => AES256_UUID,
        KdbxCipher::ChaCha20 => CHACHA20_UUID,
        KdbxCipher::Twofish => TWOFISH_UUID,
    }
}

fn uuid_to_cipher(uuid: Uuid) -> Result<KdbxCipher> {
    if uuid == AES256_UUID {
        Ok(KdbxCipher::Aes256)
    } else if uuid == CHACHA20_UUID {
        Ok(KdbxCipher::ChaCha20)
    } else if uuid == TWOFISH_UUID {
        Ok(KdbxCipher::Twofish)
    } else {
        Err(KdbxError::InvalidValue)
    }
}

fn write_field(bytes: &mut Vec<u8>, id: u8, data: &[u8]) {
    bytes.push(id);
    bytes.extend((data.len() as i32).to_le_bytes());
    bytes.extend(data);
}

fn group_requires_41(group: &Group) -> bool {
    if !group.tags.is_empty() || group.previous_parent.is_some() {
        return true;
    }

    if group.entries.iter().any(|entry| {
        entry.exclude_from_reports || entry.previous_parent.is_some() || entry.passkey.is_some()
    }) {
        return true;
    }

    group.children.iter().any(group_requires_41)
}

fn build_totp(fields: &BTreeMap<String, CustomField>) -> Option<TotpSpec> {
    if let Some(field) = fields.get("otp") {
        if let Ok(spec) = TotpSpec::parse_otpauth(&field.value) {
            return Some(spec);
        }
    }

    let secret = fields.get("TimeOtp-Secret-Base32")?.value.clone();
    let algorithm = match fields
        .get("TimeOtp-Algorithm")
        .map(|field| field.value.as_str())
    {
        Some("HMAC-SHA-256") => TotpAlgorithm::Sha256,
        Some("HMAC-SHA-512") => TotpAlgorithm::Sha512,
        _ => TotpAlgorithm::Sha1,
    };
    let digits = fields
        .get("TimeOtp-Length")
        .and_then(|field| field.value.parse().ok())
        .unwrap_or(6);
    let period_seconds = fields
        .get("TimeOtp-Period")
        .and_then(|field| field.value.parse().ok())
        .unwrap_or(30);

    Some(TotpSpec {
        secret_base32: secret,
        algorithm,
        digits,
        period_seconds,
        issuer: None,
        account_name: None,
    })
}

fn build_otpauth_uri(entry: &Entry, totp: &TotpSpec) -> String {
    let issuer = totp.issuer.clone().unwrap_or_else(|| entry.title.clone());
    let account_name = totp
        .account_name
        .clone()
        .unwrap_or_else(|| entry.username.clone());
    let label = if account_name.is_empty() {
        percent_encode_component(&issuer)
    } else {
        format!(
            "{}:{}",
            percent_encode_component(&issuer),
            percent_encode_component(&account_name)
        )
    };
    let algorithm = match totp.algorithm {
        TotpAlgorithm::Sha1 => "SHA1",
        TotpAlgorithm::Sha256 => "SHA256",
        TotpAlgorithm::Sha512 => "SHA512",
    };
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}",
        label = label,
        secret = percent_encode_component(&totp.secret_base32),
        issuer = percent_encode_component(&issuer),
        algorithm = algorithm,
        digits = totp.digits,
        period = totp.period_seconds,
    )
}

fn percent_encode_component(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push_str(&format!("{byte:02X}"));
            }
        }
    }
    encoded
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InnerBinary {
    protect_in_memory: bool,
    data: Vec<u8>,
}

struct ProtectedStream {
    cipher: ProtectedStreamCipher,
}

enum ProtectedStreamCipher {
    Plain,
    ChaCha20(ChaCha20Stream),
    Salsa20(Salsa20Stream),
}

impl ProtectedStream {
    fn new_plain() -> Self {
        Self {
            cipher: ProtectedStreamCipher::Plain,
        }
    }

    fn new_chacha(inner_key: &[u8]) -> Result<Self> {
        let (key, nonce) = derive_chacha20_inner_stream_key(inner_key)?;
        Ok(Self {
            cipher: ProtectedStreamCipher::ChaCha20(ChaCha20Stream::new(&key, &nonce)),
        })
    }

    fn new_salsa(inner_key: &[u8]) -> Self {
        const SALSA20_NONCE: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
        let key = derive_salsa20_inner_stream_key(inner_key);
        Self {
            cipher: ProtectedStreamCipher::Salsa20(Salsa20Stream::new(&key, &SALSA20_NONCE)),
        }
    }

    fn from_stream(stream_id: u32, inner_key: &[u8]) -> Result<Self> {
        match stream_id {
            0 => Ok(Self::new_plain()),
            2 => Ok(Self::new_salsa(inner_key)),
            3 => Self::new_chacha(inner_key),
            _ => Err(KdbxError::UnsupportedInnerStream),
        }
    }

    fn apply(&mut self, bytes: &mut [u8]) {
        match &mut self.cipher {
            ProtectedStreamCipher::Plain => {}
            ProtectedStreamCipher::ChaCha20(stream) => stream.apply(bytes),
            ProtectedStreamCipher::Salsa20(stream) => stream.apply(bytes),
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.position + len > self.bytes.len() {
            return Err(KdbxError::UnexpectedEof);
        }
        let slice = &self.bytes[self.position..self.position + len];
        self.position += len;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(*self
            .read_exact(1)?
            .first()
            .ok_or(KdbxError::UnexpectedEof)?)
    }

    fn read_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.read_exact(2)?
                .try_into()
                .map_err(|_| KdbxError::InvalidValue)?,
        ))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.read_exact(4)?
                .try_into()
                .map_err(|_| KdbxError::InvalidValue)?,
        ))
    }

    fn read_i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(
            self.read_exact(4)?
                .try_into()
                .map_err(|_| KdbxError::InvalidValue)?,
        ))
    }

    fn read_remaining(&mut self) -> &'a [u8] {
        let slice = &self.bytes[self.position..];
        self.position = self.bytes.len();
        slice
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::{
        Compression, KdbxCipher, KdbxHeader, KdbxVersion, SaveKdf, SaveProfile, child_text,
        decode_block_stream, decrypt_payload, encode_block_stream, gzip_compress, gzip_decompress,
        header_hmac, kdf_from_variant_dict, load_kdbx, mac_seed, parse_inner_header, save_kdbx,
        sha256_seeded, text_element,
    };
    use vaultkern_crypto::{CompositeKey, sha256_bytes};
    use vaultkern_model::{CustomField, Entry, PasskeyRecord, Vault};
    use xmltree::{Element, XMLNode};

    fn fast_profile() -> SaveProfile {
        SaveProfile {
            version: KdbxVersion::V4_1,
            cipher: KdbxCipher::Aes256,
            compression: Compression::Gzip,
            kdf: SaveKdf::AesKdbx4 { rounds: 1 },
        }
    }

    fn test_key(password: &str) -> CompositeKey {
        let mut key = CompositeKey::default();
        key.add_password(password);
        key
    }

    fn extract_kdbx4_xml(bytes: &[u8], composite_key: &CompositeKey) -> super::Result<String> {
        let (header, header_len) = KdbxHeader::decode_with_consumed(bytes)?;
        let mut cursor = super::Cursor::new(&bytes[header_len..]);
        let stored_header_hash = cursor.read_exact(32)?.to_vec();
        let _stored_header_hmac = cursor.read_exact(32)?.to_vec();
        let payload_bytes = cursor.read_remaining().to_vec();

        let header_bytes = &bytes[..header_len];
        assert_eq!(
            sha256_bytes(header_bytes).as_slice(),
            stored_header_hash.as_slice()
        );

        let raw_key = composite_key.raw_key()?;
        let kdf = kdf_from_variant_dict(&header.kdf_parameters)?;
        let transformed = kdf.derive_key(&raw_key)?;
        let encryption_key = sha256_seeded(&header.master_seed, &transformed);
        let mac_seed = mac_seed(&header.master_seed, &transformed);
        let encrypted_payload = decode_block_stream(&mac_seed, &payload_bytes)?;
        let payload = decrypt_payload(
            header.cipher,
            &encryption_key,
            &header.encryption_iv,
            &encrypted_payload,
        )?;
        let payload = match header.compression {
            Compression::None => payload,
            Compression::Gzip => gzip_decompress(&payload)?,
        };
        let (_, _, _, consumed) = parse_inner_header(&payload)?;
        String::from_utf8(payload[consumed..].to_vec()).map_err(|_| super::KdbxError::InvalidValue)
    }

    fn rewrite_kdbx4_xml(
        bytes: &[u8],
        composite_key: &CompositeKey,
        mutate: impl FnOnce(&mut Element),
    ) -> super::Result<Vec<u8>> {
        let (header, header_len) = KdbxHeader::decode_with_consumed(bytes)?;
        let mut cursor = super::Cursor::new(&bytes[header_len..]);
        let _stored_header_hash = cursor.read_exact(32)?.to_vec();
        let _stored_header_hmac = cursor.read_exact(32)?.to_vec();
        let payload_bytes = cursor.read_remaining().to_vec();

        let raw_key = composite_key.raw_key()?;
        let kdf = kdf_from_variant_dict(&header.kdf_parameters)?;
        let transformed = kdf.derive_key(&raw_key)?;
        let encryption_key = sha256_seeded(&header.master_seed, &transformed);
        let mac_seed = mac_seed(&header.master_seed, &transformed);
        let encrypted_payload = decode_block_stream(&mac_seed, &payload_bytes)?;
        let payload = decrypt_payload(
            header.cipher,
            &encryption_key,
            &header.encryption_iv,
            &encrypted_payload,
        )?;
        let payload = match header.compression {
            Compression::None => payload,
            Compression::Gzip => gzip_decompress(&payload)?,
        };

        let (_, _, _, consumed) = parse_inner_header(&payload)?;
        let mut xml = Element::parse(std::io::Cursor::new(&payload[consumed..]))
            .map_err(|error| super::KdbxError::Xml(error.to_string()))?;
        mutate(&mut xml);
        let mut xml_bytes = Vec::new();
        xml.write(&mut xml_bytes)
            .map_err(|error| super::KdbxError::Xml(error.to_string()))?;

        let mut new_payload = payload[..consumed].to_vec();
        new_payload.extend(xml_bytes);
        let payload = match header.compression {
            Compression::None => new_payload,
            Compression::Gzip => gzip_compress(&new_payload)?,
        };
        let encrypted_payload = super::encrypt_payload(
            header.cipher,
            &encryption_key,
            &header.encryption_iv,
            &payload,
        )?;
        let block_stream = encode_block_stream(&mac_seed, &encrypted_payload)?;
        let header_bytes = header.encode()?;
        let header_hash = sha256_bytes(&header_bytes);
        let header_hmac = header_hmac(&mac_seed, &header_bytes)?;

        let mut file = Vec::new();
        file.extend(header_bytes);
        file.extend(header_hash);
        file.extend(header_hmac);
        file.extend(block_stream);
        Ok(file)
    }

    fn first_live_entry_mut(root: &mut Element) -> &mut Element {
        root.get_mut_child("Root")
            .and_then(|root| root.get_mut_child("Group"))
            .and_then(|group| group.get_mut_child("Entry"))
            .expect("live entry")
    }

    fn first_live_entry(root: &Element) -> &Element {
        root.get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("live entry")
    }

    #[test]
    fn known_bad_custom_data_upgrades_to_quality_check_false() {
        let mut vault = Vault::empty("KnownBad");
        let mut entry = Entry::new("Legacy");
        entry.custom_data.insert("KnownBad".into(), "True".into());
        vault.root.entries.push(entry);

        let key = test_key("known-bad");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save legacy known bad");
        let loaded = load_kdbx(&bytes, &key).expect("load legacy known bad");
        let loaded_entry = &loaded.root.entries[0];

        assert!(loaded_entry.exclude_from_reports);
        assert!(!loaded_entry.custom_data.contains_key("KnownBad"));
        assert!(
            loaded_entry
                .custom_data_blocks
                .iter()
                .flat_map(|block| &block.items)
                .all(|item| item.key != "KnownBad")
        );

        let rewritten = save_kdbx(&loaded, &key, &fast_profile()).expect("save upgraded known bad");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten xml");
        let parsed =
            Element::parse(std::io::Cursor::new(xml.as_bytes())).expect("parse rewritten xml");
        let entry = first_live_entry(&parsed);

        assert_eq!(child_text(entry, "QualityCheck").as_deref(), Some("False"));
        assert!(!xml.contains("<Key>KnownBad</Key>"));
    }

    #[test]
    fn quality_check_true_roundtrip_preserves_explicit_true() {
        let mut vault = Vault::empty("QualityCheck");
        vault.root.entries.push(Entry::new("ExplicitTrue"));

        let key = test_key("quality-check");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save quality check seed");
        let injected = rewrite_kdbx4_xml(&bytes, &key, |root| {
            first_live_entry_mut(root)
                .children
                .push(XMLNode::Element(text_element("QualityCheck", "True")));
        })
        .expect("inject quality check true");

        let loaded = load_kdbx(&injected, &key).expect("load quality check true");
        assert!(!loaded.root.entries[0].exclude_from_reports);

        let rewritten = save_kdbx(&loaded, &key, &fast_profile()).expect("save quality check true");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten xml");
        let parsed =
            Element::parse(std::io::Cursor::new(xml.as_bytes())).expect("parse rewritten xml");
        let entry = first_live_entry(&parsed);

        assert_eq!(child_text(entry, "QualityCheck").as_deref(), Some("True"));
    }

    #[test]
    fn partial_passkey_fields_roundtrip_as_custom_fields() {
        let mut vault = Vault::empty("PartialPasskey");
        let mut entry = Entry::new("Example");
        entry.attributes.insert(
            PasskeyRecord::CREDENTIAL_ID_KEY.into(),
            CustomField {
                value: "partial-credential".into(),
                protected: true,
            },
        );
        vault.root.entries.push(entry);

        let key = test_key("partial-passkey");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save kdbx");
        let loaded = load_kdbx(&bytes, &key).expect("load kdbx");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert!(loaded_entry.passkey.is_none());
        assert_eq!(
            loaded_entry
                .attributes
                .get(PasskeyRecord::CREDENTIAL_ID_KEY)
                .map(|field| (field.value.as_str(), field.protected)),
            Some(("partial-credential", true))
        );

        let rewritten = save_kdbx(&loaded, &key, &fast_profile()).expect("save kdbx");
        let reloaded = load_kdbx(&rewritten, &key).expect("reload kdbx");
        let reloaded_entry = reloaded.root.entries.first().expect("reloaded entry");

        assert_eq!(
            reloaded_entry
                .attributes
                .get(PasskeyRecord::CREDENTIAL_ID_KEY)
                .map(|field| (field.value.as_str(), field.protected)),
            Some(("partial-credential", true))
        );
    }

    #[test]
    fn complete_kpex_passkey_preserves_passkey_username_custom_field() {
        let mut vault = Vault::empty("LegacyUsernameCustomField");
        let mut entry = Entry::new("Example");
        entry.passkey = Some(PasskeyRecord {
            username: "alice@example.com".into(),
            credential_id: "credential-1".into(),
            generated_user_id: None,
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".into(),
            relying_party: "example.com".into(),
            user_handle: Some("user-handle".into()),
            backup_eligible: true,
            backup_state: true,
        });
        entry.attributes.insert(
            "Passkey Username".into(),
            CustomField {
                value: "custom legacy label".into(),
                protected: false,
            },
        );
        vault.root.entries.push(entry);

        let key = test_key("legacy-passkey-username-custom-field");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save kdbx");
        let loaded = load_kdbx(&bytes, &key).expect("load kdbx");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert_eq!(
            loaded_entry
                .attributes
                .get("Passkey Username")
                .map(|field| (field.value.as_str(), field.protected)),
            Some(("custom legacy label", false))
        );
    }
}

#[cfg(all(test, feature = "external-fixtures"))]
mod tests {
    use super::{
        Compression, KdbxCipher, KdbxHeader, KdbxVersion, SaveProfile, VariantDictionary,
        VariantValue, bool_text, child_text, decode_block_stream, decode_kdbx3_header,
        decode_legacy_block_stream, decrypt_payload, detect_file_version, encode_block_stream,
        gzip_compress, gzip_decompress, header_hmac, kdf_from_variant_dict, load_kdbx, mac_seed,
        parse_inner_header, parse_xml_fragment, required_version, save_kdbx, sha256_seeded,
        text_element,
    };
    use base64::Engine as _;
    use vaultkern_crypto::{CompositeKey, KdfProfile, sha256_bytes};
    use vaultkern_model::{CustomDataBlock, CustomDataItem, Entry, Group, MemoryProtection, Vault};
    use xmltree::{Element, XMLNode};

    const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
        include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
    const FIXTURE_NEW_DATABASE_MULTI: &[u8] =
        include_bytes!("../../../fixtures/kdbx/NewDatabaseMulti.kdbx");
    const FIXTURE_FORMAT200: &[u8] = include_bytes!("../../../fixtures/kdbx/Format200.kdbx");
    const FIXTURE_FORMAT400: &[u8] = include_bytes!("../../../fixtures/kdbx/Format400.kdbx");
    const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
    const FIXTURE_MERGE_DATABASE: &[u8] =
        include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");
    const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");
    const FIXTURE_PROTECTED_STRINGS: &[u8] =
        include_bytes!("../../../fixtures/kdbx/ProtectedStrings.kdbx");
    const FIXTURE_NON_ASCII: &[u8] = include_bytes!("../../../fixtures/kdbx/NonAscii.kdbx");
    const FIXTURE_COMPRESSED: &[u8] = include_bytes!("../../../fixtures/kdbx/Compressed.kdbx");
    const FIXTURE_RECYCLE_BIN_DISABLED: &[u8] =
        include_bytes!("../../../fixtures/kdbx/RecycleBinDisabled.kdbx");
    const FIXTURE_RECYCLE_BIN_NOT_YET_CREATED: &[u8] =
        include_bytes!("../../../fixtures/kdbx/RecycleBinNotYetCreated.kdbx");
    const FIXTURE_RECYCLE_BIN_EMPTY: &[u8] =
        include_bytes!("../../../fixtures/kdbx/RecycleBinEmpty.kdbx");
    const FIXTURE_RECYCLE_BIN_WITH_DATA: &[u8] =
        include_bytes!("../../../fixtures/kdbx/RecycleBinWithData.kdbx");
    const FIXTURE_KEY_FILE_PROTECTED_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/KeyFileProtected.kdbx");
    const FIXTURE_KEY_FILE_PROTECTED: &[u8] =
        include_bytes!("../../../fixtures/kdbx/KeyFileProtected.key");
    const FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/KeyFileProtectedNoPassword.kdbx");
    const FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD: &[u8] =
        include_bytes!("../../../fixtures/kdbx/KeyFileProtectedNoPassword.key");
    const FIXTURE_FILE_KEY_BINARY_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyBinary.kdbx");
    const FIXTURE_FILE_KEY_BINARY: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyBinary.key");
    const FIXTURE_FILE_KEY_HEX_DB: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyHex.kdbx");
    const FIXTURE_FILE_KEY_HEX: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyHex.key");
    const FIXTURE_FILE_KEY_HASHED_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyHashed.kdbx");
    const FIXTURE_FILE_KEY_HASHED: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyHashed.key");
    const FIXTURE_FILE_KEY_XML_DB: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyXml.kdbx");
    const FIXTURE_FILE_KEY_XML: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyXml.key");
    const FIXTURE_FILE_KEY_XML_V2_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyXmlV2.kdbx");
    const FIXTURE_FILE_KEY_XML_V2: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyXmlV2.keyx");
    const FIXTURE_SCHEMA_COMPAT_KNOWN_BAD: &[u8] =
        include_bytes!("../../../fixtures/kdbx/SchemaCompatKnownBad.kdbx");
    const FIXTURE_SCHEMA_COMPAT_QUALITY_CHECK_TRUE: &[u8] =
        include_bytes!("../../../fixtures/kdbx/SchemaCompatQualityCheckTrue.kdbx");

    #[test]
    fn variant_dictionary_roundtrips_supported_types() {
        let mut dictionary = VariantDictionary::default();
        dictionary.insert("$UUID", VariantValue::Bytes(vec![1, 2, 3]));
        dictionary.insert("R", VariantValue::UInt64(42));
        dictionary.insert("Name", VariantValue::String("alpha".into()));
        dictionary.insert("Enabled", VariantValue::Bool(true));

        let encoded = dictionary.encode().expect("encode dictionary");
        let decoded = VariantDictionary::decode(&encoded).expect("decode dictionary");

        assert_eq!(decoded.get("R"), Some(&VariantValue::UInt64(42)));
        assert_eq!(
            decoded.get("Name"),
            Some(&VariantValue::String("alpha".into()))
        );
        assert_eq!(decoded.get("Enabled"), Some(&VariantValue::Bool(true)));
    }

    #[test]
    fn schema_compat_known_bad_fixture_upgrades_to_quality_check_false() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_SCHEMA_COMPAT_KNOWN_BAD, &key).expect("extract fixture xml");
        assert!(original_xml.contains("<Key>KnownBad</Key>"));

        let loaded =
            load_kdbx(FIXTURE_SCHEMA_COMPAT_KNOWN_BAD, &key).expect("load known bad fixture");
        let entry = loaded.root.entries.first().expect("known bad entry");
        assert!(entry.exclude_from_reports);
        assert!(!entry.custom_data.contains_key("KnownBad"));
        assert!(
            entry
                .custom_data_blocks
                .iter()
                .flat_map(|block| &block.items)
                .all(|item| item.key != "KnownBad")
        );

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save known bad fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten known bad xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten known bad xml");
        let mut entries = Vec::new();
        collect_entry_elements(&rewritten_parsed, &mut entries);
        let rewritten_entry = entries.first().expect("rewritten known bad entry");

        assert_eq!(
            child_text(rewritten_entry, "QualityCheck").as_deref(),
            Some("False")
        );
        assert!(!rewritten_xml.contains("<Key>KnownBad</Key>"));
    }

    #[test]
    fn schema_compat_quality_check_true_fixture_preserves_explicit_true() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml = extract_kdbx4_xml(FIXTURE_SCHEMA_COMPAT_QUALITY_CHECK_TRUE, &key)
            .expect("extract fixture xml");
        let original_parsed =
            Element::parse(original_xml.as_bytes()).expect("parse quality check true fixture");
        let mut original_entries = Vec::new();
        collect_entry_elements(&original_parsed, &mut original_entries);
        let original_entry = original_entries
            .first()
            .expect("quality check true fixture entry");
        assert_eq!(
            child_text(original_entry, "QualityCheck").as_deref(),
            Some("True")
        );

        let loaded = load_kdbx(FIXTURE_SCHEMA_COMPAT_QUALITY_CHECK_TRUE, &key)
            .expect("load quality check true fixture");
        assert!(!loaded.root.entries[0].exclude_from_reports);

        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save quality check true fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten quality check true xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten quality check true");
        let mut rewritten_entries = Vec::new();
        collect_entry_elements(&rewritten_parsed, &mut rewritten_entries);
        let rewritten_entry = rewritten_entries
            .first()
            .expect("rewritten quality check true entry");

        assert_eq!(
            child_text(rewritten_entry, "QualityCheck").as_deref(),
            Some("True")
        );
    }

    #[test]
    fn header_roundtrips_known_and_unknown_fields() {
        let mut header = KdbxHeader::new(KdbxVersion::V4_1, KdbxCipher::ChaCha20);
        header.compression = Compression::None;
        header.master_seed = [7_u8; 32];
        header.encryption_iv = vec![9_u8; 12];
        header
            .public_custom_data
            .insert("Client", VariantValue::String("mobile".into()));
        header.unknown_fields.push(super::UnknownHeaderField {
            id: 0x7F,
            data: vec![9, 8, 7],
        });

        let encoded = header.encode().expect("encode header");
        let decoded = KdbxHeader::decode(&encoded).expect("decode header");

        assert_eq!(decoded.version, KdbxVersion::V4_1);
        assert_eq!(decoded.cipher, KdbxCipher::ChaCha20);
        assert_eq!(decoded.compression, Compression::None);
        assert_eq!(decoded.master_seed, [7_u8; 32]);
        assert_eq!(decoded.encryption_iv, vec![9_u8; 12]);
        assert_eq!(
            decoded.public_custom_data.get("Client"),
            Some(&VariantValue::String("mobile".into()))
        );
        assert_eq!(decoded.unknown_fields.len(), 1);
        assert_eq!(decoded.unknown_fields[0].data, vec![9, 8, 7]);
    }

    #[test]
    fn required_version_uses_4_1_for_extended_metadata() {
        let mut vault = Vault::empty("Demo");
        let mut entry = Entry::new("Tagged");
        entry.exclude_from_reports = true;
        vault.root.entries.push(entry);
        vault.root.tags.insert("shared".into());

        assert_eq!(required_version(&vault), KdbxVersion::V4_1);
    }

    #[test]
    fn kdbx4_roundtrip_preserves_opaque_meta_group_and_entry_xml() {
        let mut vault = Vault::empty("Opaque");
        vault.root.title = "Root".into();
        vault.root.entries.push(Entry::new("Entry"));

        let mut key = CompositeKey::default();
        key.add_password("opaque-pass");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            meta.children.push(XMLNode::Element(parse_xml_fragment(
                "<CustomData><Item><Key>MetaExtra</Key><Value>Alpha</Value></Item></CustomData>",
            )
            .expect("meta custom data")));

            let group = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .expect("group");
            group.children.push(XMLNode::Element(parse_xml_fragment(
                "<CustomData><Item><Key>GroupExtra</Key><Value>Beta</Value></Item></CustomData>",
            )
            .expect("group custom data")));

            let entry = group.get_mut_child("Entry").expect("entry");
            entry.children.push(XMLNode::Element(
                parse_xml_fragment("<UnknownEntryNode><Value>Gamma</Value></UnknownEntryNode>")
                    .expect("unknown entry node"),
            ));
            entry.children.push(XMLNode::Element(parse_xml_fragment(
                "<CustomData><Item><Key>EntryExtra</Key><Value>Delta</Value></Item></CustomData>",
            )
            .expect("entry custom data")));
        })
        .expect("rewrite xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        assert_eq!(
            loaded.meta_custom_data.get("MetaExtra").map(String::as_str),
            Some("Alpha")
        );
        assert_eq!(
            loaded
                .root
                .custom_data
                .get("GroupExtra")
                .map(String::as_str),
            Some("Beta")
        );
        assert!(
            loaded.root.entries[0]
                .opaque_xml
                .iter()
                .any(|fragment| fragment.xml.contains("UnknownEntryNode"))
        );
        assert_eq!(
            loaded.root.entries[0]
                .custom_data
                .get("EntryExtra")
                .map(String::as_str),
            Some("Delta")
        );

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        assert!(xml.contains("MetaExtra"));
        assert!(xml.contains("GroupExtra"));
        assert!(xml.contains("UnknownEntryNode"));
        assert!(xml.contains("EntryExtra"));
    }

    #[test]
    fn kdbx4_roundtrip_preserves_root_opaque_xml_and_deleted_objects() {
        let mut vault = Vault::empty("RootOpaque");
        vault.root.title = "Root".into();
        vault.deleted_objects.push(vaultkern_model::DeletedObject {
            id: uuid::Uuid::new_v4(),
            deleted_at: 1_700_000_000,
        });

        let mut key = CompositeKey::default();
        key.add_password("root-opaque");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let root_node = root.get_mut_child("Root").expect("root node");
            root_node.children.push(XMLNode::Element(
                parse_xml_fragment("<UnknownRootNode><Value>Omega</Value></UnknownRootNode>")
                    .expect("unknown root node"),
            ));
        })
        .expect("rewrite root xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        assert_eq!(loaded.deleted_objects.len(), 1);
        assert_eq!(loaded.deleted_objects[0].deleted_at, 1_700_000_000);
        assert!(
            loaded
                .root_opaque_xml
                .iter()
                .any(|fragment| fragment.xml.contains("UnknownRootNode"))
        );

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        assert!(xml.contains("UnknownRootNode"));
        assert!(xml.contains("DeletionTime"));
    }

    #[test]
    fn kdbx4_roundtrip_preserves_opaque_meta_group_entry_order_relative_to_known_nodes() {
        let mut vault = Vault::empty("OpaqueOrder");
        vault.root.title = "Root".into();
        vault.root.notes = "Root notes".into();
        vault.root.tags.insert("root-tag".into());
        vault.memory_protection = Some(MemoryProtection {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        });

        let mut entry = Entry::new("Entry");
        entry.tags.insert("entry-tag".into());
        entry
            .custom_data
            .insert("EntryKey".into(), "EntryValue".into());
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("opaque-order");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            let memory_protection_index = meta
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "MemoryProtection")
                })
                .expect("memory protection index");
            meta.children.insert(
                memory_protection_index,
                XMLNode::Element(
                    parse_xml_fragment("<UnknownMetaNode><Value>Alpha</Value></UnknownMetaNode>")
                        .expect("unknown meta node"),
                ),
            );

            let group = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .expect("group");
            let tags_index = group
                .children
                .iter()
                .position(
                    |child| matches!(child, XMLNode::Element(element) if element.name == "Tags"),
                )
                .expect("group tags index");
            group.children.insert(
                tags_index,
                XMLNode::Element(
                    parse_xml_fragment("<UnknownGroupNode><Value>Beta</Value></UnknownGroupNode>")
                        .expect("unknown group node"),
                ),
            );

            let entry = group.get_mut_child("Entry").expect("entry");
            let custom_data_index = entry
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "CustomData")
                })
                .expect("entry custom data index");
            entry.children.insert(
                custom_data_index,
                XMLNode::Element(
                    parse_xml_fragment("<UnknownEntryNode><Value>Gamma</Value></UnknownEntryNode>")
                        .expect("unknown entry node"),
                ),
            );
        })
        .expect("rewrite xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse rewritten xml");

        let meta = parsed.get_child("Meta").expect("meta");
        assert_in_order(
            child_element_names(meta),
            &["DatabaseName", "UnknownMetaNode", "MemoryProtection"],
        );

        let group = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("group");
        assert_in_order(
            child_element_names(group),
            &["Notes", "UnknownGroupNode", "Tags"],
        );

        let entry = group.get_child("Entry").expect("entry");
        assert_in_order(
            child_element_names(entry),
            &["Tags", "UnknownEntryNode", "CustomData"],
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_root_opaque_xml_order_relative_to_known_nodes() {
        let mut vault = Vault::empty("RootOpaqueOrder");
        vault.root.title = "Root".into();
        vault.deleted_objects.push(vaultkern_model::DeletedObject {
            id: uuid::Uuid::new_v4(),
            deleted_at: 1_700_000_000,
        });

        let mut key = CompositeKey::default();
        key.add_password("root-opaque-order");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let root_node = root.get_mut_child("Root").expect("root node");
            let deleted_objects_index = root_node
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "DeletedObjects")
                })
                .expect("deleted objects index");
            root_node.children.insert(
                deleted_objects_index,
                XMLNode::Element(
                    parse_xml_fragment("<UnknownRootNode><Value>Omega</Value></UnknownRootNode>")
                        .expect("unknown root node"),
                ),
            );
        })
        .expect("rewrite root xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse rewritten xml");

        let root_node = parsed.get_child("Root").expect("root node");
        assert_in_order(
            child_element_names(root_node),
            &["Group", "UnknownRootNode", "DeletedObjects"],
        );
    }

    #[test]
    fn kdbx4_roundtrip_writes_root_group_first_for_keepassxc_compatibility() {
        let mut vault = Vault::empty("RootMixedOrder");
        vault.root.title = "Root".into();
        vault.deleted_objects.push(vaultkern_model::DeletedObject {
            id: uuid::Uuid::new_v4(),
            deleted_at: 1_700_000_000,
        });

        let mut key = CompositeKey::default();
        key.add_password("root-mixed-order");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let root_node = root.get_mut_child("Root").expect("root node");
            let deleted_objects_index = root_node
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "DeletedObjects")
                })
                .expect("deleted objects index");
            let deleted_objects = root_node.children.remove(deleted_objects_index);
            let group_index = root_node
                .children
                .iter()
                .position(
                    |child| matches!(child, XMLNode::Element(element) if element.name == "Group"),
                )
                .expect("group index");
            let group = root_node.children.remove(group_index);

            root_node.children.insert(0, deleted_objects);
            root_node.children.insert(
                1,
                XMLNode::Element(
                    parse_xml_fragment("<UnknownRootMixed><Value>Omega</Value></UnknownRootMixed>")
                        .expect("unknown root mixed node"),
                ),
            );
            root_node.children.insert(2, group);
        })
        .expect("rewrite root xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse rewritten xml");

        let root_node = parsed.get_child("Root").expect("root node");
        assert_eq!(
            child_element_names(root_node).first().copied(),
            Some("Group")
        );
        assert_in_order(
            child_element_names(root_node),
            &["Group", "DeletedObjects", "UnknownRootMixed"],
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_mixed_group_node_order() {
        let mut vault = Vault::empty("GroupMixedOrder");
        vault.root.title = "Root".into();
        vault.root.notes = "Root notes".into();
        vault.root.tags.insert("root-tag".into());
        vault.root.previous_parent = Some(uuid::Uuid::new_v4());
        vault.root.custom_data.insert("group-a".into(), "1".into());
        vault.root.custom_data.insert("group-b".into(), "2".into());

        let mut key = CompositeKey::default();
        key.add_password("group-mixed-order");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let group = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .expect("group");
            let tags_index = group
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "Tags"))
                .expect("tags index");
            let tags = group.children.remove(tags_index);
            let custom_data_index = group
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "CustomData")
                })
                .expect("custom data index");
            let custom_data = group.children.remove(custom_data_index);
            let notes_index = group
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "Notes"))
                .expect("notes index");
            let notes = group.children.remove(notes_index);
            let previous_parent_index = group
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "PreviousParentGroup")
                })
                .expect("previous parent index");
            let previous_parent = group.children.remove(previous_parent_index);

            group.children.insert(2, tags);
            group.children.insert(3, custom_data);
            group.children.insert(
                4,
                XMLNode::Element(
                    parse_xml_fragment(
                        "<UnknownGroupMixed><Value>Omega</Value></UnknownGroupMixed>",
                    )
                    .expect("unknown group mixed node"),
                ),
            );
            group.children.insert(5, notes);
            group.children.insert(6, previous_parent);
        })
        .expect("rewrite group xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse rewritten xml");

        let group = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("group");
        assert_in_order(
            child_element_names(group),
            &[
                "Tags",
                "CustomData",
                "UnknownGroupMixed",
                "Notes",
                "PreviousParentGroup",
            ],
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_mixed_entry_node_order() {
        let mut vault = Vault::empty("EntryMixedOrder");
        vault.root.title = "Root".into();

        let mut entry = Entry::new("Entry");
        entry.tags.insert("entry-tag".into());
        entry.previous_parent = Some(uuid::Uuid::new_v4());
        entry.custom_data.insert("entry-a".into(), "1".into());
        entry.auto_type = Some(vaultkern_model::AutoTypeConfig {
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into()),
            ..Default::default()
        });
        entry.history.push(Entry::new("Old"));
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("entry-mixed-order");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .and_then(|group| group.get_mut_child("Entry"))
                .expect("entry");
            let tags_index = entry
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "Tags"))
                .expect("tags index");
            let tags = entry.children.remove(tags_index);
            let previous_parent_index = entry
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "PreviousParentGroup")
                })
                .expect("previous parent index");
            let previous_parent = entry.children.remove(previous_parent_index);
            let custom_data_index = entry
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "CustomData")
                })
                .expect("custom data index");
            let custom_data = entry.children.remove(custom_data_index);
            let times_index = entry
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "Times"))
                .expect("times index");
            let times = entry.children.remove(times_index);
            let auto_type_index = entry
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "AutoType"))
                .expect("auto type index");
            let auto_type = entry.children.remove(auto_type_index);
            let history_index = entry
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "History"))
                .expect("history index");
            let history = entry.children.remove(history_index);

            entry.children.insert(1, previous_parent);
            entry.children.insert(2, custom_data);
            entry.children.insert(
                3,
                XMLNode::Element(
                    parse_xml_fragment(
                        "<UnknownEntryMixed><Value>Omega</Value></UnknownEntryMixed>",
                    )
                    .expect("unknown entry mixed node"),
                ),
            );
            entry.children.insert(4, tags);
            entry.children.insert(5, times);
            entry.children.insert(6, auto_type);
            entry.children.insert(7, history);
        })
        .expect("rewrite entry xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse rewritten xml");

        let entry = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("entry");
        assert_in_order(
            child_element_names(entry),
            &[
                "PreviousParentGroup",
                "CustomData",
                "UnknownEntryMixed",
                "Tags",
                "Times",
                "AutoType",
                "History",
            ],
        );
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_entry_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("extract original xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_entry = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("original entry");
        let original_order = entry_child_descriptors(original_entry);

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("load browser fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_entry = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("rewritten entry");
        let rewritten_order = entry_child_descriptors(rewritten_entry);

        assert_eq!(rewritten_order, original_order);
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_history_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("extract original xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_entry = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("original entry");
        let original_matrix = history_entry_child_matrix(original_entry, "root".into());

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("load browser fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_entry = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("rewritten entry");
        let rewritten_matrix = history_entry_child_matrix(rewritten_entry, "root".into());

        assert_eq!(rewritten_matrix, original_matrix);
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_history_entry_child_order_matrix_for_group_tree() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("extract original xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original group");
        let original_matrix = collect_group_history_entry_matrix(original_group, String::new());

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("load browser fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten group");
        let rewritten_matrix = collect_group_history_entry_matrix(rewritten_group, String::new());

        assert_eq!(rewritten_matrix, original_matrix);
    }

    #[test]
    fn kdbx4_save_omits_nested_history_nodes_from_history_entries() {
        let mut vault = Vault::empty("HistoryCompat");
        let mut entry = Entry::new("Live");
        entry.created_at = 1;
        entry.modified_at = 3;

        let mut snapshot = entry.clone();
        snapshot.modified_at = 2;
        snapshot.raw_state.has_history_node = true;
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("history-compat");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let xml = extract_kdbx4_xml(&bytes, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse xml");
        let history_entry = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .and_then(|entry| entry.get_child("History"))
            .and_then(|history| history.get_child("Entry"))
            .expect("history entry");

        assert!(history_entry.get_child("History").is_none());
    }

    #[test]
    fn format400_fixture_roundtrip_preserves_entry_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("t");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_FORMAT400, &key).expect("extract original xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_entry = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("original entry");
        let original_order = entry_child_descriptors(original_entry);

        let loaded = load_kdbx(FIXTURE_FORMAT400, &key).expect("load format400 fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save format400 fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten format400 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten format400 xml");
        let rewritten_entry = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("rewritten entry");
        let rewritten_order = entry_child_descriptors(rewritten_entry);

        assert_eq!(rewritten_order, original_order);
    }

    #[test]
    fn kdbx4_save_writes_all_entry_times_as_binary_datetime_values() {
        let mut key = CompositeKey::default();
        key.add_password("t");

        let loaded = load_kdbx(FIXTURE_FORMAT400, &key).expect("load format400 fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save format400 fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten format400 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten format400 xml");
        let mut entries = Vec::new();
        collect_entry_elements(&rewritten_parsed, &mut entries);
        assert!(!entries.is_empty());

        for entry in entries {
            let times = entry.get_child("Times").expect("entry times");
            let modified_at =
                child_text(times, "LastModificationTime").expect("entry last modification time");

            assert!(
                is_kdbx4_binary_datetime(&modified_at),
                "expected KDBX4 binary datetime, got {modified_at}"
            );
        }
    }

    #[test]
    fn kdbx3_datetime_text_uses_iso_utc_format() {
        assert_eq!(
            super::datetime_text(KdbxVersion::V3_1, 0_i64),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            super::datetime_text(KdbxVersion::V3_1, 1_700_000_000_i64),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn kdbx4_0_save_omits_4_1_only_xml_fields() {
        let mut vault = Vault::empty("VersionGates");
        vault.custom_icons.push(vaultkern_model::CustomIcon {
            id: uuid::Uuid::nil(),
            data: vec![1, 2, 3],
            name: Some("Named Icon".into()),
            last_modified: Some(1_700_000_005),
        });
        vault.meta_custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "meta-key".into(),
                value: "meta-value".into(),
                last_modified: Some(1_700_000_006),
            }],
            after: None,
        });
        vault.root.previous_parent = Some(uuid::Uuid::nil());
        vault.root.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "group-key".into(),
                value: "group-value".into(),
                last_modified: Some(1_700_000_007),
            }],
            after: None,
        });

        let mut entry = Entry::new("Entry");
        entry.previous_parent = Some(uuid::Uuid::nil());
        entry.exclude_from_reports = true;
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "entry-key".into(),
                value: "entry-value".into(),
                last_modified: Some(1_700_000_008),
            }],
            after: None,
        });
        vault.root.entries.push(entry);

        let parsed = generated_xml(&vault, KdbxVersion::V4_0);
        let meta = parsed.get_child("Meta").expect("meta");
        let icon = meta
            .get_child("CustomIcons")
            .and_then(|icons| icons.get_child("Icon"))
            .expect("custom icon");
        assert!(icon.get_child("Name").is_none());
        assert!(icon.get_child("LastModificationTime").is_none());
        assert_custom_data_items_omit_last_modified(meta);

        let group = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("group");
        assert!(group.get_child("PreviousParentGroup").is_none());
        assert_custom_data_items_omit_last_modified(group);

        let entry = group.get_child("Entry").expect("entry");
        assert!(entry.get_child("PreviousParentGroup").is_none());
        assert!(entry.get_child("QualityCheck").is_none());
        assert_custom_data_items_omit_last_modified(entry);
    }

    #[test]
    fn kdbx3_save_omits_kdbx4_xml_only_custom_data() {
        let mut vault = Vault::empty("LegacyNoCustomData");
        vault
            .meta_custom_data
            .insert("meta-key".into(), "meta-value".into());
        vault
            .root
            .custom_data
            .insert("group-key".into(), "group-value".into());
        let mut entry = Entry::new("Entry");
        entry
            .custom_data
            .insert("entry-key".into(), "entry-value".into());
        vault.root.entries.push(entry);

        let parsed = generated_xml(&vault, KdbxVersion::V3_1);
        let meta = parsed.get_child("Meta").expect("meta");
        assert!(meta.get_child("CustomData").is_none());

        let group = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("group");
        assert!(group.get_child("CustomData").is_none());
        let entry = group.get_child("Entry").expect("entry");
        assert!(entry.get_child("CustomData").is_none());
    }

    #[test]
    fn kdbx4_new_save_writes_keepassxc_structural_default_nodes() {
        let mut vault = Vault::empty("Defaults");
        vault.root.entries.push(Entry::new("Entry"));

        let parsed = generated_xml(&vault, KdbxVersion::V4_1);
        let root_node = parsed.get_child("Root").expect("root");
        assert!(root_node.get_child("DeletedObjects").is_some());

        let group = root_node.get_child("Group").expect("group");
        assert_eq!(child_text(group, "IconID").as_deref(), Some("0"));
        assert!(group.get_child("Times").is_some());
        assert!(group.get_child("IsExpanded").is_some());
        assert!(group.get_child("DefaultAutoTypeSequence").is_some());
        assert_eq!(child_text(group, "EnableAutoType").as_deref(), Some("null"));
        assert_eq!(
            child_text(group, "EnableSearching").as_deref(),
            Some("null")
        );
        assert_eq!(
            child_text(group, "LastTopVisibleEntry").as_deref(),
            Some("AAAAAAAAAAAAAAAAAAAAAA==")
        );

        let entry = group.get_child("Entry").expect("entry");
        assert_eq!(child_text(entry, "IconID").as_deref(), Some("0"));
        assert!(entry.get_child("AutoType").is_some());
        assert!(entry.get_child("History").is_some());
    }

    #[test]
    fn kdbx4_times_use_keepassxc_child_order() {
        let mut vault = Vault::empty("TimeOrder");
        vault.root.times = Some(vaultkern_model::GroupTimes {
            created_at: 1,
            modified_at: 2,
            last_accessed_at: Some(3),
            expiry_time: Some(4),
            expires: true,
            usage_count: Some(5),
            location_changed_at: Some(6),
        });
        let mut entry = Entry::new("Entry");
        entry.created_at = 1;
        entry.modified_at = 2;
        entry.last_accessed_at = Some(3);
        entry.expiry_time = Some(4);
        entry.expires = true;
        entry.usage_count = Some(5);
        entry.location_changed_at = Some(6);
        vault.root.entries.push(entry);

        let parsed = generated_xml(&vault, KdbxVersion::V4_1);
        let group_times = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Times"))
            .expect("group times");
        assert_eq!(
            child_element_names(group_times),
            vec![
                "LastModificationTime",
                "CreationTime",
                "LastAccessTime",
                "ExpiryTime",
                "Expires",
                "UsageCount",
                "LocationChanged"
            ]
        );

        let entry_times = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .and_then(|entry| entry.get_child("Times"))
            .expect("entry times");
        assert_eq!(
            child_element_names(entry_times),
            child_element_names(group_times)
        );
    }

    #[test]
    fn kdbx4_1_custom_icon_uses_keepassxc_child_order() {
        let mut vault = Vault::empty("IconOrder");
        vault.custom_icons.push(vaultkern_model::CustomIcon {
            id: uuid::Uuid::nil(),
            data: vec![1, 2, 3],
            name: Some("Named Icon".into()),
            last_modified: Some(1_700_000_005),
        });

        let parsed = generated_xml(&vault, KdbxVersion::V4_1);
        let icon = parsed
            .get_child("Meta")
            .and_then(|meta| meta.get_child("CustomIcons"))
            .and_then(|icons| icons.get_child("Icon"))
            .expect("custom icon");

        assert_eq!(
            child_element_names(icon),
            vec!["UUID", "Name", "LastModificationTime", "Data"]
        );
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_group_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("extract original xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original group");
        let original_order = child_element_names(original_group);

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("load browser fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten group");
        let rewritten_order = child_element_names(rewritten_group);

        assert_eq!(rewritten_order, original_order);
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_group_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("extract original xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original group");
        let original_orders = collect_group_child_order_matrix(original_group, String::new());

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("load browser fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten group");
        let rewritten_orders = collect_group_child_order_matrix(rewritten_group, String::new());

        assert_eq!(rewritten_orders, original_orders);
    }

    #[test]
    fn format400_fixture_roundtrip_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("t");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_FORMAT400, &key).expect("extract original xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed.get_child("Root").expect("original root");
        let original_order = child_element_names(original_root);

        let loaded = load_kdbx(FIXTURE_FORMAT400, &key).expect("load format400 fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save format400 fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten format400 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten format400 xml");
        let rewritten_root = rewritten_parsed.get_child("Root").expect("rewritten root");
        let rewritten_order = child_element_names(rewritten_root);

        assert_eq!(rewritten_order, original_order);
    }

    #[test]
    fn kdbx4_roundtrip_merges_multiple_custom_data_nodes_across_layers() {
        let mut vault = Vault::empty("CustomDataMatrix");
        vault.meta_custom_data.insert("meta-a".into(), "A".into());
        vault
            .public_custom_data
            .insert("client".into(), b"web".to_vec());

        let mut group = Group::new("Nested");
        group.custom_data.insert("group-a".into(), "A".into());

        let mut entry = Entry::new("Entry");
        entry.custom_data.insert("entry-a".into(), "A".into());
        group.entries.push(entry);
        vault.root.children.push(group);

        let mut key = CompositeKey::default();
        key.add_password("custom-data-matrix");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            meta.children.push(XMLNode::Element(
                parse_xml_fragment(
                    "<CustomData><Item><Key>meta-b</Key><Value>B</Value></Item></CustomData>",
                )
                .expect("meta custom data"),
            ));

            let group = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .and_then(|root_group| root_group.get_mut_child("Group"))
                .expect("nested group");
            group.children.push(XMLNode::Element(
                parse_xml_fragment(
                    "<CustomData><Item><Key>group-b</Key><Value>B</Value></Item></CustomData>",
                )
                .expect("group custom data"),
            ));

            let entry = group.get_mut_child("Entry").expect("entry");
            entry.children.push(XMLNode::Element(
                parse_xml_fragment(
                    "<CustomData><Item><Key>entry-b</Key><Value>B</Value></Item></CustomData>",
                )
                .expect("entry custom data"),
            ));
        })
        .expect("rewrite xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        assert_eq!(
            loaded.meta_custom_data.get("meta-a").map(String::as_str),
            Some("A")
        );
        assert_eq!(
            loaded.meta_custom_data.get("meta-b").map(String::as_str),
            Some("B")
        );
        assert_eq!(
            loaded.public_custom_data.get("client"),
            Some(&b"web".to_vec())
        );

        let nested = loaded.root.children.first().expect("nested group");
        assert_eq!(
            nested.custom_data.get("group-a").map(String::as_str),
            Some("A")
        );
        assert_eq!(
            nested.custom_data.get("group-b").map(String::as_str),
            Some("B")
        );

        let entry = nested.entries.first().expect("entry");
        assert_eq!(
            entry.custom_data.get("entry-a").map(String::as_str),
            Some("A")
        );
        assert_eq!(
            entry.custom_data.get("entry-b").map(String::as_str),
            Some("B")
        );

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let reloaded = load_kdbx(&rewritten, &key).expect("reload rewritten kdbx");
        assert_eq!(reloaded.meta_custom_data, loaded.meta_custom_data);
        assert_eq!(reloaded.public_custom_data, loaded.public_custom_data);
        assert_eq!(reloaded.root.children[0].custom_data, nested.custom_data);
        assert_eq!(
            reloaded.root.children[0].entries[0].custom_data,
            entry.custom_data
        );
    }

    #[test]
    fn kdbx4_custom_data_duplicate_keys_use_last_write_wins_across_layers() {
        let mut vault = Vault::empty("CustomDataDup");
        let mut group = Group::new("Nested");
        group.entries.push(Entry::new("Entry"));
        vault.root.children.push(group);

        let mut key = CompositeKey::default();
        key.add_password("custom-data-dup");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated =
            rewrite_kdbx4_xml(&bytes, &key, |root| {
                let meta = root.get_mut_child("Meta").expect("meta");
                meta.children.push(XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData>\
                    <Item><Key>dup</Key><Value>meta-1</Value></Item>\
                    <Item><Key>dup</Key><Value>meta-2</Value></Item>\
                </CustomData>",
                    )
                    .expect("meta custom data"),
                ));
                meta.children.push(XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData><Item><Key>dup</Key><Value>meta-3</Value></Item></CustomData>",
                    )
                    .expect("meta custom data second"),
                ));

                let group = root
                    .get_mut_child("Root")
                    .and_then(|root| root.get_mut_child("Group"))
                    .and_then(|group| group.get_mut_child("Group"))
                    .expect("nested group");
                group.children.push(XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData>\
                    <Item><Key>dup</Key><Value>group-1</Value></Item>\
                    <Item><Key>dup</Key><Value>group-2</Value></Item>\
                </CustomData>",
                    )
                    .expect("group custom data"),
                ));
                group.children.push(XMLNode::Element(parse_xml_fragment(
                "<CustomData><Item><Key>dup</Key><Value>group-3</Value></Item></CustomData>",
            )
            .expect("group custom data second")));

                let entry = group.get_mut_child("Entry").expect("entry");
                entry.children.push(XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData>\
                    <Item><Key>dup</Key><Value>entry-1</Value></Item>\
                    <Item><Key>dup</Key><Value>entry-2</Value></Item>\
                </CustomData>",
                    )
                    .expect("entry custom data"),
                ));
                entry.children.push(XMLNode::Element(parse_xml_fragment(
                "<CustomData><Item><Key>dup</Key><Value>entry-3</Value></Item></CustomData>",
            )
            .expect("entry custom data second")));
            })
            .expect("rewrite xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        assert_eq!(
            loaded.meta_custom_data.get("dup").map(String::as_str),
            Some("meta-3")
        );
        assert_eq!(
            loaded.root.children[0]
                .custom_data
                .get("dup")
                .map(String::as_str),
            Some("group-3")
        );
        assert_eq!(
            loaded.root.children[0].entries[0]
                .custom_data
                .get("dup")
                .map(String::as_str),
            Some("entry-3")
        );

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let reloaded = load_kdbx(&rewritten, &key).expect("reload rewritten kdbx");
        assert_eq!(reloaded.meta_custom_data, loaded.meta_custom_data);
        assert_eq!(
            reloaded.root.children[0].custom_data,
            loaded.root.children[0].custom_data
        );
        assert_eq!(
            reloaded.root.children[0].entries[0].custom_data,
            loaded.root.children[0].entries[0].custom_data
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_group_custom_data_item_last_modified() {
        let mut vault = Vault::empty("GroupCustomDataTimes");
        let mut group = Group::new("Nested");
        group
            .custom_data
            .insert("group-key".into(), "group-value".into());
        group.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "group-key".into(),
                value: "group-value".into(),
                last_modified: Some(1_700_000_111),
            }],
            after: None,
        });
        vault.root.children.push(group);

        let mut key = CompositeKey::default();
        key.add_password("group-custom-data-times");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let loaded = load_kdbx(&bytes, &key).expect("load kdbx");
        let nested = loaded.root.children.first().expect("nested group");
        assert_eq!(
            nested.custom_data_blocks,
            vec![CustomDataBlock {
                items: vec![CustomDataItem {
                    key: "group-key".into(),
                    value: "group-value".into(),
                    last_modified: Some(1_700_000_111),
                }],
                after: None,
            }]
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_entry_custom_data_item_last_modified() {
        let mut vault = Vault::empty("EntryCustomDataTimes");
        let mut group = Group::new("Nested");
        let mut entry = Entry::new("Entry");
        entry
            .custom_data
            .insert("entry-key".into(), "entry-value".into());
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "entry-key".into(),
                value: "entry-value".into(),
                last_modified: Some(1_700_000_222),
            }],
            after: None,
        });
        group.entries.push(entry);
        vault.root.children.push(group);

        let mut key = CompositeKey::default();
        key.add_password("entry-custom-data-times");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let loaded = load_kdbx(&bytes, &key).expect("load kdbx");
        let nested = loaded.root.children.first().expect("nested group");
        let entry = nested.entries.first().expect("entry");
        assert_eq!(
            entry.custom_data_blocks,
            vec![CustomDataBlock {
                items: vec![CustomDataItem {
                    key: "entry-key".into(),
                    value: "entry-value".into(),
                    last_modified: Some(1_700_000_222),
                }],
                after: None,
            }]
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_custom_data_block_boundaries_across_layers() {
        let mut vault = Vault::empty("CustomDataBlocks");
        vault.default_username = Some("meta-user".into());
        vault.history_max_items = Some(10);
        vault.root.notes = "root notes".into();
        vault.root.tags.insert("root-tag".into());
        vault.root.previous_parent = Some(uuid::Uuid::new_v4());

        let mut entry = Entry::new("Entry");
        entry.tags.insert("entry-tag".into());
        entry.auto_type = Some(vaultkern_model::AutoTypeConfig {
            enabled: Some(true),
            obfuscation: Some(0),
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}".into()),
            associations: Vec::new(),
        });
        entry.history.push(Entry::new("History"));
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("custom-data-blocks");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            let default_user_index = meta
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "DefaultUserName")
                })
                .expect("default username index");
            meta.children.insert(
                default_user_index,
                XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData><Item><Key>meta-a</Key><Value>1</Value></Item></CustomData>",
                    )
                    .expect("meta block 1"),
                ),
            );
            let history_max_items_index = meta
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "HistoryMaxItems")
                })
                .expect("history max items index");
            meta.children.insert(
                history_max_items_index,
                XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData>\
                            <Item><Key>meta-b</Key><Value>2</Value></Item>\
                            <Item><Key>dup</Key><Value>meta-last</Value></Item>\
                        </CustomData>",
                    )
                    .expect("meta block 2"),
                ),
            );

            let group = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .expect("group");
            let tags_index = group
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "Tags"))
                .expect("group tags index");
            group.children.insert(
                tags_index,
                XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData><Item><Key>group-a</Key><Value>1</Value></Item></CustomData>",
                    )
                    .expect("group block 1"),
                ),
            );
            let previous_parent_index = group
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "PreviousParentGroup")
                })
                .expect("group previous parent index");
            group.children.insert(
                previous_parent_index,
                XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData>\
                            <Item><Key>group-b</Key><Value>2</Value></Item>\
                            <Item><Key>dup</Key><Value>group-last</Value></Item>\
                        </CustomData>",
                    )
                    .expect("group block 2"),
                ),
            );

            let entry = group.get_mut_child("Entry").expect("entry");
            let auto_type_index = entry
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "AutoType"))
                .expect("entry auto type index");
            entry.children.insert(
                auto_type_index,
                XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData><Item><Key>entry-a</Key><Value>1</Value></Item></CustomData>",
                    )
                    .expect("entry block 1"),
                ),
            );
            let history_index = entry
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "History"))
                .expect("entry history index");
            entry.children.insert(
                history_index,
                XMLNode::Element(
                    parse_xml_fragment(
                        "<CustomData>\
                            <Item><Key>entry-b</Key><Value>2</Value></Item>\
                            <Item><Key>dup</Key><Value>entry-last</Value></Item>\
                        </CustomData>",
                    )
                    .expect("entry block 2"),
                ),
            );
        })
        .expect("rewrite xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        assert_eq!(
            loaded.meta_custom_data.get("dup").map(String::as_str),
            Some("meta-last")
        );
        assert_eq!(
            loaded.root.custom_data.get("dup").map(String::as_str),
            Some("group-last")
        );
        assert_eq!(
            loaded.root.entries[0]
                .custom_data
                .get("dup")
                .map(String::as_str),
            Some("entry-last")
        );

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse rewritten xml");

        let meta = parsed.get_child("Meta").expect("meta");
        assert_in_order(
            child_element_names(meta),
            &[
                "DatabaseName",
                "CustomData",
                "DefaultUserName",
                "CustomData",
                "HistoryMaxItems",
            ],
        );
        assert_eq!(
            custom_data_blocks(meta),
            vec![
                vec![("meta-a".into(), "1".into())],
                vec![
                    ("meta-b".into(), "2".into()),
                    ("dup".into(), "meta-last".into()),
                ],
            ]
        );

        let group = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("group");
        assert_in_order(
            child_element_names(group),
            &[
                "Notes",
                "CustomData",
                "Tags",
                "CustomData",
                "PreviousParentGroup",
            ],
        );
        assert_eq!(
            custom_data_blocks(group),
            vec![
                vec![("group-a".into(), "1".into())],
                vec![
                    ("group-b".into(), "2".into()),
                    ("dup".into(), "group-last".into()),
                ],
            ]
        );

        let entry = group.get_child("Entry").expect("entry");
        assert_in_order(
            child_element_names(entry),
            &["Tags", "CustomData", "AutoType", "CustomData", "History"],
        );
        assert_eq!(
            custom_data_blocks(entry),
            vec![
                vec![("entry-a".into(), "1".into())],
                vec![
                    ("entry-b".into(), "2".into()),
                    ("dup".into(), "entry-last".into()),
                ],
            ]
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_meta_custom_data_item_last_modification_time() {
        let mut vault = Vault::empty("MetaCustomDataTimes");
        vault.meta_custom_data.insert("meta-a".into(), "1".into());
        vault.meta_custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "meta-a".into(),
                value: "1".into(),
                last_modified: Some(1_700_000_006),
            }],
            after: None,
        });

        let mut key = CompositeKey::default();
        key.add_password("meta-custom-data-times");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let loaded = load_kdbx(&bytes, &key).expect("reload kdbx");

        assert_eq!(loaded.meta_custom_data_blocks.len(), 1);
        assert_eq!(loaded.meta_custom_data_blocks[0].items.len(), 1);
        assert_eq!(
            loaded.meta_custom_data_blocks[0].items[0].last_modified,
            Some(1_700_000_006)
        );

        let xml = extract_kdbx4_xml(&bytes, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse xml");
        let item = parsed
            .get_child("Meta")
            .and_then(|meta| meta.get_child("CustomData"))
            .and_then(|custom_data| custom_data.get_child("Item"))
            .expect("custom data item");
        assert_datetime_text(item, "LastModificationTime", 1_700_000_006, true);
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_split_custom_data_blocks() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let mutated = rewrite_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            split_first_custom_data_block(meta);

            let entry = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .and_then(|group| group.get_mut_child("Entry"))
                .expect("root entry");
            split_first_custom_data_block(entry);
        })
        .expect("rewrite browser fixture");

        let mutated_xml = extract_kdbx4_xml(&mutated, &key).expect("extract mutated xml");
        let mutated_parsed = Element::parse(mutated_xml.as_bytes()).expect("parse mutated xml");
        let mutated_meta = mutated_parsed.get_child("Meta").expect("mutated meta");
        let mutated_entry = mutated_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("mutated root entry");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated browser fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten fixture");
        let rewritten_xml = extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten xml");
        let rewritten_meta = rewritten_parsed.get_child("Meta").expect("rewritten meta");
        let rewritten_entry = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("rewritten root entry");

        assert_eq!(
            custom_data_blocks(rewritten_meta),
            custom_data_blocks(mutated_meta)
        );
        assert_eq!(
            custom_data_blocks(rewritten_entry),
            custom_data_blocks(mutated_entry)
        );
        assert_custom_data_cluster_context(mutated_meta, rewritten_meta);
        assert_custom_data_cluster_context(mutated_entry, rewritten_entry);
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_meta_custom_data_item_last_modification_time() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let mutated = rewrite_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key, |root| {
            let item = root
                .get_mut_child("Meta")
                .and_then(|meta| meta.get_mut_child("CustomData"))
                .and_then(|custom_data| custom_data.get_mut_child("Item"))
                .expect("meta custom data item");
            let value_index = item
                .children
                .iter()
                .position(
                    |child| matches!(child, XMLNode::Element(element) if element.name == "Value"),
                )
                .expect("value index");
            item.children.insert(
                value_index + 1,
                XMLNode::Element(text_element("LastModificationTime", "1700000006")),
            );
        })
        .expect("rewrite browser fixture");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated browser fixture");
        assert_eq!(
            loaded.meta_custom_data_blocks[0].items[0].last_modified,
            Some(1_700_000_006)
        );

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten fixture");
        let rewritten_xml = extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten xml");
        let rewritten_item = rewritten_parsed
            .get_child("Meta")
            .and_then(|meta| meta.get_child("CustomData"))
            .and_then(|custom_data| custom_data.get_child("Item"))
            .expect("rewritten custom data item");

        assert_datetime_text(rewritten_item, "LastModificationTime", 1_700_000_006, true);
    }

    #[test]
    fn mutated_custom_data_maps_fall_back_to_canonical_single_block_output() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let mutated = rewrite_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            split_first_custom_data_block(meta);

            let entry = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .and_then(|group| group.get_mut_child("Entry"))
                .expect("root entry");
            split_first_custom_data_block(entry);
        })
        .expect("rewrite browser fixture");

        let mut loaded = load_kdbx(&mutated, &key).expect("load mutated browser fixture");
        loaded
            .meta_custom_data
            .insert("KeePassXC-Browser Settings".into(), "mutated-meta".into());
        loaded.root.entries[0]
            .custom_data
            .insert("KPH: {USERNAME}".into(), "mutated-entry".into());

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save mutated model");
        let rewritten_xml = extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten xml");
        let rewritten_meta = rewritten_parsed.get_child("Meta").expect("rewritten meta");
        let rewritten_entry = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("rewritten root entry");

        assert_eq!(custom_data_blocks(rewritten_meta).len(), 1);
        assert_eq!(
            custom_data_blocks(rewritten_meta)[0]
                .iter()
                .find(|(key, _)| key == "KeePassXC-Browser Settings")
                .map(|(_, value)| value.as_str()),
            Some("mutated-meta")
        );
        assert_eq!(custom_data_blocks(rewritten_entry).len(), 1);
        assert_eq!(
            custom_data_blocks(rewritten_entry)[0]
                .iter()
                .find(|(key, _)| key == "KPH: {USERNAME}")
                .map(|(_, value)| value.as_str()),
            Some("mutated-entry")
        );
    }

    #[test]
    fn deleting_custom_data_item_with_empty_split_block_falls_back_to_canonical_output() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let mutated = rewrite_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            split_first_custom_data_block(meta);
        })
        .expect("rewrite browser fixture");

        let mut loaded = load_kdbx(&mutated, &key).expect("load mutated browser fixture");
        loaded.meta_custom_data.remove("_LAST_MODIFIED");
        for block in &mut loaded.meta_custom_data_blocks {
            block.items.retain(|item| item.key != "_LAST_MODIFIED");
        }

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save mutated model");
        let rewritten_xml = extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten xml");
        let rewritten_meta = rewritten_parsed.get_child("Meta").expect("rewritten meta");

        assert_eq!(custom_data_blocks(rewritten_meta).len(), 1);
        assert_eq!(
            custom_data_blocks(rewritten_meta)[0]
                .iter()
                .find(|(key, _)| key == "KPXC_BROWSER_test")
                .map(|(_, value)| value.as_str())
                .is_some(),
            true
        );
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_empty_meta_nodes() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("extract original xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_meta = original_parsed.get_child("Meta").expect("original meta");

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("load browser fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_meta = rewritten_parsed.get_child("Meta").expect("rewritten meta");

        let original_description = meta_child_text_or_empty(original_meta, "DatabaseDescription");
        let original_default_username = meta_child_text_or_empty(original_meta, "DefaultUserName");
        let original_color = meta_child_text_or_empty(original_meta, "Color");
        let original_recycle_bin_uuid = meta_child_text_or_empty(original_meta, "RecycleBinUUID");
        let original_entry_templates_group =
            meta_child_text_or_empty(original_meta, "EntryTemplatesGroup");

        assert_eq!(original_description, Some(String::new()));
        assert_eq!(original_default_username, Some(String::new()));
        assert_eq!(original_color, Some(String::new()));
        assert!(original_meta.get_child("CustomIcons").is_some());
        assert!(original_recycle_bin_uuid.is_some());
        assert!(original_entry_templates_group.is_some());

        assert_eq!(
            meta_child_text_or_empty(rewritten_meta, "DatabaseDescription"),
            original_description
        );
        assert_eq!(
            meta_child_text_or_empty(rewritten_meta, "DefaultUserName"),
            original_default_username
        );
        assert_eq!(
            meta_child_text_or_empty(rewritten_meta, "Color"),
            original_color
        );
        assert!(rewritten_meta.get_child("CustomIcons").is_some());
        assert_eq!(
            meta_child_text_or_empty(rewritten_meta, "RecycleBinUUID"),
            original_recycle_bin_uuid
        );
        assert_eq!(
            meta_child_text_or_empty(rewritten_meta, "EntryTemplatesGroup"),
            original_entry_templates_group
        );
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_known_meta_node_order() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("extract original xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_meta = original_parsed.get_child("Meta").expect("original meta");
        assert_in_order(
            child_element_names(original_meta),
            &[
                "Color",
                "MasterKeyChanged",
                "MemoryProtection",
                "CustomIcons",
            ],
        );

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("load browser fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_meta = rewritten_parsed.get_child("Meta").expect("rewritten meta");

        assert_in_order(
            child_element_names(rewritten_meta),
            &[
                "Color",
                "MasterKeyChanged",
                "MemoryProtection",
                "CustomIcons",
            ],
        );
    }

    #[test]
    fn format400_fixture_roundtrip_preserves_meta_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("t");

        let original_xml =
            extract_kdbx4_xml(FIXTURE_FORMAT400, &key).expect("extract original format400 xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_meta = original_parsed.get_child("Meta").expect("original meta");

        let loaded = load_kdbx(FIXTURE_FORMAT400, &key).expect("load format400 fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save format400 fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten format400 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten format400 xml");
        let rewritten_meta = rewritten_parsed.get_child("Meta").expect("rewritten meta");
        let expected_order = child_element_names(original_meta);

        assert_in_order(child_element_names(rewritten_meta), &expected_order);
    }

    #[test]
    fn multi_fixture_roundtrip_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx_xml(FIXTURE_NEW_DATABASE_MULTI, &key).expect("extract original multi xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_MULTI, &key).expect("load multi fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save multi fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten multi xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten multi xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn multi_fixture_roundtrip_preserves_group_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx_xml(FIXTURE_NEW_DATABASE_MULTI, &key).expect("extract original multi xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_MULTI, &key).expect("load multi fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save multi fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten multi xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten multi xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_child_order_matrix(rewritten_group, String::new()),
            collect_group_child_order_matrix(original_group, String::new())
        );
    }

    #[test]
    fn multi_fixture_roundtrip_preserves_live_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx_xml(FIXTURE_NEW_DATABASE_MULTI, &key).expect("extract original multi xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_NEW_DATABASE_MULTI, &key).expect("load multi fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save multi fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten multi xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten multi xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_live_entry_matrix(rewritten_group, String::new()),
            collect_group_live_entry_matrix(original_group, String::new())
        );
    }

    #[test]
    fn sync_fixture_upgrade_preserves_live_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx_xml(FIXTURE_SYNC_DATABASE, &key).expect("extract original sync xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_SYNC_DATABASE, &key).expect("load sync fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save sync fixture");
        let rewritten_xml = extract_kdbx_xml(&rewritten, &key).expect("extract rewritten sync xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten sync xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_live_entry_matrix(rewritten_group, String::new()),
            collect_group_live_entry_matrix(original_group, String::new())
        );
    }

    #[test]
    fn merge_fixture_upgrade_preserves_group_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx_xml(FIXTURE_MERGE_DATABASE, &key).expect("extract original merge xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_MERGE_DATABASE, &key).expect("load merge fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save merge fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten merge xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten merge xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_child_order_matrix(rewritten_group, String::new()),
            collect_group_child_order_matrix(original_group, String::new())
        );
    }

    #[test]
    fn format300_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx_xml(FIXTURE_FORMAT300, &key).expect("extract original format300 xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_FORMAT300, &key).expect("load format300 fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save format300 fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten format300 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten format300 xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn format300_fixture_upgrade_preserves_live_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx_xml(FIXTURE_FORMAT300, &key).expect("extract original format300 xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_FORMAT300, &key).expect("load format300 fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save format300 fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten format300 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten format300 xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_live_entry_matrix(rewritten_group, String::new()),
            collect_group_live_entry_matrix(original_group, String::new())
        );
    }

    #[test]
    fn protected_strings_fixture_upgrade_preserves_live_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("masterpw");

        let original_xml = extract_kdbx_xml(FIXTURE_PROTECTED_STRINGS, &key)
            .expect("extract original protected strings xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded =
            load_kdbx(FIXTURE_PROTECTED_STRINGS, &key).expect("load protected strings fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save protected strings fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten protected strings xml");
        let rewritten_parsed = Element::parse(rewritten_xml.as_bytes())
            .expect("parse rewritten protected strings xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_live_entry_matrix(rewritten_group, String::new()),
            collect_group_live_entry_matrix(original_group, String::new())
        );
    }

    #[test]
    fn recycle_bin_with_data_fixture_roundtrip_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("123");

        let original_xml = extract_kdbx_xml(FIXTURE_RECYCLE_BIN_WITH_DATA, &key)
            .expect("extract original recycle bin xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded =
            load_kdbx(FIXTURE_RECYCLE_BIN_WITH_DATA, &key).expect("load recycle bin fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save recycle bin fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten recycle bin xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten recycle bin xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn recycle_bin_with_data_fixture_roundtrip_preserves_group_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("123");

        let original_xml = extract_kdbx_xml(FIXTURE_RECYCLE_BIN_WITH_DATA, &key)
            .expect("extract original recycle bin xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded =
            load_kdbx(FIXTURE_RECYCLE_BIN_WITH_DATA, &key).expect("load recycle bin fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save recycle bin fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten recycle bin xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten recycle bin xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_child_order_matrix(rewritten_group, String::new()),
            collect_group_child_order_matrix(original_group, String::new())
        );
    }

    #[test]
    fn non_ascii_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("Δöض");

        let original_xml =
            extract_kdbx_xml(FIXTURE_NON_ASCII, &key).expect("extract original non-ascii xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_NON_ASCII, &key).expect("load non-ascii fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save non-ascii fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten non-ascii xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten non-ascii xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn non_ascii_fixture_upgrade_preserves_live_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("Δöض");

        let original_xml =
            extract_kdbx_xml(FIXTURE_NON_ASCII, &key).expect("extract original non-ascii xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_NON_ASCII, &key).expect("load non-ascii fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save non-ascii fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten non-ascii xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten non-ascii xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_live_entry_matrix(rewritten_group, String::new()),
            collect_group_live_entry_matrix(original_group, String::new())
        );
    }

    #[test]
    fn compressed_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("");

        let original_xml =
            extract_kdbx_xml(FIXTURE_COMPRESSED, &key).expect("extract original compressed xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_COMPRESSED, &key).expect("load compressed fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save compressed fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten compressed xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten compressed xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn compressed_fixture_upgrade_preserves_live_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("");

        let original_xml =
            extract_kdbx_xml(FIXTURE_COMPRESSED, &key).expect("extract original compressed xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_COMPRESSED, &key).expect("load compressed fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save compressed fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten compressed xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten compressed xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_live_entry_matrix(rewritten_group, String::new()),
            collect_group_live_entry_matrix(original_group, String::new())
        );
    }

    #[test]
    fn recycle_bin_disabled_fixture_roundtrip_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("123");

        let original_xml = extract_kdbx_xml(FIXTURE_RECYCLE_BIN_DISABLED, &key)
            .expect("extract original recycle-bin-disabled xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_RECYCLE_BIN_DISABLED, &key)
            .expect("load recycle-bin-disabled fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save recycle-bin-disabled fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten recycle-bin-disabled xml");
        let rewritten_parsed = Element::parse(rewritten_xml.as_bytes())
            .expect("parse rewritten recycle-bin-disabled xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn recycle_bin_disabled_fixture_roundtrip_preserves_group_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("123");

        let original_xml = extract_kdbx_xml(FIXTURE_RECYCLE_BIN_DISABLED, &key)
            .expect("extract original recycle-bin-disabled xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_RECYCLE_BIN_DISABLED, &key)
            .expect("load recycle-bin-disabled fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save recycle-bin-disabled fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten recycle-bin-disabled xml");
        let rewritten_parsed = Element::parse(rewritten_xml.as_bytes())
            .expect("parse rewritten recycle-bin-disabled xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_child_order_matrix(rewritten_group, String::new()),
            collect_group_child_order_matrix(original_group, String::new())
        );
    }

    #[test]
    fn recycle_bin_not_yet_created_fixture_roundtrip_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("123");

        let original_xml = extract_kdbx_xml(FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, &key)
            .expect("extract original recycle-bin-not-yet-created xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, &key)
            .expect("load recycle-bin-not-yet-created fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save recycle-bin-not-yet-created fixture");
        let rewritten_xml = extract_kdbx_xml(&rewritten, &key)
            .expect("extract rewritten recycle-bin-not-yet-created xml");
        let rewritten_parsed = Element::parse(rewritten_xml.as_bytes())
            .expect("parse rewritten recycle-bin-not-yet-created xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn recycle_bin_empty_fixture_roundtrip_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("123");

        let original_xml = extract_kdbx_xml(FIXTURE_RECYCLE_BIN_EMPTY, &key)
            .expect("extract original recycle-bin-empty xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded =
            load_kdbx(FIXTURE_RECYCLE_BIN_EMPTY, &key).expect("load recycle-bin-empty fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save recycle-bin-empty fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten recycle-bin-empty xml");
        let rewritten_parsed = Element::parse(rewritten_xml.as_bytes())
            .expect("parse rewritten recycle-bin-empty xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn key_file_protected_fixture_upgrade_preserves_live_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("a");
        key.add_key_file_content(FIXTURE_KEY_FILE_PROTECTED)
            .expect("password+key key file");

        let original_xml = extract_kdbx_xml(FIXTURE_KEY_FILE_PROTECTED_DB, &key)
            .expect("extract original key-file-protected xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_KEY_FILE_PROTECTED_DB, &key)
            .expect("load key-file-protected fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save key-file-protected fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten key-file-protected xml");
        let rewritten_parsed = Element::parse(rewritten_xml.as_bytes())
            .expect("parse rewritten key-file-protected xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_live_entry_matrix(rewritten_group, String::new()),
            collect_group_live_entry_matrix(original_group, String::new())
        );
    }

    #[test]
    fn key_file_only_fixture_upgrade_preserves_live_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_key_file_content(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD)
            .expect("key-only key file");

        let original_xml = extract_kdbx_xml(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB, &key)
            .expect("extract original key-file-only xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB, &key)
            .expect("load key-file-only fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save key-file-only fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten key-file-only xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten key-file-only xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_live_entry_matrix(rewritten_group, String::new()),
            collect_group_live_entry_matrix(original_group, String::new())
        );
    }

    #[test]
    fn recycle_bin_not_yet_created_fixture_roundtrip_preserves_group_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("123");

        let original_xml = extract_kdbx_xml(FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, &key)
            .expect("extract original recycle-bin-not-yet-created xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, &key)
            .expect("load recycle-bin-not-yet-created fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save recycle-bin-not-yet-created fixture");
        let rewritten_xml = extract_kdbx_xml(&rewritten, &key)
            .expect("extract rewritten recycle-bin-not-yet-created xml");
        let rewritten_parsed = Element::parse(rewritten_xml.as_bytes())
            .expect("parse rewritten recycle-bin-not-yet-created xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_child_order_matrix(rewritten_group, String::new()),
            collect_group_child_order_matrix(original_group, String::new())
        );
    }

    #[test]
    fn recycle_bin_empty_fixture_roundtrip_preserves_group_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("123");

        let original_xml = extract_kdbx_xml(FIXTURE_RECYCLE_BIN_EMPTY, &key)
            .expect("extract original recycle-bin-empty xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded =
            load_kdbx(FIXTURE_RECYCLE_BIN_EMPTY, &key).expect("load recycle-bin-empty fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save recycle-bin-empty fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten recycle-bin-empty xml");
        let rewritten_parsed = Element::parse(rewritten_xml.as_bytes())
            .expect("parse rewritten recycle-bin-empty xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_child_order_matrix(rewritten_group, String::new()),
            collect_group_child_order_matrix(original_group, String::new())
        );
    }

    #[test]
    fn key_file_protected_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("a");
        key.add_key_file_content(FIXTURE_KEY_FILE_PROTECTED)
            .expect("password+key key file");

        let original_xml = extract_kdbx_xml(FIXTURE_KEY_FILE_PROTECTED_DB, &key)
            .expect("extract original key-file-protected xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_KEY_FILE_PROTECTED_DB, &key)
            .expect("load key-file-protected fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save key-file-protected fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten key-file-protected xml");
        let rewritten_parsed = Element::parse(rewritten_xml.as_bytes())
            .expect("parse rewritten key-file-protected xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn key_file_only_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_key_file_content(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD)
            .expect("key-only key file");

        let original_xml = extract_kdbx_xml(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB, &key)
            .expect("extract original key-file-only xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB, &key)
            .expect("load key-file-only fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save key-file-only fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten key-file-only xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten key-file-only xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn format200_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx_xml(FIXTURE_FORMAT200, &key).expect("extract original format200 xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_FORMAT200, &key).expect("load format200 fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save format200 fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten format200 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten format200 xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn format200_fixture_upgrade_preserves_live_entry_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let original_xml =
            extract_kdbx_xml(FIXTURE_FORMAT200, &key).expect("extract original format200 xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded = load_kdbx(FIXTURE_FORMAT200, &key).expect("load format200 fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save format200 fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten format200 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten format200 xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_live_entry_matrix(rewritten_group, String::new()),
            collect_group_live_entry_matrix(original_group, String::new())
        );
    }

    #[test]
    fn file_key_binary_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_key_file_content(FIXTURE_FILE_KEY_BINARY)
            .expect("binary key file");

        let original_xml = extract_kdbx_xml(FIXTURE_FILE_KEY_BINARY_DB, &key)
            .expect("extract original file-key-binary xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded =
            load_kdbx(FIXTURE_FILE_KEY_BINARY_DB, &key).expect("load file-key-binary fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save file-key-binary fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten file-key-binary xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten file-key-binary xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn file_key_xml_v2_fixture_upgrade_preserves_group_child_order_matrix() {
        let mut key = CompositeKey::default();
        key.add_key_file_content(FIXTURE_FILE_KEY_XML_V2)
            .expect("xml-v2 key file");

        let original_xml = extract_kdbx_xml(FIXTURE_FILE_KEY_XML_V2_DB, &key)
            .expect("extract original file-key-xml-v2 xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_group = original_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("original root group");

        let loaded =
            load_kdbx(FIXTURE_FILE_KEY_XML_V2_DB, &key).expect("load file-key-xml-v2 fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save file-key-xml-v2 fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten file-key-xml-v2 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten file-key-xml-v2 xml");
        let rewritten_group = rewritten_parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("rewritten root group");

        assert_eq!(
            collect_group_child_order_matrix(rewritten_group, String::new()),
            collect_group_child_order_matrix(original_group, String::new())
        );
    }

    #[test]
    fn file_key_hex_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_key_file_content(FIXTURE_FILE_KEY_HEX)
            .expect("hex key file");

        let original_xml = extract_kdbx_xml(FIXTURE_FILE_KEY_HEX_DB, &key)
            .expect("extract original file-key-hex xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_FILE_KEY_HEX_DB, &key).expect("load file-key-hex fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save file-key-hex fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten file-key-hex xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten file-key-hex xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn file_key_hashed_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_key_file_content(FIXTURE_FILE_KEY_HASHED)
            .expect("hashed key file");

        let original_xml = extract_kdbx_xml(FIXTURE_FILE_KEY_HASHED_DB, &key)
            .expect("extract original file-key-hashed xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded =
            load_kdbx(FIXTURE_FILE_KEY_HASHED_DB, &key).expect("load file-key-hashed fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save file-key-hashed fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten file-key-hashed xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten file-key-hashed xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn file_key_xml_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_key_file_content(FIXTURE_FILE_KEY_XML)
            .expect("xml key file");

        let original_xml = extract_kdbx_xml(FIXTURE_FILE_KEY_XML_DB, &key)
            .expect("extract original file-key-xml xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded = load_kdbx(FIXTURE_FILE_KEY_XML_DB, &key).expect("load file-key-xml fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save file-key-xml fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten file-key-xml xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten file-key-xml xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn file_key_xml_v2_fixture_upgrade_preserves_root_child_order() {
        let mut key = CompositeKey::default();
        key.add_key_file_content(FIXTURE_FILE_KEY_XML_V2)
            .expect("xml-v2 key file");

        let original_xml = extract_kdbx_xml(FIXTURE_FILE_KEY_XML_V2_DB, &key)
            .expect("extract original file-key-xml-v2 xml");
        let original_parsed = Element::parse(original_xml.as_bytes()).expect("parse original xml");
        let original_root = original_parsed
            .get_child("Root")
            .expect("original root node");

        let loaded =
            load_kdbx(FIXTURE_FILE_KEY_XML_V2_DB, &key).expect("load file-key-xml-v2 fixture");
        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("save file-key-xml-v2 fixture");
        let rewritten_xml =
            extract_kdbx_xml(&rewritten, &key).expect("extract rewritten file-key-xml-v2 xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten file-key-xml-v2 xml");
        let rewritten_root = rewritten_parsed
            .get_child("Root")
            .expect("rewritten root node");
        let expected_order = child_element_names(original_root);

        assert_in_order(child_element_names(rewritten_root), &expected_order);
    }

    #[test]
    fn browser_fixture_roundtrip_loads_meta_settings_changed_and_force_once() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let mutated = rewrite_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            let database_name_index = meta
                .children
                .iter()
                .position(
                    |child| matches!(child, XMLNode::Element(element) if element.name == "DatabaseName"),
                )
                .expect("database name index");
            meta.children.insert(
                database_name_index,
                XMLNode::Element(text_element("SettingsChanged", "1700000000")),
            );

            let memory_protection_index = meta
                .children
                .iter()
                .position(
                    |child| matches!(child, XMLNode::Element(element) if element.name == "MemoryProtection"),
                )
                .expect("memory protection index");
            meta.children.insert(
                memory_protection_index,
                XMLNode::Element(text_element("MasterKeyChangeForceOnce", bool_text(true))),
            );
        })
        .expect("rewrite browser fixture");

        let mutated_xml = extract_kdbx4_xml(&mutated, &key).expect("extract mutated xml");
        let mutated_parsed = Element::parse(mutated_xml.as_bytes()).expect("parse mutated xml");
        let mutated_meta = mutated_parsed.get_child("Meta").expect("mutated meta");
        assert_in_order(
            child_element_names(mutated_meta),
            &["Generator", "SettingsChanged", "DatabaseName"],
        );
        assert_in_order(
            child_element_names(mutated_meta),
            &[
                "MasterKeyChanged",
                "MasterKeyChangeForceOnce",
                "MemoryProtection",
            ],
        );

        let loaded = load_kdbx(&mutated, &key).expect("load mutated browser fixture");
        assert_eq!(loaded.settings_changed, Some(1_700_000_000));
        assert_eq!(loaded.master_key_change_force_once, Some(true));

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_meta = rewritten_parsed.get_child("Meta").expect("rewritten meta");

        assert_eq!(
            meta_child_text_or_empty(rewritten_meta, "SettingsChanged"),
            Some("1700000000".into())
        );
        assert_eq!(
            meta_child_text_or_empty(rewritten_meta, "MasterKeyChangeForceOnce"),
            Some("True".into())
        );
        assert_in_order(
            child_element_names(rewritten_meta),
            &["Generator", "SettingsChanged", "DatabaseName"],
        );
        assert_in_order(
            child_element_names(rewritten_meta),
            &[
                "MasterKeyChanged",
                "MasterKeyChangeForceOnce",
                "MemoryProtection",
            ],
        );
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_custom_icon_name_and_last_modification_time() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let mutated = rewrite_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key, |root| {
            let custom_icons = root
                .get_mut_child("Meta")
                .and_then(|meta| meta.get_mut_child("CustomIcons"))
                .expect("custom icons");
            custom_icons.children.push(XMLNode::Element(
                parse_xml_fragment(
                    "<Icon>\
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>\
                        <Data>AQIDBA==</Data>\
                        <Name>Browser Icon</Name>\
                        <LastModificationTime>1700000005</LastModificationTime>\
                    </Icon>",
                )
                .expect("custom icon"),
            ));
        })
        .expect("rewrite browser fixture");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated browser fixture");
        assert_eq!(loaded.custom_icons.len(), 1);
        assert_eq!(loaded.custom_icons[0].name.as_deref(), Some("Browser Icon"));
        assert_eq!(loaded.custom_icons[0].last_modified, Some(1_700_000_005));

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_icon = rewritten_parsed
            .get_child("Meta")
            .and_then(|meta| meta.get_child("CustomIcons"))
            .and_then(|custom_icons| custom_icons.get_child("Icon"))
            .expect("rewritten icon");

        assert_eq!(
            child_text(rewritten_icon, "Name").as_deref(),
            Some("Browser Icon")
        );
        assert_datetime_text(rewritten_icon, "LastModificationTime", 1_700_000_005, true);
        assert_in_order(
            child_element_names(rewritten_icon),
            &["UUID", "Name", "LastModificationTime", "Data"],
        );
    }

    #[test]
    fn browser_fixture_roundtrip_preserves_mixed_meta_node_order() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let mutated = rewrite_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            let custom_data_index = meta
                .children
                .iter()
                .position(|child| matches!(child, XMLNode::Element(element) if element.name == "CustomData"))
                .expect("custom data index");
            let custom_data = match meta.children.remove(custom_data_index) {
                XMLNode::Element(element) => element,
                _ => unreachable!("custom data child must be element"),
            };
            let mut items = custom_data
                .children
                .into_iter()
                .filter_map(|child| match child {
                    XMLNode::Element(element) if element.name == "Item" => Some(XMLNode::Element(element)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert!(
                items.len() >= 2,
                "expected at least two custom data items for mixed meta test"
            );
            let trailing_items = items.split_off(1);
            let mut first_custom_data = Element::new("CustomData");
            first_custom_data.children = items;
            let mut second_custom_data = Element::new("CustomData");
            second_custom_data.children = trailing_items;

            let description_index = meta
                .children
                .iter()
                .position(|child| {
                    matches!(child, XMLNode::Element(element) if element.name == "DatabaseDescription")
                })
                .expect("description index");
            meta.children
                .insert(description_index + 1, XMLNode::Element(first_custom_data));
            meta.children.insert(
                description_index + 2,
                XMLNode::Element(
                    parse_xml_fragment("<UnknownMetaMixed><Value>Omega</Value></UnknownMetaMixed>")
                        .expect("unknown mixed meta node"),
                ),
            );
            meta.children
                .insert(description_index + 3, XMLNode::Element(second_custom_data));
        })
        .expect("rewrite browser fixture");

        let mutated_xml = extract_kdbx4_xml(&mutated, &key).expect("extract mutated xml");
        let mutated_parsed = Element::parse(mutated_xml.as_bytes()).expect("parse mutated xml");
        let mutated_meta = mutated_parsed.get_child("Meta").expect("mutated meta");
        assert_in_order(
            child_element_names(mutated_meta),
            &[
                "DatabaseDescription",
                "CustomData",
                "UnknownMetaMixed",
                "CustomData",
                "DatabaseDescriptionChanged",
                "DefaultUserName",
            ],
        );
        assert_eq!(custom_data_blocks(mutated_meta).len(), 2);

        let loaded = load_kdbx(&mutated, &key).expect("load mutated browser fixture");
        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save browser fixture");
        let rewritten_xml =
            extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten browser xml");
        let rewritten_parsed =
            Element::parse(rewritten_xml.as_bytes()).expect("parse rewritten browser xml");
        let rewritten_meta = rewritten_parsed.get_child("Meta").expect("rewritten meta");

        assert_in_order(
            child_element_names(rewritten_meta),
            &[
                "DatabaseDescription",
                "CustomData",
                "UnknownMetaMixed",
                "CustomData",
                "DatabaseDescriptionChanged",
                "DefaultUserName",
            ],
        );
        assert_eq!(
            custom_data_blocks(rewritten_meta),
            custom_data_blocks(mutated_meta)
        );
    }

    fn extract_kdbx_xml(bytes: &[u8], composite_key: &CompositeKey) -> super::Result<String> {
        match detect_file_version(bytes)? {
            KdbxVersion::V2_0 | KdbxVersion::V3_0 | KdbxVersion::V3_1 => {
                extract_kdbx3_xml(bytes, composite_key)
            }
            KdbxVersion::V4_0 | KdbxVersion::V4_1 => extract_kdbx4_xml(bytes, composite_key),
        }
    }

    fn extract_kdbx3_xml(bytes: &[u8], composite_key: &CompositeKey) -> super::Result<String> {
        let (header, header_len) = decode_kdbx3_header(bytes)?;
        let raw_key = composite_key.raw_key()?;
        let transformed = KdfProfile::AesKdbx3 {
            rounds: header.transform_rounds,
            salt: header.transform_seed,
        }
        .derive_key(&raw_key)?;
        let encryption_key = sha256_seeded(&header.master_seed, &transformed);
        let encrypted_payload = &bytes[header_len..];
        let payload = decrypt_payload(
            header.cipher,
            &encryption_key,
            &header.encryption_iv,
            encrypted_payload,
        )?;

        if payload.len() < header.stream_start_bytes.len()
            || &payload[..header.stream_start_bytes.len()] != header.stream_start_bytes.as_slice()
        {
            return Err(super::KdbxError::HeaderHashMismatch);
        }

        let block_payload =
            decode_legacy_block_stream(&payload[header.stream_start_bytes.len()..])?;
        let xml_bytes = match header.compression {
            Compression::None => block_payload,
            Compression::Gzip => gzip_decompress(&block_payload)?,
        };
        String::from_utf8(xml_bytes).map_err(|_| super::KdbxError::InvalidValue)
    }

    fn extract_kdbx4_xml(bytes: &[u8], composite_key: &CompositeKey) -> super::Result<String> {
        let (header, header_len) = KdbxHeader::decode_with_consumed(bytes)?;
        let mut cursor = super::Cursor::new(&bytes[header_len..]);
        let stored_header_hash = cursor.read_exact(32)?.to_vec();
        let _stored_header_hmac = cursor.read_exact(32)?.to_vec();
        let payload_bytes = cursor.read_remaining().to_vec();

        let header_bytes = &bytes[..header_len];
        assert_eq!(
            sha256_bytes(header_bytes).as_slice(),
            stored_header_hash.as_slice()
        );

        let raw_key = composite_key.raw_key()?;
        let kdf = kdf_from_variant_dict(&header.kdf_parameters)?;
        let transformed = kdf.derive_key(&raw_key)?;
        let encryption_key = sha256_seeded(&header.master_seed, &transformed);
        let mac_seed = mac_seed(&header.master_seed, &transformed);
        let encrypted_payload = decode_block_stream(&mac_seed, &payload_bytes)?;
        let payload = decrypt_payload(
            header.cipher,
            &encryption_key,
            &header.encryption_iv,
            &encrypted_payload,
        )?;
        let payload = match header.compression {
            Compression::None => payload,
            Compression::Gzip => gzip_decompress(&payload)?,
        };
        let (_, _, _, consumed) = parse_inner_header(&payload)?;
        String::from_utf8(payload[consumed..].to_vec()).map_err(|_| super::KdbxError::InvalidValue)
    }

    fn rewrite_kdbx4_xml(
        bytes: &[u8],
        composite_key: &CompositeKey,
        mutate: impl FnOnce(&mut Element),
    ) -> super::Result<Vec<u8>> {
        let (header, header_len) = KdbxHeader::decode_with_consumed(bytes)?;
        let mut cursor = super::Cursor::new(&bytes[header_len..]);
        let _stored_header_hash = cursor.read_exact(32)?.to_vec();
        let _stored_header_hmac = cursor.read_exact(32)?.to_vec();
        let payload_bytes = cursor.read_remaining().to_vec();

        let raw_key = composite_key.raw_key()?;
        let kdf = kdf_from_variant_dict(&header.kdf_parameters)?;
        let transformed = kdf.derive_key(&raw_key)?;
        let encryption_key = sha256_seeded(&header.master_seed, &transformed);
        let mac_seed = mac_seed(&header.master_seed, &transformed);
        let encrypted_payload = decode_block_stream(&mac_seed, &payload_bytes)?;
        let payload = decrypt_payload(
            header.cipher,
            &encryption_key,
            &header.encryption_iv,
            &encrypted_payload,
        )?;
        let payload = match header.compression {
            Compression::None => payload,
            Compression::Gzip => gzip_decompress(&payload)?,
        };

        let (_, _, _, consumed) = parse_inner_header(&payload)?;
        let mut xml = Element::parse(std::io::Cursor::new(&payload[consumed..]))
            .map_err(|error| super::KdbxError::Xml(error.to_string()))?;
        mutate(&mut xml);
        let mut xml_bytes = Vec::new();
        xml.write(&mut xml_bytes)
            .map_err(|error| super::KdbxError::Xml(error.to_string()))?;

        let mut new_payload = payload[..consumed].to_vec();
        new_payload.extend(xml_bytes);
        let payload = match header.compression {
            Compression::None => new_payload,
            Compression::Gzip => gzip_compress(&new_payload)?,
        };
        let encrypted_payload = super::encrypt_payload(
            header.cipher,
            &encryption_key,
            &header.encryption_iv,
            &payload,
        )?;
        let block_stream = encode_block_stream(&mac_seed, &encrypted_payload)?;
        let header_bytes = header.encode()?;
        let header_hash = sha256_bytes(&header_bytes);
        let header_hmac = header_hmac(&mac_seed, &header_bytes)?;

        let mut file = Vec::new();
        file.extend(header_bytes);
        file.extend(header_hash);
        file.extend(header_hmac);
        file.extend(block_stream);
        Ok(file)
    }

    fn collect_group_live_entry_matrix(
        group: &Element,
        parent_path: String,
    ) -> Vec<(String, Vec<String>)> {
        let title = child_text(group, "Name").unwrap_or_else(|| "Group".into());
        let path = if parent_path.is_empty() {
            title
        } else {
            format!("{parent_path}/{title}")
        };

        let mut rows = Vec::new();
        let mut entry_index = 0usize;
        for child in &group.children {
            if let XMLNode::Element(element) = child {
                match element.name.as_str() {
                    "Entry" => {
                        rows.push((
                            format!("{path}/entry[{entry_index}]"),
                            entry_child_descriptors(element),
                        ));
                        entry_index += 1;
                    }
                    "Group" => rows.extend(collect_group_live_entry_matrix(element, path.clone())),
                    _ => {}
                }
            }
        }
        rows
    }

    fn child_element_names(element: &Element) -> Vec<&str> {
        element
            .children
            .iter()
            .filter_map(|child| match child {
                XMLNode::Element(element) => Some(element.name.as_str()),
                _ => None,
            })
            .collect()
    }

    fn collect_entry_elements<'a>(root: &'a Element, entries: &mut Vec<&'a Element>) {
        if root.name == "Entry" {
            entries.push(root);
        }

        for child in &root.children {
            if let XMLNode::Element(element) = child {
                collect_entry_elements(element, entries);
            }
        }
    }

    fn generated_xml(vault: &Vault, version: KdbxVersion) -> Element {
        let xml = super::build_xml(
            vault,
            &std::collections::HashMap::new(),
            &[0_u8; 64],
            version,
        )
        .expect("build xml");
        Element::parse(std::io::Cursor::new(xml)).expect("parse generated xml")
    }

    fn assert_custom_data_items_omit_last_modified(element: &Element) {
        for custom_data in element.children.iter().filter_map(|child| match child {
            XMLNode::Element(custom_data) if custom_data.name == "CustomData" => Some(custom_data),
            _ => None,
        }) {
            for item in custom_data.children.iter().filter_map(|child| match child {
                XMLNode::Element(item) if item.name == "Item" => Some(item),
                _ => None,
            }) {
                assert!(
                    item.get_child("LastModificationTime").is_none(),
                    "CustomData item should not carry KDBX4.1-only LastModificationTime"
                );
            }
        }
    }

    fn is_kdbx4_binary_datetime(value: &str) -> bool {
        super::STANDARD
            .decode(value.as_bytes())
            .map(|bytes| bytes.len() == 8)
            .unwrap_or(false)
    }

    fn assert_datetime_text(
        element: &Element,
        child_name: &str,
        expected: u64,
        expect_kdbx4_binary: bool,
    ) {
        let value = child_text(element, child_name).expect("datetime child");
        assert_eq!(super::parse_datetime_value(&value), Some(expected));
        if expect_kdbx4_binary {
            assert!(
                is_kdbx4_binary_datetime(&value),
                "expected KDBX4 binary datetime, got {value}"
            );
        }
    }

    fn entry_child_descriptors(element: &Element) -> Vec<String> {
        element
            .children
            .iter()
            .filter_map(|child| match child {
                XMLNode::Element(element) if element.name == "String" => Some(format!(
                    "String:{}",
                    child_text(element, "Key").unwrap_or_default()
                )),
                XMLNode::Element(element) if element.name == "Binary" => Some(format!(
                    "Binary:{}",
                    child_text(element, "Key").unwrap_or_default()
                )),
                XMLNode::Element(element) => Some(element.name.clone()),
                _ => None,
            })
            .collect()
    }

    fn collect_group_child_order_matrix(
        group: &Element,
        parent_path: String,
    ) -> Vec<(String, Vec<String>)> {
        let title = child_text(group, "Name").unwrap_or_else(|| "Group".into());
        let path = if parent_path.is_empty() {
            title
        } else {
            format!("{parent_path}/{title}")
        };

        let mut rows = vec![(
            path.clone(),
            child_element_names(group)
                .into_iter()
                .map(str::to_string)
                .collect(),
        )];
        for child in &group.children {
            if let XMLNode::Element(child_group) = child {
                if child_group.name == "Group" {
                    rows.extend(collect_group_child_order_matrix(child_group, path.clone()));
                }
            }
        }
        rows
    }

    fn history_entry_child_matrix(
        entry: &Element,
        parent_path: String,
    ) -> Vec<(String, Vec<String>)> {
        let mut rows = Vec::new();
        let Some(history) = entry.get_child("History") else {
            return rows;
        };

        let mut index = 0usize;
        for child in &history.children {
            if let XMLNode::Element(history_entry) = child {
                if history_entry.name == "Entry" {
                    let path = format!("{parent_path}/history[{index}]");
                    rows.push((path.clone(), entry_child_descriptors(history_entry)));
                    rows.extend(history_entry_child_matrix(history_entry, path));
                    index += 1;
                }
            }
        }
        rows
    }

    fn collect_group_history_entry_matrix(
        group: &Element,
        parent_path: String,
    ) -> Vec<(String, Vec<String>)> {
        let title = child_text(group, "Name").unwrap_or_else(|| "Group".into());
        let path = if parent_path.is_empty() {
            title
        } else {
            format!("{parent_path}/{title}")
        };

        let mut rows = Vec::new();
        let mut entry_index = 0usize;
        for child in &group.children {
            if let XMLNode::Element(element) = child {
                match element.name.as_str() {
                    "Entry" => {
                        rows.extend(history_entry_child_matrix(
                            element,
                            format!("{path}/entry[{entry_index}]"),
                        ));
                        entry_index += 1;
                    }
                    "Group" => {
                        rows.extend(collect_group_history_entry_matrix(element, path.clone()))
                    }
                    _ => {}
                }
            }
        }
        rows
    }

    fn assert_in_order(actual: Vec<&str>, expected_subsequence: &[&str]) {
        let mut cursor = 0;
        for expected in expected_subsequence {
            let offset = actual[cursor..]
                .iter()
                .position(|name| name == expected)
                .unwrap_or_else(|| panic!("missing `{expected}` in child order: {actual:?}"));
            cursor += offset + 1;
        }
    }

    fn custom_data_blocks(element: &Element) -> Vec<Vec<(String, String)>> {
        element
            .children
            .iter()
            .filter_map(|child| match child {
                XMLNode::Element(element) if element.name == "CustomData" => Some(
                    element
                        .children
                        .iter()
                        .filter_map(|item| match item {
                            XMLNode::Element(item) if item.name == "Item" => Some((
                                child_text(item, "Key").unwrap_or_default(),
                                child_text(item, "Value").unwrap_or_default(),
                            )),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .collect()
    }

    fn split_first_custom_data_block(target: &mut Element) {
        let custom_data_index = target
            .children
            .iter()
            .position(
                |child| matches!(child, XMLNode::Element(element) if element.name == "CustomData"),
            )
            .expect("custom data index");
        let custom_data = match target.children.remove(custom_data_index) {
            XMLNode::Element(element) => element,
            _ => unreachable!("custom data child must be element"),
        };
        let mut items = custom_data
            .children
            .into_iter()
            .filter_map(|child| match child {
                XMLNode::Element(element) if element.name == "Item" => {
                    Some(XMLNode::Element(element))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            items.len() >= 2,
            "expected at least two custom data items to split"
        );

        let remaining = items.split_off(1);
        let mut first_block = Element::new("CustomData");
        first_block.children = items;
        let mut second_block = Element::new("CustomData");
        second_block.children = remaining;

        target
            .children
            .insert(custom_data_index, XMLNode::Element(first_block));
        target
            .children
            .insert(custom_data_index + 1, XMLNode::Element(second_block));
    }

    fn assert_custom_data_cluster_context(expected: &Element, actual: &Element) {
        let expected_names = child_element_names(expected);
        let actual_names = child_element_names(actual);

        let expected_first = expected_names
            .iter()
            .position(|name| *name == "CustomData")
            .expect("expected custom data cluster start");
        let expected_last = expected_names
            .iter()
            .rposition(|name| *name == "CustomData")
            .expect("expected custom data cluster end");
        let actual_first = actual_names
            .iter()
            .position(|name| *name == "CustomData")
            .expect("actual custom data cluster start");
        let actual_last = actual_names
            .iter()
            .rposition(|name| *name == "CustomData")
            .expect("actual custom data cluster end");

        assert_eq!(
            expected_last - expected_first,
            actual_last - actual_first,
            "expected names: {:?}, actual names: {:?}",
            expected_names,
            actual_names,
        );
        assert_eq!(
            expected_first
                .checked_sub(1)
                .map(|index| expected_names[index]),
            actual_first.checked_sub(1).map(|index| actual_names[index]),
            "expected names: {:?}, actual names: {:?}",
            expected_names,
            actual_names,
        );
        assert_eq!(
            expected_names.get(expected_last + 1).copied(),
            actual_names.get(actual_last + 1).copied(),
            "expected names: {:?}, actual names: {:?}",
            expected_names,
            actual_names,
        );
    }

    fn meta_child_text_or_empty(element: &Element, name: &str) -> Option<String> {
        element.get_child(name).map(|child| {
            child
                .get_text()
                .map(|text| text.to_string())
                .unwrap_or_default()
        })
    }
}
