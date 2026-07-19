use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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
    Attachment, AttachmentContent, AttachmentContentId, AttachmentContentPool, AutoTypeAssociation,
    AutoTypeConfig, CustomDataBlock, CustomDataItem, CustomField, CustomIcon, DeletedObject, Entry,
    EntryRawState, Group, GroupRawState, GroupTimes, MemoryProtection, MetaRawState, ModelError,
    OpaqueXmlAnchor, OpaqueXmlFragment, PasskeyRecord, RootRawState, Vault,
    is_totp_persistent_attribute_key, is_totp_secret_persistent_attribute_key,
    materialize_entry_persistent_attributes, totp_from_persistent_attributes,
};
use xmltree::{Element, XMLNode};
use zeroize::{Zeroize, Zeroizing};

mod external_kdf;
pub use external_kdf::{
    DESKTOP_AES_CONFIRM_ROUNDS, DESKTOP_AES_REFUSE_ROUNDS, DESKTOP_ARGON2_CONFIRM_BYTES,
    DESKTOP_ARGON2_REFUSE_BYTES, ExternalKdfAlgorithm, ExternalKdfConfirmation,
    ExternalKdfDecision, ExternalKdfParameter, ExternalKdfParameters, ExternalKdfPolicy,
    ExternalKdfRequest, ExternalKdfResource, KdfPolicyEvaluator, MOBILE_AES_REFUSE_ROUNDS,
    MOBILE_ARGON2_REFUSE_BYTES, enforce_external_kdf_policy,
};
pub mod kdf_generation;

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
    #[error("invalid external KDF parameter {parameter:?}={value} for algorithm {algorithm:?}")]
    InvalidKdfParameters {
        algorithm: ExternalKdfAlgorithm,
        parameter: ExternalKdfParameter,
        value: u64,
    },
    #[error(
        "external KDF policy {decision:?} for algorithm {algorithm:?} with observed value {observed}"
    )]
    ExternalKdfPolicy {
        algorithm: ExternalKdfAlgorithm,
        observed: u64,
        decision: ExternalKdfDecision,
    },
    #[error("xml error: {0}")]
    Xml(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Model(#[from] ModelError),
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
    Unknown { type_tag: u8, bytes: Vec<u8> },
}

#[derive(Debug, Clone, Default)]
pub struct VariantDictionary {
    items: BTreeMap<String, VariantValue>,
    loaded_encoding: Option<Vec<u8>>,
}

impl PartialEq for VariantDictionary {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items
    }
}

impl Eq for VariantDictionary {}

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
        if let Some(encoded) = &self.loaded_encoding
            && Self::decode_items(encoded)? == self.items
        {
            return Ok(encoded.clone());
        }

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
        Ok(Self {
            items: Self::decode_items(bytes)?,
            loaded_encoding: Some(bytes.to_vec()),
        })
    }

    fn decode_items(bytes: &[u8]) -> Result<BTreeMap<String, VariantValue>> {
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

        Ok(items)
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
    Argon2d {
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    },
    Argon2id {
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    },
}

impl SaveKdf {
    pub fn recommended() -> Self {
        Self::Argon2id {
            iterations: 2,
            memory_kib: 64 * 1024,
            parallelism: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveProfile {
    pub version: KdbxVersion,
    pub cipher: KdbxCipher,
    pub compression: Compression,
    /// `None` preserves a loaded KDBX4 dictionary and uses product defaults only on first save.
    pub kdf: Option<SaveKdf>,
}

impl SaveProfile {
    pub fn recommended() -> Self {
        Self {
            version: KdbxVersion::V4_1,
            cipher: KdbxCipher::Aes256,
            compression: Compression::Gzip,
            kdf: None,
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

/// A KDBX KDF result cached only for the lifetime of an unlocked session or
/// inside a platform-protected unlock blob. It intentionally exposes no
/// `Debug` or `Clone` implementation.
pub struct TransformedKey(Zeroizing<[u8; 32]>);

impl TransformedKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn required_version(vault: &Vault) -> KdbxVersion {
    if custom_data_requires_41(&vault.meta_custom_data_blocks, &vault.meta_custom_data)
        || vault.custom_icons.iter().any(|icon| {
            icon.name.as_deref().is_some_and(|name| !name.is_empty())
                || icon.last_modified.is_some()
        })
        || group_requires_41(&vault.root)
    {
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

pub fn derive_transformed_key(
    bytes: &[u8],
    composite_key: &CompositeKey,
) -> Result<TransformedKey> {
    derive_transformed_key_with_policy(
        bytes,
        composite_key,
        &ExternalKdfPolicy::Mobile,
        ExternalKdfConfirmation::Unconfirmed,
    )
}

pub fn derive_transformed_key_with_policy(
    bytes: &[u8],
    composite_key: &CompositeKey,
    policy: &dyn KdfPolicyEvaluator,
    confirmation: ExternalKdfConfirmation,
) -> Result<TransformedKey> {
    if !matches!(
        detect_file_version(bytes)?,
        KdbxVersion::V4_0 | KdbxVersion::V4_1
    ) {
        return Err(KdbxError::UnsupportedVersion);
    }

    let (header, header_len) = KdbxHeader::decode_with_consumed(bytes)?;
    let mut cursor = Cursor::new(&bytes[header_len..]);
    let stored_header_hash = cursor.read_exact(32)?;
    if sha256_bytes(&bytes[..header_len]).as_slice() != stored_header_hash {
        return Err(KdbxError::HeaderHashMismatch);
    }

    let parameters = ExternalKdfParameters::decode_kdbx4(&header.kdf_parameters)?;
    enforce_external_kdf_policy(&parameters, policy, confirmation)?;
    let kdf = parameters.into_profile();
    let raw_key = Zeroizing::new(composite_key.raw_key()?);
    Ok(TransformedKey::from_bytes(kdf.derive_key(&*raw_key)?))
}

pub fn load_kdbx_with_transformed_key(bytes: &[u8], transformed: &TransformedKey) -> Result<Vault> {
    if !matches!(
        detect_file_version(bytes)?,
        KdbxVersion::V4_0 | KdbxVersion::V4_1
    ) {
        return Err(KdbxError::UnsupportedVersion);
    }

    let (header, header_len) = KdbxHeader::decode_with_consumed(bytes)?;
    let mut cursor = Cursor::new(&bytes[header_len..]);
    let stored_header_hash = cursor.read_exact(32)?.to_vec();
    let stored_header_hmac = cursor.read_exact(32)?.to_vec();
    let payload_bytes = cursor.read_remaining().to_vec();

    let header_bytes = &bytes[..header_len];
    if sha256_bytes(header_bytes).as_slice() != stored_header_hash.as_slice() {
        return Err(KdbxError::HeaderHashMismatch);
    }

    let encryption_key = sha256_seeded(&header.master_seed, transformed.as_bytes());
    let mac_seed = mac_seed(&header.master_seed, transformed.as_bytes());
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
    parse_xml(
        &payload[consumed..],
        &header,
        inner_algorithm,
        &inner_key,
        &binaries,
    )
}

pub fn save_kdbx(
    vault: &Vault,
    composite_key: &CompositeKey,
    profile: &SaveProfile,
) -> Result<Vec<u8>> {
    let (header, kdf) = prepare_save(vault, profile)?;
    let raw_key = Zeroizing::new(composite_key.raw_key()?);
    let transformed = TransformedKey::from_bytes(kdf.derive_key(&*raw_key)?);
    encode_kdbx_with_transformed_key(vault, profile, header, &transformed)
}

pub fn save_kdbx_with_transformed_key(
    vault: &Vault,
    transformed: &TransformedKey,
    profile: &SaveProfile,
) -> Result<Vec<u8>> {
    if profile.kdf.is_some() || vault.kdf_parameters.is_none() {
        return Err(KdbxError::InvalidValue);
    }
    let (header, _) = prepare_save(vault, profile)?;
    encode_kdbx_with_transformed_key(vault, profile, header, transformed)
}

fn prepare_save(vault: &Vault, profile: &SaveProfile) -> Result<(KdbxHeader, KdfProfile)> {
    if !matches!(profile.version, KdbxVersion::V4_0 | KdbxVersion::V4_1) {
        return Err(KdbxError::UnsupportedVersion);
    }
    validate_vault_model(vault)?;
    if required_version(vault) == KdbxVersion::V4_1 && profile.version != KdbxVersion::V4_1 {
        return Err(KdbxError::UnsupportedVersion);
    }

    let mut header = KdbxHeader::new(profile.version, profile.cipher);
    header.compression = profile.compression;
    header.master_seed = random_array_32();
    header.encryption_iv = random_iv(profile.cipher);
    let (kdf, kdf_parameters) = save_kdf_state(vault, profile.kdf.as_ref())?;
    header.kdf_parameters = kdf_parameters;
    for (key, value) in &vault.public_custom_data {
        header
            .public_custom_data
            .insert(key.clone(), VariantValue::Bytes(value.clone()));
    }
    Ok((header, kdf))
}

fn encode_kdbx_with_transformed_key(
    vault: &Vault,
    profile: &SaveProfile,
    header: KdbxHeader,
    transformed: &TransformedKey,
) -> Result<Vec<u8>> {
    let encryption_key = sha256_seeded(&header.master_seed, transformed.as_bytes());
    let mac_seed = mac_seed(&header.master_seed, transformed.as_bytes());

    let mut binaries = Vec::new();
    let attachment_refs = collect_attachment_refs(vault, &mut binaries)?;
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
    load_kdbx_with_policy(
        bytes,
        composite_key,
        &ExternalKdfPolicy::Mobile,
        ExternalKdfConfirmation::Unconfirmed,
    )
}

pub fn load_kdbx_with_policy(
    bytes: &[u8],
    composite_key: &CompositeKey,
    policy: &dyn KdfPolicyEvaluator,
    confirmation: ExternalKdfConfirmation,
) -> Result<Vault> {
    match detect_file_version(bytes)? {
        KdbxVersion::V2_0 | KdbxVersion::V3_0 | KdbxVersion::V3_1 => {
            load_kdbx3(bytes, composite_key, policy, confirmation)
        }
        KdbxVersion::V4_0 | KdbxVersion::V4_1 => {
            load_kdbx4(bytes, composite_key, policy, confirmation)
        }
    }
}

fn load_kdbx4(
    bytes: &[u8],
    composite_key: &CompositeKey,
    policy: &dyn KdfPolicyEvaluator,
    confirmation: ExternalKdfConfirmation,
) -> Result<Vault> {
    let transformed =
        derive_transformed_key_with_policy(bytes, composite_key, policy, confirmation)?;
    load_kdbx_with_transformed_key(bytes, &transformed)
}

fn load_kdbx3(
    bytes: &[u8],
    composite_key: &CompositeKey,
    policy: &dyn KdfPolicyEvaluator,
    confirmation: ExternalKdfConfirmation,
) -> Result<Vault> {
    let (header, header_len) = decode_kdbx3_header(bytes)?;
    let parameters =
        ExternalKdfParameters::decode_kdbx3(header.transform_rounds, header.transform_seed)?;
    enforce_external_kdf_policy(&parameters, policy, confirmation)?;
    let kdf = parameters.into_profile();
    let raw_key = composite_key.raw_key()?;
    let transformed = kdf.derive_key(&raw_key)?;
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
        VariantValue::Unknown { type_tag, bytes } => (*type_tag, bytes.clone()),
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
        type_tag => VariantValue::Unknown {
            type_tag,
            bytes: bytes.to_vec(),
        },
    })
}

fn build_kdf_profile(profile: &SaveKdf) -> KdfProfile {
    match profile {
        SaveKdf::AesKdbx4 { rounds } => KdfProfile::AesKdbx4 {
            rounds: *rounds,
            salt: random_array_32(),
        },
        SaveKdf::Argon2d {
            iterations,
            memory_kib,
            parallelism,
        } => KdfProfile::Argon2d {
            iterations: *iterations,
            memory_kib: *memory_kib,
            parallelism: *parallelism,
            salt: random_bytes(32),
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

pub fn retained_or_recommended_save_kdf(vault: &Vault) -> Result<SaveKdf> {
    let Some(encoded) = &vault.kdf_parameters else {
        return Ok(SaveKdf::recommended());
    };
    let parameters = ExternalKdfParameters::decode_kdbx4(&VariantDictionary::decode(encoded)?)?;
    match parameters.algorithm() {
        ExternalKdfAlgorithm::AesKdbx3 | ExternalKdfAlgorithm::AesKdbx4 => Ok(SaveKdf::AesKdbx4 {
            rounds: parameters.rounds().ok_or(KdbxError::UnsupportedKdf)?,
        }),
        ExternalKdfAlgorithm::Argon2d | ExternalKdfAlgorithm::Argon2id => {
            let (iterations, memory_kib, parallelism) = parameters
                .argon2_work_factors()
                .ok_or(KdbxError::UnsupportedKdf)?;
            if parameters.algorithm() == ExternalKdfAlgorithm::Argon2d {
                Ok(SaveKdf::Argon2d {
                    iterations,
                    memory_kib,
                    parallelism,
                })
            } else {
                Ok(SaveKdf::Argon2id {
                    iterations,
                    memory_kib,
                    parallelism,
                })
            }
        }
    }
}

fn save_kdf_state(
    vault: &Vault,
    requested: Option<&SaveKdf>,
) -> Result<(KdfProfile, VariantDictionary)> {
    if let Some(requested) = requested {
        let profile = build_kdf_profile(requested);
        let parameters = kdf_to_variant_dict(&profile);
        return Ok((profile, parameters));
    }
    if let Some(encoded) = &vault.kdf_parameters {
        let parameters = VariantDictionary::decode(encoded)?;
        let profile = ExternalKdfParameters::decode_kdbx4(&parameters)?.into_profile();
        return Ok((profile, parameters));
    }

    let profile = build_kdf_profile(&SaveKdf::recommended());
    let parameters = kdf_to_variant_dict(&profile);
    Ok((profile, parameters))
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
        KdfProfile::Argon2d {
            iterations,
            memory_kib,
            parallelism,
            salt,
        }
        | KdfProfile::Argon2id {
            iterations,
            memory_kib,
            parallelism,
            salt,
        } => {
            dict.insert(
                "$UUID",
                VariantValue::Bytes(
                    match kdf {
                        KdfProfile::Argon2d { .. } => KDF_ARGON2D_UUID,
                        KdfProfile::Argon2id { .. } => KDF_ARGON2ID_UUID,
                        _ => unreachable!("matched an Argon2 KDF"),
                    }
                    .into_bytes()
                    .to_vec(),
                ),
            );
            dict.insert("V", VariantValue::UInt32(0x13));
            dict.insert("I", VariantValue::UInt64(u64::from(*iterations)));
            dict.insert("M", VariantValue::UInt64(u64::from(*memory_kib) * 1024));
            dict.insert("P", VariantValue::UInt32(*parallelism));
            dict.insert("S", VariantValue::Bytes(salt.clone()));
        }
        KdfProfile::AesKdbx3 { .. } => {}
    }
    dict
}

#[cfg(test)]
fn kdf_from_variant_dict(dict: &VariantDictionary) -> Result<KdfProfile> {
    Ok(ExternalKdfParameters::decode_kdbx4(dict)?.into_profile())
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
        payload.extend(binary.data.as_bytes());
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
    let mut content_pool = AttachmentContentPool::new();

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
                if *flag & !0x01 != 0 {
                    return Err(KdbxError::InvalidValue);
                }
                binaries.push(InnerBinary {
                    protect_in_memory: *flag & 0x01 == 0x01,
                    data: content_pool.intern(bytes)?,
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
    if !matches!(version, KdbxVersion::V4_0 | KdbxVersion::V4_1) {
        return Err(KdbxError::UnsupportedVersion);
    }

    let mut guarded_root = ZeroizingXmlElement::new("KeePassFile");
    let root = guarded_root.element_mut();

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
                vault
                    .meta_raw_state
                    .memory_protection_auto_enable_visual_hiding_raw
                    .as_deref(),
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
    validate_custom_data_block_positions(&meta.children, &vault.meta_custom_data_blocks)?;
    append_opaque_xml(&mut meta, &vault.meta_opaque_xml)?;
    root.children.push(XMLNode::Element(meta));

    let mut root_node = Element::new("Root");
    let mut root_group =
        ZeroizingXmlElement::from_element(group_to_xml(&vault.root, attachment_refs, version)?);
    let mut protected = ProtectedStream::new_chacha(inner_key)?;
    protect_xml_group(root_group.element_mut(), &mut protected)?;
    root_node
        .children
        .push(XMLNode::Element(root_group.into_inner()));
    if !vault.deleted_objects.is_empty() || vault.root_raw_state.has_deleted_objects_node {
        root_node
            .children
            .push(XMLNode::Element(deleted_objects_to_xml(
                &vault.deleted_objects,
                version,
            )));
    }
    reorder_known_xml_nodes(&mut root_node.children, &vault.root_raw_state.node_order);
    append_opaque_xml(&mut root_node, &vault.root_opaque_xml)?;
    root.children.push(XMLNode::Element(root_node));

    validate_xml_text(root)?;
    let mut bytes = Vec::new();
    root.write(&mut bytes)
        .map_err(|error| KdbxError::Xml(error.to_string()))?;
    Ok(bytes)
}

fn group_to_xml(
    group: &Group,
    attachment_refs: &HashMap<(usize, String), usize>,
    version: KdbxVersion,
) -> Result<Element> {
    let mut guarded = ZeroizingXmlElement::new("Group");
    let element = guarded.element_mut();
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
    if let Some(enable_auto_type_raw) = &group.raw_state.enable_auto_type_raw {
        element.children.push(XMLNode::Element(text_element(
            "EnableAutoType",
            enable_auto_type_raw,
        )));
    } else if let Some(enable_auto_type) = group.flags.enable_auto_type {
        element.children.push(XMLNode::Element(text_element(
            "EnableAutoType",
            bool_text(enable_auto_type),
        )));
    } else {
        element
            .children
            .push(XMLNode::Element(text_element("EnableAutoType", "null")));
    }
    if let Some(enable_searching_raw) = &group.raw_state.enable_searching_raw {
        element.children.push(XMLNode::Element(text_element(
            "EnableSearching",
            enable_searching_raw,
        )));
    } else if let Some(enable_searching) = group.flags.enable_searching {
        element.children.push(XMLNode::Element(text_element(
            "EnableSearching",
            bool_text(enable_searching),
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
    }
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
            true,
            version,
        )?));
    }
    for child in &group.children {
        element.children.push(XMLNode::Element(group_to_xml(
            child,
            attachment_refs,
            version,
        )?));
    }
    append_custom_data_blocks(
        element,
        &group.custom_data_blocks,
        &group.custom_data,
        true,
        version,
    )?;
    reorder_known_xml_nodes(&mut element.children, &group.raw_state.node_order);
    validate_custom_data_block_positions(&element.children, &group.custom_data_blocks)?;
    append_opaque_xml(element, &group.opaque_xml)?;
    Ok(guarded.into_inner())
}

fn entry_to_xml(
    entry: &Entry,
    attachment_refs: &HashMap<(usize, String), usize>,
    include_history: bool,
    version: KdbxVersion,
) -> Result<Element> {
    let mut guarded = ZeroizingXmlElement::new("Entry");
    let element = guarded.element_mut();
    element.children.push(XMLNode::Element(text_element(
        "UUID",
        &encode_uuid(entry.id),
    )));
    if let Some(icon_id) = entry.icon_id {
        element.children.push(XMLNode::Element(text_element(
            "IconID",
            &icon_id.to_string(),
        )));
    }
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
    if let Some(tags_raw) = &entry.raw_state.tags_raw {
        element
            .children
            .push(XMLNode::Element(text_element("Tags", tags_raw)));
    } else if !entry.tags.is_empty() {
        element.children.push(XMLNode::Element(text_element(
            "Tags",
            &entry.tags.iter().cloned().collect::<Vec<_>>().join(";"),
        )));
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
        if let Some(quality_check_raw) = &entry.raw_state.quality_check_raw {
            element.children.push(XMLNode::Element(text_element(
                "QualityCheck",
                quality_check_raw,
            )));
        } else if entry.exclude_from_reports {
            element
                .children
                .push(XMLNode::Element(text_element("QualityCheck", "False")));
        }
    }

    element
        .children
        .push(XMLNode::Element(entry_times_to_xml(entry, version)));

    let materialized = materialize_entry_persistent_attributes(entry);
    let mut fields: BTreeMap<&str, (&str, bool)> = materialized
        .iter()
        .map(|(key, field)| (key, (field.value(), field.protected())))
        .collect();
    fields.insert(
        "Title",
        (&entry.title, entry.field_protection.protect_title),
    );
    fields.insert(
        "UserName",
        (&entry.username, entry.field_protection.protect_username),
    );
    fields.insert(
        "Password",
        (&entry.password, entry.field_protection.protect_password),
    );
    fields.insert("URL", (&entry.url, entry.field_protection.protect_url));
    fields.insert(
        "Notes",
        (&entry.notes, entry.field_protection.protect_notes),
    );
    let mut ordered_fields = Vec::with_capacity(fields.len());
    for key in &entry.raw_state.string_order {
        if let Some(field) = fields.remove(key.as_str()) {
            ordered_fields.push((key.as_str(), field));
        }
    }
    ordered_fields.extend(fields);
    for (key, (value, protected)) in ordered_fields {
        element
            .children
            .push(XMLNode::Element(string_field_to_xml(key, value, protected)));
    }

    let mut ordered_attachments = Vec::with_capacity(entry.attachments.len());
    let mut retained_names = BTreeSet::new();
    for name in &entry.raw_state.binary_order {
        if let Some(attachment) = entry.attachments.get(name) {
            retained_names.insert(name.as_str());
            ordered_attachments.push((name.as_str(), attachment));
        }
    }
    ordered_attachments.extend(
        entry
            .attachments
            .iter()
            .filter(|(name, _)| !retained_names.contains(name.as_str()))
            .map(|(name, attachment)| (name.as_str(), attachment)),
    );
    for (name, _) in ordered_attachments {
        let mut binary = Element::new("Binary");
        binary
            .children
            .push(XMLNode::Element(text_element("Key", name)));
        let mut value = Element::new("Value");
        value.attributes.insert(
            "Ref".into(),
            attachment_refs[&(entry_ref_key(entry), name.to_owned())].to_string(),
        );
        binary.children.push(XMLNode::Element(value));
        element.children.push(XMLNode::Element(binary));
    }

    if let Some(auto_type) = &entry.auto_type {
        element
            .children
            .push(XMLNode::Element(auto_type_to_xml(auto_type)));
    }
    if should_emit_history(entry, include_history) {
        let mut history = Element::new("History");
        for old_entry in &entry.history {
            history.children.push(XMLNode::Element(entry_to_xml(
                old_entry,
                attachment_refs,
                false,
                version,
            )?));
        }
        element.children.push(XMLNode::Element(history));
    }

    append_custom_data_blocks(
        element,
        &entry.custom_data_blocks,
        &entry.custom_data,
        true,
        version,
    )?;

    reorder_known_xml_nodes(&mut element.children, &entry.raw_state.node_order);
    validate_custom_data_block_positions(&element.children, &entry.custom_data_blocks)?;
    append_opaque_xml(element, &entry.opaque_xml)?;
    Ok(guarded.into_inner())
}

fn is_standard_entry_field_name(name: &str) -> bool {
    matches!(name, "Title" | "UserName" | "Password" | "URL" | "Notes")
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
        if include_item_times
            && version == KdbxVersion::V4_1
            && let Some(last_modified) = custom_item.last_modified
        {
            item.children.push(XMLNode::Element(text_element(
                "LastModificationTime",
                &datetime_text(version, last_modified),
            )));
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

    if merge_custom_data_blocks(blocks) != *merged {
        return Err(KdbxError::InvalidValue);
    }

    let mut minimum_insertion_index = 0;
    for block in blocks {
        let node = XMLNode::Element(custom_data_block_to_xml(block, include_item_times, version));
        let desired_index = match block.after.as_ref() {
            Some(anchor) => xml_anchor_index(&target.children, anchor)
                .map(|anchor_index| anchor_index + 1)
                .ok_or(KdbxError::InvalidValue)?,
            None => 0,
        };
        if desired_index < minimum_insertion_index {
            return Err(KdbxError::InvalidValue);
        }
        let insertion_index = desired_index.min(target.children.len());
        target.children.insert(insertion_index, node);
        minimum_insertion_index = insertion_index + 1;
    }
    Ok(())
}

fn xml_anchor_index(children: &[XMLNode], anchor: &OpaqueXmlAnchor) -> Option<usize> {
    let mut occurrence = 0;
    children.iter().position(|child| {
        let XMLNode::Element(element) = child else {
            return false;
        };
        if element.name != anchor.element_name {
            return false;
        }
        occurrence += 1;
        occurrence == anchor.occurrence
    })
}

fn validate_custom_data_block_positions(
    children: &[XMLNode],
    blocks: &[CustomDataBlock],
) -> Result<()> {
    if blocks.is_empty() {
        return Ok(());
    }
    let mut counts = HashMap::<&str, usize>::new();
    let mut predecessor = None;
    let mut block_index = 0;
    for child in children {
        let XMLNode::Element(element) = child else {
            continue;
        };
        if element.name == "CustomData" {
            let block = blocks.get(block_index).ok_or(KdbxError::InvalidValue)?;
            if block.after != predecessor {
                return Err(KdbxError::InvalidValue);
            }
            block_index += 1;
        }
        let occurrence = counts.entry(element.name.as_str()).or_insert(0);
        *occurrence += 1;
        predecessor = Some(OpaqueXmlAnchor {
            element_name: element.name.clone(),
            occurrence: *occurrence,
        });
    }
    if block_index != blocks.len() {
        return Err(KdbxError::InvalidValue);
    }
    Ok(())
}

fn reorder_known_xml_nodes(children: &mut Vec<XMLNode>, original_order: &[String]) {
    if original_order.is_empty() {
        return;
    }

    let original_children = std::mem::take(children);
    let mut canonical_nodes = Vec::<Option<(String, XMLNode)>>::new();
    let mut indices_by_name = HashMap::<String, VecDeque<usize>>::new();
    for child in original_children {
        let XMLNode::Element(element) = child else {
            continue;
        };
        let name = element.name.clone();
        let canonical_index = canonical_nodes.len();
        canonical_nodes.push(Some((name.clone(), XMLNode::Element(element))));
        indices_by_name
            .entry(name)
            .or_default()
            .push_back(canonical_index);
    }

    let mut ordered_nodes = Vec::<(usize, String, XMLNode)>::new();

    for name in original_order {
        let Some(canonical_index) = indices_by_name.get_mut(name).and_then(VecDeque::pop_front)
        else {
            continue;
        };
        let (node_name, node) = canonical_nodes[canonical_index]
            .take()
            .expect("queued canonical node");
        ordered_nodes.push((canonical_index, node_name, node));
    }

    let mut base_position_by_canonical_index = vec![None; canonical_nodes.len()];
    let mut last_base_position_by_name = HashMap::<String, usize>::new();
    for (base_position, (canonical_index, name, _)) in ordered_nodes.iter().enumerate() {
        base_position_by_canonical_index[*canonical_index] = Some(base_position);
        last_base_position_by_name.insert(name.clone(), base_position);
    }

    let mut previous_base_position = vec![None; canonical_nodes.len()];
    let mut previous = None;
    for canonical_index in 0..canonical_nodes.len() {
        previous_base_position[canonical_index] = previous;
        if let Some(base_position) = base_position_by_canonical_index[canonical_index] {
            previous = Some(base_position);
        }
    }
    let mut next_base_position = vec![None; canonical_nodes.len()];
    let mut next = None;
    for canonical_index in (0..canonical_nodes.len()).rev() {
        next_base_position[canonical_index] = next;
        if let Some(base_position) = base_position_by_canonical_index[canonical_index] {
            next = Some(base_position);
        }
    }

    let mut leftover_by_name = HashMap::<String, Vec<(usize, XMLNode)>>::new();
    for (canonical_index, slot) in canonical_nodes.into_iter().enumerate() {
        if let Some((name, node)) = slot {
            leftover_by_name
                .entry(name)
                .or_default()
                .push((canonical_index, node));
        }
    }

    let mut gap_nodes = (0..=ordered_nodes.len())
        .map(|_| Vec::<(usize, Vec<XMLNode>)>::new())
        .collect::<Vec<_>>();
    for (name, nodes) in leftover_by_name {
        let first_canonical_index = nodes[0].0;
        let gap = last_base_position_by_name
            .get(&name)
            .map(|position| position + 1)
            .or_else(|| previous_base_position[first_canonical_index].map(|position| position + 1))
            .or(next_base_position[first_canonical_index])
            .unwrap_or(0);
        gap_nodes[gap].push((
            first_canonical_index,
            nodes.into_iter().map(|(_, node)| node).collect(),
        ));
    }

    let mut ordered_nodes = ordered_nodes
        .into_iter()
        .map(|(_, _, node)| Some(node))
        .collect::<Vec<_>>();
    let mut rebuilt = Vec::with_capacity(
        ordered_nodes.len()
            + gap_nodes
                .iter()
                .flat_map(|groups| groups.iter())
                .map(|(_, nodes)| nodes.len())
                .sum::<usize>(),
    );
    for (gap, groups) in gap_nodes.iter_mut().enumerate() {
        groups.sort_by_key(|(canonical_index, _)| *canonical_index);
        for (_, nodes) in groups.drain(..) {
            rebuilt.extend(nodes);
        }
        if gap < ordered_nodes.len() {
            rebuilt.push(ordered_nodes[gap].take().expect("ordered canonical node"));
        }
    }
    *children = rebuilt;
}

fn string_field_to_xml(key: &str, field_value: &str, protected: bool) -> Element {
    let mut string = Element::new("String");
    string
        .children
        .push(XMLNode::Element(text_element("Key", key)));
    let mut value = Element::new("Value");
    if protected {
        value.attributes.insert("Protected".into(), "True".into());
    }
    value.children.push(XMLNode::Text(field_value.to_owned()));
    string.children.push(XMLNode::Element(value));
    string
}

struct ZeroizingXmlElement {
    element: Option<Element>,
}

impl ZeroizingXmlElement {
    fn new(name: &str) -> Self {
        Self::from_element(Element::new(name))
    }

    fn from_element(element: Element) -> Self {
        Self {
            element: Some(element),
        }
    }

    fn element_mut(&mut self) -> &mut Element {
        self.element.as_mut().expect("live XML guard")
    }

    fn into_inner(mut self) -> Element {
        self.element.take().expect("live XML guard")
    }
}

impl Drop for ZeroizingXmlElement {
    fn drop(&mut self) {
        if let Some(element) = self.element.as_mut() {
            zeroize_xml_text(element);
        }
    }
}

fn zeroize_xml_text(element: &mut Element) {
    for child in &mut element.children {
        match child {
            XMLNode::Element(child) => zeroize_xml_text(child),
            XMLNode::Text(text) | XMLNode::CData(text) => text.zeroize(),
            _ => {}
        }
    }
}

fn protect_xml_group(group: &mut Element, protected: &mut ProtectedStream) -> Result<()> {
    for child in &mut group.children {
        let XMLNode::Element(child) = child else {
            continue;
        };
        match child.name.as_str() {
            "Entry" => protect_xml_entry(child, protected)?,
            "Group" => protect_xml_group(child, protected)?,
            _ => {}
        }
    }
    Ok(())
}

fn protect_xml_entry(entry: &mut Element, protected: &mut ProtectedStream) -> Result<()> {
    for child in &mut entry.children {
        let XMLNode::Element(child) = child else {
            continue;
        };
        match child.name.as_str() {
            "String" => protect_xml_string(child, protected)?,
            "History" => {
                for history_child in &mut child.children {
                    if let XMLNode::Element(history_entry) = history_child
                        && history_entry.name == "Entry"
                    {
                        protect_xml_entry(history_entry, protected)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn protect_xml_string(string: &mut Element, protected: &mut ProtectedStream) -> Result<()> {
    let value = string
        .get_mut_child("Value")
        .ok_or(KdbxError::InvalidValue)?;
    let is_protected = value
        .attributes
        .get("Protected")
        .map(|value| parse_bool_text(value))
        .unwrap_or(false);
    if !is_protected {
        return Ok(());
    }

    let mut bytes = Zeroizing::new(
        value
            .get_text()
            .map(|text| text.as_bytes().to_vec())
            .unwrap_or_default(),
    );
    protected.apply(bytes.as_mut_slice());
    let encoded = STANDARD.encode(bytes.as_slice());
    for child in &mut value.children {
        if let XMLNode::Text(text) | XMLNode::CData(text) = child {
            text.zeroize();
        }
    }
    value.children.clear();
    value.children.push(XMLNode::Text(encoded));
    Ok(())
}

fn validate_xml_model_shape(root: &Element) -> Result<()> {
    if root.name != "KeePassFile" {
        return Err(KdbxError::InvalidValue);
    }
    validate_only_element_children(root, &["Meta", "Root"])?;
    validate_child_multiplicity(root, &["Meta", "Root"], &["Meta", "Root"])?;
    let meta = root.get_child("Meta").ok_or(KdbxError::InvalidValue)?;
    let root_node = root.get_child("Root").ok_or(KdbxError::InvalidValue)?;
    validate_meta_shape(meta)?;
    validate_root_shape(root_node)
}

fn validate_meta_shape(meta: &Element) -> Result<()> {
    const SINGLETONS: &[&str] = &[
        "Generator",
        "SettingsChanged",
        "DatabaseName",
        "DatabaseNameChanged",
        "HeaderHash",
        "Binaries",
        "DatabaseDescription",
        "DatabaseDescriptionChanged",
        "DefaultUserName",
        "DefaultUserNameChanged",
        "MaintenanceHistoryDays",
        "Color",
        "MemoryProtection",
        "CustomIcons",
        "RecycleBinEnabled",
        "RecycleBinUUID",
        "RecycleBinChanged",
        "EntryTemplatesGroup",
        "EntryTemplatesGroupChanged",
        "MasterKeyChanged",
        "MasterKeyChangeRec",
        "MasterKeyChangeForce",
        "MasterKeyChangeForceOnce",
        "LastSelectedGroup",
        "LastTopVisibleGroup",
        "HistoryMaxItems",
        "HistoryMaxSize",
    ];
    validate_child_multiplicity(meta, SINGLETONS, &[])?;
    validate_known_scalar_children(
        meta,
        SINGLETONS,
        &["MemoryProtection", "CustomIcons", "Binaries"],
    )?;
    for child in element_children(meta) {
        match child.name.as_str() {
            "MemoryProtection" => {
                const FIELDS: &[&str] = &[
                    "ProtectTitle",
                    "ProtectUserName",
                    "ProtectPassword",
                    "ProtectURL",
                    "ProtectNotes",
                    "AutoEnableVisualHiding",
                ];
                validate_only_singletons(child, FIELDS, &[])?;
                validate_known_scalar_children(child, FIELDS, &[])?;
            }
            "CustomIcons" => validate_custom_icons_shape(child)?,
            "Binaries" => validate_legacy_binaries_shape(child)?,
            "CustomData" => validate_custom_data_shape(child)?,
            _ => {}
        }
    }
    if let Some(memory_protection) = meta.get_child("MemoryProtection") {
        validate_typed_children(
            memory_protection,
            &[
                "ProtectTitle",
                "ProtectUserName",
                "ProtectPassword",
                "ProtectURL",
                "ProtectNotes",
                "AutoEnableVisualHiding",
            ],
            |value| parse_bool_text_strict(value).is_some(),
        )?;
    }
    validate_typed_children(
        meta,
        &[
            "SettingsChanged",
            "DatabaseNameChanged",
            "DatabaseDescriptionChanged",
            "DefaultUserNameChanged",
            "RecycleBinChanged",
            "EntryTemplatesGroupChanged",
            "MasterKeyChanged",
        ],
        |value| parse_datetime_i64(value).is_some(),
    )?;
    validate_typed_children(
        meta,
        &["RecycleBinEnabled", "MasterKeyChangeForceOnce"],
        |value| parse_bool_text_strict(value).is_some(),
    )?;
    validate_typed_children(
        meta,
        &["MaintenanceHistoryDays", "HistoryMaxItems"],
        |value| value.trim().parse::<i32>().is_ok(),
    )?;
    validate_typed_children(
        meta,
        &[
            "MasterKeyChangeRec",
            "MasterKeyChangeForce",
            "HistoryMaxSize",
        ],
        |value| value.trim().parse::<i64>().is_ok(),
    )?;
    validate_typed_children(
        meta,
        &[
            "RecycleBinUUID",
            "EntryTemplatesGroup",
            "LastSelectedGroup",
            "LastTopVisibleGroup",
        ],
        |value| parse_optional_uuid(value).is_ok(),
    )?;
    Ok(())
}

fn validate_root_shape(root: &Element) -> Result<()> {
    validate_child_multiplicity(root, &["Group", "DeletedObjects"], &["Group"])?;
    let group = root.get_child("Group").ok_or(KdbxError::InvalidValue)?;
    validate_group_shape(group)?;
    if let Some(deleted) = root.get_child("DeletedObjects") {
        validate_deleted_objects_shape(deleted)?;
    }
    Ok(())
}

fn validate_group_shape(group: &Element) -> Result<()> {
    const SINGLETONS: &[&str] = &[
        "UUID",
        "Name",
        "Notes",
        "IconID",
        "CustomIconUUID",
        "Tags",
        "Times",
        "IsExpanded",
        "DefaultAutoTypeSequence",
        "EnableAutoType",
        "EnableSearching",
        "LastTopVisibleEntry",
        "PreviousParentGroup",
    ];
    validate_child_multiplicity(group, SINGLETONS, &["UUID"])?;
    validate_known_scalar_children(group, SINGLETONS, &["Times"])?;
    for child in element_children(group) {
        match child.name.as_str() {
            "Times" => validate_times_shape(child)?,
            "CustomData" => validate_custom_data_shape(child)?,
            "Entry" => validate_entry_shape(child)?,
            "Group" => validate_group_shape(child)?,
            _ => {}
        }
    }
    validate_typed_children(group, &["UUID"], |value| {
        decode_uuid(value.trim()).is_ok_and(|uuid| !uuid.is_nil())
    })?;
    validate_typed_children(group, &["IconID"], |value| {
        value.trim().parse::<u32>().is_ok()
    })?;
    validate_typed_children(
        group,
        &[
            "CustomIconUUID",
            "LastTopVisibleEntry",
            "PreviousParentGroup",
        ],
        |value| parse_optional_uuid(value).is_ok(),
    )?;
    validate_typed_children(group, &["IsExpanded"], |value| {
        parse_bool_text_strict(value).is_some()
    })?;
    validate_typed_children(group, &["EnableAutoType", "EnableSearching"], |value| {
        parse_nullable_bool_strict(value).is_some()
    })?;
    Ok(())
}

fn validate_entry_shape(entry: &Element) -> Result<()> {
    const SINGLETONS: &[&str] = &[
        "UUID",
        "IconID",
        "CustomIconUUID",
        "ForegroundColor",
        "BackgroundColor",
        "OverrideURL",
        "Tags",
        "PreviousParentGroup",
        "QualityCheck",
        "Times",
        "AutoType",
        "History",
    ];
    validate_child_multiplicity(entry, SINGLETONS, &["UUID"])?;
    validate_known_scalar_children(entry, SINGLETONS, &["Times", "AutoType", "History"])?;
    let mut string_keys = BTreeSet::new();
    let mut binary_names = BTreeSet::new();
    for child in element_children(entry) {
        match child.name.as_str() {
            "Times" => validate_times_shape(child)?,
            "String" => {
                validate_only_singletons(child, &["Key", "Value"], &["Key", "Value"])?;
                validate_known_scalar_children(child, &["Key", "Value"], &[])?;
                let key = child_text(child, "Key").ok_or(KdbxError::InvalidValue)?;
                if !string_keys.insert(key) {
                    return Err(KdbxError::InvalidValue);
                }
                let value = child.get_child("Value").ok_or(KdbxError::InvalidValue)?;
                validate_bool_attribute_if_present(value, "Protected")?;
            }
            "Binary" => {
                validate_only_singletons(child, &["Key", "Value"], &["Key", "Value"])?;
                validate_known_scalar_children(child, &["Key", "Value"], &[])?;
                let name = child_text(child, "Key").ok_or(KdbxError::InvalidValue)?;
                if !binary_names.insert(name) {
                    return Err(KdbxError::InvalidValue);
                }
                let value = child.get_child("Value").ok_or(KdbxError::InvalidValue)?;
                validate_bool_attribute_if_present(value, "Protected")?;
                validate_bool_attribute_if_present(value, "Compressed")?;
                if let Some(reference) = value.attributes.get("Ref")
                    && reference.trim().parse::<usize>().is_err()
                {
                    return Err(KdbxError::InvalidValue);
                }
            }
            "AutoType" => validate_auto_type_shape(child)?,
            "CustomData" => validate_custom_data_shape(child)?,
            "History" => {
                validate_only_element_children(child, &["Entry"])?;
                for history_entry in element_children(child) {
                    validate_entry_shape(history_entry)?;
                }
            }
            _ => {}
        }
    }
    validate_typed_children(entry, &["UUID"], |value| {
        decode_uuid(value.trim()).is_ok_and(|uuid| !uuid.is_nil())
    })?;
    validate_typed_children(entry, &["IconID"], |value| {
        value.trim().is_empty() || value.trim().parse::<u32>().is_ok()
    })?;
    validate_typed_children(entry, &["CustomIconUUID", "PreviousParentGroup"], |value| {
        parse_optional_uuid(value).is_ok()
    })?;
    validate_typed_children(entry, &["QualityCheck"], |value| {
        parse_bool_text_strict(value).is_some()
    })?;
    Ok(())
}

fn validate_times_shape(times: &Element) -> Result<()> {
    const FIELDS: &[&str] = &[
        "CreationTime",
        "LastModificationTime",
        "LastAccessTime",
        "ExpiryTime",
        "Expires",
        "UsageCount",
        "LocationChanged",
    ];
    validate_only_singletons(times, FIELDS, &[])?;
    validate_known_scalar_children(times, FIELDS, &[])?;
    validate_typed_children(times, &["CreationTime", "LastModificationTime"], |value| {
        parse_datetime_value(value).is_some()
    })?;
    validate_typed_children(times, &["LastAccessTime", "LocationChanged"], |value| {
        value.trim().is_empty() || parse_datetime_value(value).is_some()
    })?;
    validate_typed_children(times, &["ExpiryTime"], |value| {
        value.trim().is_empty() || parse_datetime_i64(value).is_some()
    })?;
    validate_typed_children(times, &["Expires"], |value| {
        parse_bool_text_strict(value).is_some()
    })?;
    validate_typed_children(times, &["UsageCount"], |value| {
        value.trim().is_empty() || value.trim().parse::<u64>().is_ok()
    })
}

fn validate_auto_type_shape(auto_type: &Element) -> Result<()> {
    const FIELDS: &[&str] = &["Enabled", "DataTransferObfuscation", "DefaultSequence"];
    validate_child_multiplicity(auto_type, FIELDS, &[])?;
    validate_known_scalar_children(auto_type, FIELDS, &[])?;
    for child in element_children(auto_type) {
        match child.name.as_str() {
            "Enabled" | "DataTransferObfuscation" | "DefaultSequence" => {}
            "Association" => {
                const ASSOCIATION_FIELDS: &[&str] = &["Window", "KeystrokeSequence"];
                validate_only_singletons(child, ASSOCIATION_FIELDS, &[])?;
                validate_known_scalar_children(child, ASSOCIATION_FIELDS, &[])?;
            }
            _ => return Err(KdbxError::InvalidValue),
        }
    }
    validate_typed_children(auto_type, &["Enabled"], |value| {
        parse_nullable_bool_strict(value).is_some()
    })?;
    validate_typed_children(auto_type, &["DataTransferObfuscation"], |value| {
        value.trim().is_empty() || value.trim().parse::<i32>().is_ok()
    })?;
    Ok(())
}

fn validate_custom_data_shape(custom_data: &Element) -> Result<()> {
    validate_only_element_children(custom_data, &["Item"])?;
    for item in element_children(custom_data) {
        const FIELDS: &[&str] = &["Key", "Value", "LastModificationTime"];
        validate_only_singletons(item, FIELDS, &["Key"])?;
        validate_known_scalar_children(item, FIELDS, &[])?;
        validate_typed_children(item, &["LastModificationTime"], |value| {
            parse_datetime_i64(value).is_some()
        })?;
    }
    Ok(())
}

fn validate_custom_icons_shape(custom_icons: &Element) -> Result<()> {
    validate_only_element_children(custom_icons, &["Icon"])?;
    for icon in element_children(custom_icons) {
        const FIELDS: &[&str] = &["UUID", "Data", "Name", "LastModificationTime"];
        validate_only_singletons(icon, FIELDS, &["UUID", "Data"])?;
        validate_known_scalar_children(icon, FIELDS, &[])?;
        validate_typed_children(icon, &["UUID"], |value| {
            decode_uuid(value.trim()).is_ok_and(|uuid| !uuid.is_nil())
        })?;
        validate_typed_children(icon, &["Data"], |value| {
            STANDARD.decode(value.trim().as_bytes()).is_ok()
        })?;
        validate_typed_children(icon, &["LastModificationTime"], |value| {
            parse_datetime_i64(value).is_some()
        })?;
    }
    Ok(())
}

fn validate_legacy_binaries_shape(binaries: &Element) -> Result<()> {
    validate_only_element_children(binaries, &["Binary"])?;
    let mut ids = BTreeSet::new();
    for binary in element_children(binaries) {
        validate_scalar_element(binary)?;
        let id = binary.attributes.get("ID").ok_or(KdbxError::InvalidValue)?;
        if !ids.insert(id.as_str()) {
            return Err(KdbxError::InvalidValue);
        }
    }
    Ok(())
}

fn validate_deleted_objects_shape(deleted: &Element) -> Result<()> {
    validate_only_element_children(deleted, &["DeletedObject"])?;
    for object in element_children(deleted) {
        const FIELDS: &[&str] = &["UUID", "DeletionTime"];
        validate_only_singletons(object, FIELDS, FIELDS)?;
        validate_known_scalar_children(object, FIELDS, &[])?;
        validate_typed_children(object, &["UUID"], |value| {
            decode_uuid(value.trim()).is_ok_and(|uuid| !uuid.is_nil())
        })?;
        validate_typed_children(object, &["DeletionTime"], |value| {
            parse_datetime_i64(value).is_some()
        })?;
    }
    Ok(())
}

fn validate_only_singletons(element: &Element, allowed: &[&str], required: &[&str]) -> Result<()> {
    validate_only_element_children(element, allowed)?;
    validate_child_multiplicity(element, allowed, required)
}

fn validate_only_element_children(element: &Element, allowed: &[&str]) -> Result<()> {
    if element_children(element).any(|child| !allowed.contains(&child.name.as_str())) {
        return Err(KdbxError::InvalidValue);
    }
    Ok(())
}

fn validate_child_multiplicity(
    element: &Element,
    singleton_names: &[&str],
    required_names: &[&str],
) -> Result<()> {
    let mut counts = BTreeMap::new();
    for child in element_children(element) {
        if singleton_names.contains(&child.name.as_str()) {
            let count = counts.entry(child.name.as_str()).or_insert(0_usize);
            *count += 1;
            if *count > 1 {
                return Err(KdbxError::InvalidValue);
            }
        }
    }
    if required_names
        .iter()
        .any(|name| counts.get(name).copied().unwrap_or(0) != 1)
    {
        return Err(KdbxError::InvalidValue);
    }
    Ok(())
}

fn validate_known_scalar_children(
    element: &Element,
    known_names: &[&str],
    container_names: &[&str],
) -> Result<()> {
    for child in element_children(element).filter(|child| {
        known_names.contains(&child.name.as_str())
            && !container_names.contains(&child.name.as_str())
    }) {
        validate_scalar_element(child)?;
    }
    Ok(())
}

fn validate_scalar_element(element: &Element) -> Result<()> {
    if element_children(element).next().is_some() {
        return Err(KdbxError::InvalidValue);
    }
    Ok(())
}

fn validate_typed_children(
    element: &Element,
    names: &[&str],
    validate: impl Fn(&str) -> bool,
) -> Result<()> {
    for child in element_children(element).filter(|child| names.contains(&child.name.as_str())) {
        validate_scalar_element(child)?;
        let value = child.get_text().unwrap_or_default();
        if !validate(&value) {
            return Err(KdbxError::InvalidValue);
        }
    }
    Ok(())
}

fn validate_bool_attribute_if_present(element: &Element, name: &str) -> Result<()> {
    if element
        .attributes
        .get(name)
        .is_some_and(|value| parse_bool_text_strict(value).is_none())
    {
        return Err(KdbxError::InvalidValue);
    }
    Ok(())
}

fn element_children(element: &Element) -> impl Iterator<Item = &Element> {
    element.children.iter().filter_map(|child| match child {
        XMLNode::Element(child) => Some(child),
        _ => None,
    })
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
    validate_xml_model_shape(&root)?;
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
    let maintenance_history_days = child_text(&meta, "MaintenanceHistoryDays")
        .and_then(|value| value.trim().parse::<i32>().ok());
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
        child_text(&meta, "MasterKeyChangeRec").and_then(|value| value.trim().parse::<i64>().ok());
    let master_key_change_force = child_text(&meta, "MasterKeyChangeForce")
        .and_then(|value| value.trim().parse::<i64>().ok());
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
        child_text(&meta, "HistoryMaxItems").and_then(|value| value.trim().parse::<i32>().ok());
    let history_max_size =
        child_text(&meta, "HistoryMaxSize").and_then(|value| value.trim().parse::<i64>().ok());
    let (meta_custom_data, mut meta_custom_data_blocks) = parse_meta_custom_data(&meta)?;
    let mut meta_raw_state = MetaRawState {
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
        memory_protection_auto_enable_visual_hiding_raw: child_optional(&meta, "MemoryProtection")
            .and_then(|memory| child_text_preserve_empty(&memory, "AutoEnableVisualHiding")),
        has_custom_icons_node: child_optional(&meta, "CustomIcons").is_some(),
        recycle_bin_group_raw: None,
        entry_templates_group_raw: None,
    };
    let mut meta_opaque_xml = collect_meta_opaque_xml(&meta)?;
    let mut collapsed_optional_nodes = Vec::new();
    for (element_name, value_is_none) in [
        ("Generator", generator.is_none()),
        ("RecycleBinUUID", recycle_bin_group.is_none()),
        ("EntryTemplatesGroup", entry_templates_group.is_none()),
        ("LastSelectedGroup", last_selected_group.is_none()),
        ("LastTopVisibleGroup", last_top_visible_group.is_none()),
    ] {
        if value_is_none && child_optional(&meta, element_name).is_some() {
            collapsed_optional_nodes.push(element_name);
        }
    }
    retarget_removed_scope_nodes(
        &mut meta_custom_data_blocks,
        &mut meta_opaque_xml,
        &mut meta_raw_state.node_order,
        &collapsed_optional_nodes,
    )?;
    let root_group = child(&child(&root, "Root")?, "Group")?;

    let mut protected = ProtectedStream::from_stream(inner_algorithm, inner_key)?;
    let mut content_pool = AttachmentContentPool::new();
    for binary in binaries {
        content_pool.intern_content(&binary.data)?;
    }
    let group = parse_group(&root_group, binaries, &mut content_pool, &mut protected)?;

    let vault = Vault {
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
        kdf_parameters: Some(header.kdf_parameters.encode()?),
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
        meta_opaque_xml,
        root_opaque_xml: collect_root_opaque_xml(&root)?,
    };
    validate_vault_model(&vault)?;
    Ok(vault)
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
    validate_xml_model_shape(&root)?;
    let meta = child(&root, "Meta")?;

    if let Some(header_hash) = child_text(&meta, "HeaderHash")
        && !header_hash.is_empty()
    {
        let expected = STANDARD
            .decode(header_hash.as_bytes())
            .map_err(|_| KdbxError::InvalidValue)?;
        if expected.as_slice() != sha256_bytes(header_bytes).as_slice() {
            return Err(KdbxError::HeaderHashMismatch);
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
    let maintenance_history_days = child_text(&meta, "MaintenanceHistoryDays")
        .and_then(|value| value.trim().parse::<i32>().ok());
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
        child_text(&meta, "MasterKeyChangeRec").and_then(|value| value.trim().parse::<i64>().ok());
    let master_key_change_force = child_text(&meta, "MasterKeyChangeForce")
        .and_then(|value| value.trim().parse::<i64>().ok());
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
        child_text(&meta, "HistoryMaxItems").and_then(|value| value.trim().parse::<i32>().ok());
    let history_max_size =
        child_text(&meta, "HistoryMaxSize").and_then(|value| value.trim().parse::<i64>().ok());
    let (meta_custom_data, mut meta_custom_data_blocks) = parse_meta_custom_data(&meta)?;
    let mut meta_raw_state = MetaRawState {
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
        memory_protection_auto_enable_visual_hiding_raw: child_optional(&meta, "MemoryProtection")
            .and_then(|memory| child_text_preserve_empty(&memory, "AutoEnableVisualHiding")),
        has_custom_icons_node: child_optional(&meta, "CustomIcons").is_some(),
        recycle_bin_group_raw: None,
        entry_templates_group_raw: None,
    };
    let root_group = child(&child(&root, "Root")?, "Group")?;
    let mut protected = ProtectedStream::from_stream(inner_random_stream_id, protected_stream_key)?;
    let binaries = parse_kdbx3_binaries(&meta, &mut protected)?;
    let mut content_pool = AttachmentContentPool::new();
    for binary in binaries.values() {
        content_pool.intern_content(&binary.data)?;
    }
    let group = parse_group(&root_group, &binaries, &mut content_pool, &mut protected)?;
    let deleted_objects = parse_deleted_objects(&root)?;
    let mut meta_opaque_xml = collect_meta_opaque_xml(&meta)?;
    let mut collapsed_optional_nodes = Vec::new();
    for (element_name, value_is_none) in [
        ("Generator", generator.is_none()),
        ("RecycleBinUUID", recycle_bin_group.is_none()),
        ("EntryTemplatesGroup", entry_templates_group.is_none()),
        ("LastSelectedGroup", last_selected_group.is_none()),
        ("LastTopVisibleGroup", last_top_visible_group.is_none()),
    ] {
        if value_is_none && child_optional(&meta, element_name).is_some() {
            collapsed_optional_nodes.push(element_name);
        }
    }
    retarget_removed_scope_nodes(
        &mut meta_custom_data_blocks,
        &mut meta_opaque_xml,
        &mut meta_raw_state.node_order,
        &collapsed_optional_nodes,
    )?;
    retarget_legacy_meta_anchors(
        &mut meta_custom_data_blocks,
        &mut meta_opaque_xml,
        &mut meta_raw_state.node_order,
    )?;

    let vault = Vault {
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
        kdf_parameters: None,
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
        meta_opaque_xml,
        root_opaque_xml: collect_root_opaque_xml(&root)?,
    };
    validate_vault_model(&vault)?;
    Ok(vault)
}

fn retarget_legacy_meta_anchors(
    blocks: &mut [CustomDataBlock],
    opaque: &mut [OpaqueXmlFragment],
    node_order: &mut Vec<String>,
) -> Result<()> {
    retarget_removed_scope_nodes(blocks, opaque, node_order, &["HeaderHash", "Binaries"])
}

fn retarget_removed_scope_nodes(
    blocks: &mut [CustomDataBlock],
    opaque: &mut [OpaqueXmlFragment],
    node_order: &mut Vec<String>,
    removed_names: &[&str],
) -> Result<()> {
    for removed_name in removed_names {
        let original_order = node_order.clone();
        for anchor in blocks
            .iter_mut()
            .map(|block| &mut block.after)
            .chain(opaque.iter_mut().map(|fragment| &mut fragment.after))
        {
            if anchor
                .as_ref()
                .is_some_and(|anchor| anchor.element_name == *removed_name)
            {
                *anchor =
                    predecessor_anchor(&original_order, anchor.as_ref().expect("matching anchor"))?;
            }
        }
        node_order.retain(|name| name != removed_name);
    }
    Ok(())
}

fn predecessor_anchor(
    node_order: &[String],
    removed: &OpaqueXmlAnchor,
) -> Result<Option<OpaqueXmlAnchor>> {
    if removed.occurrence == 0 {
        return Err(KdbxError::InvalidValue);
    }
    let mut occurrence = 0;
    let removed_index = node_order
        .iter()
        .position(|name| {
            if name == &removed.element_name {
                occurrence += 1;
            }
            name == &removed.element_name && occurrence == removed.occurrence
        })
        .ok_or(KdbxError::InvalidValue)?;

    let Some(index) = removed_index.checked_sub(1) else {
        return Ok(None);
    };
    let name = &node_order[index];
    let occurrence = node_order[..=index]
        .iter()
        .filter(|candidate| *candidate == name)
        .count();
    Ok(Some(OpaqueXmlAnchor {
        element_name: name.clone(),
        occurrence,
    }))
}

fn parse_deleted_objects(root: &Element) -> Result<Vec<DeletedObject>> {
    let root_node = child(root, "Root")?;
    let Some(deleted_objects) = child_optional(&root_node, "DeletedObjects") else {
        return Ok(Vec::new());
    };

    let mut objects: BTreeMap<Uuid, i64> = BTreeMap::new();
    for child in &deleted_objects.children {
        let XMLNode::Element(child) = child else {
            continue;
        };
        if child.name != "DeletedObject" {
            return Err(KdbxError::InvalidValue);
        }

        let id = decode_uuid(&child_text(child, "UUID").ok_or(KdbxError::InvalidValue)?)?;
        if id.is_nil() {
            return Err(KdbxError::InvalidValue);
        }
        let deleted_at = child_text(child, "DeletionTime")
            .and_then(|value| parse_datetime_i64(&value))
            .ok_or(KdbxError::InvalidValue)?;
        objects
            .entry(id)
            .and_modify(|current| *current = (*current).max(deleted_at))
            .or_insert(deleted_at);
    }

    Ok(objects
        .into_iter()
        .map(|(id, deleted_at)| DeletedObject { id, deleted_at })
        .collect())
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
            name if meta_known_child_name(name) => {
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
    let mut deleted_objects: Vec<_> = deleted_objects.iter().collect();
    deleted_objects.sort_unstable_by_key(|deleted| *deleted.id.as_bytes());
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
        let element = parse_xml_fragment(&fragment.xml)?;
        if known_child_name_for_scope(&target.name, &element.name) {
            return Err(KdbxError::InvalidValue);
        }
        let node = XMLNode::Element(element);
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
    if !anchored.is_empty() {
        return Err(KdbxError::InvalidValue);
    }
    target.children = rebuilt;
    Ok(())
}

fn known_child_name_for_scope(parent: &str, child: &str) -> bool {
    match parent {
        "Meta" => meta_known_child_name(child),
        "Root" => matches!(child, "Group" | "DeletedObjects"),
        "Group" => group_known_child_name(child),
        "Entry" => entry_known_child_name(child),
        _ => false,
    }
}

fn memory_protection_to_xml(
    memory_protection: MemoryProtection,
    auto_enable_visual_hiding_raw: Option<&str>,
) -> Element {
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
    if let Some(raw) = auto_enable_visual_hiding_raw {
        element.children.push(XMLNode::Element(text_element(
            "AutoEnableVisualHiding",
            raw,
        )));
    }
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
) -> Result<BTreeMap<usize, InnerBinary>> {
    let Some(binaries_element) = child_optional(meta, "Binaries") else {
        return Ok(BTreeMap::new());
    };

    let mut binaries = BTreeMap::new();
    let mut content_pool = AttachmentContentPool::new();
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
            .and_then(|value| value.trim().parse::<usize>().ok())
            .ok_or(KdbxError::InvalidValue)?;
        let compressed = parse_bool_attribute(binary, "Compressed")?;
        let protected_in_memory = parse_bool_attribute(binary, "Protected")?;

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

        let binary = InnerBinary {
            protect_in_memory: protected_in_memory,
            data: content_pool.intern_vec(data)?,
        };
        if binaries.insert(index, binary).is_some() {
            return Err(KdbxError::InvalidValue);
        }
    }

    Ok(binaries)
}

fn parse_group<B: BinaryLookup + ?Sized>(
    element: &Element,
    binaries: &B,
    content_pool: &mut AttachmentContentPool,
    protected: &mut ProtectedStream,
) -> Result<Group> {
    let mut group = Group::new(child_text(element, "Name").unwrap_or_else(|| "Group".into()));
    group.id = decode_uuid(&child_text(element, "UUID").ok_or(KdbxError::InvalidValue)?)?;
    group.notes = child_text(element, "Notes").unwrap_or_default();
    group.icon_id =
        child_text(element, "IconID").and_then(|value| value.trim().parse::<u32>().ok());
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
    group.previous_parent = child_text(element, "PreviousParentGroup")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    group.raw_state = GroupRawState {
        node_order: collect_group_known_node_order(element),
        entry_order: Vec::new(),
        group_order: Vec::new(),
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
        last_top_visible_entry_raw: None,
    };

    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut last_anchor: Option<OpaqueXmlAnchor> = None;
    for child in &element.children {
        if let XMLNode::Element(child) = child {
            match child.name.as_str() {
                "Group" => {
                    let parsed = parse_group(child, binaries, content_pool, protected)?;
                    group.raw_state.group_order.push(parsed.id);
                    group.children.push(parsed);
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                "Entry" => {
                    let parsed = parse_entry(child, binaries, content_pool, protected)?;
                    group.raw_state.entry_order.push(parsed.id);
                    group.entries.push(parsed);
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

    let mut collapsed_optional_nodes = Vec::new();
    if child_optional(element, "CustomIconUUID").is_some() && group.custom_icon_id.is_none() {
        collapsed_optional_nodes.push("CustomIconUUID");
    }
    if child_optional(element, "LastTopVisibleEntry").is_some()
        && group.last_top_visible_entry.is_none()
    {
        collapsed_optional_nodes.push("LastTopVisibleEntry");
    }
    if child_optional(element, "PreviousParentGroup").is_some() && group.previous_parent.is_none() {
        collapsed_optional_nodes.push("PreviousParentGroup");
    }
    retarget_removed_scope_nodes(
        &mut group.custom_data_blocks,
        &mut group.opaque_xml,
        &mut group.raw_state.node_order,
        &collapsed_optional_nodes,
    )?;

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

fn parse_entry<B: BinaryLookup + ?Sized>(
    element: &Element,
    binaries: &B,
    content_pool: &mut AttachmentContentPool,
    protected: &mut ProtectedStream,
) -> Result<Entry> {
    let mut entry = Entry::new("");
    entry.auto_type = None;
    entry.expiry_time = None;
    entry.last_accessed_at = None;
    entry.usage_count = None;
    entry.location_changed_at = Some(0);
    entry.id = decode_uuid(&child_text(element, "UUID").ok_or(KdbxError::InvalidValue)?)?;
    entry.icon_id =
        child_text(element, "IconID").and_then(|value| value.trim().parse::<u32>().ok());
    entry.custom_icon_id = child_text(element, "CustomIconUUID")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
    entry.foreground_color = child_text_preserve_empty(element, "ForegroundColor");
    entry.background_color = child_text_preserve_empty(element, "BackgroundColor");
    entry.override_url = child_text_preserve_empty(element, "OverrideURL");
    let (custom_data, custom_data_blocks) = parse_entry_custom_data(element)?;
    entry.custom_data = custom_data;
    entry.custom_data_blocks = custom_data_blocks;
    let legacy_known_bad = entry
        .custom_data
        .get("KnownBad")
        .and_then(|value| parse_bool_text_strict(value));
    if let Some(tags) = child_text(element, "Tags") {
        entry.tags = parse_tags(&tags);
    }
    entry.previous_parent = child_text(element, "PreviousParentGroup")
        .as_deref()
        .map(parse_optional_uuid)
        .transpose()?
        .flatten();
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
        entry.exclude_from_reports = known_bad;
    }
    entry.raw_state = EntryRawState {
        node_order: collect_entry_known_node_order(element),
        string_order: Vec::new(),
        binary_order: Vec::new(),
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
        entry.expiry_time =
            child_text(&times, "ExpiryTime").and_then(|value| parse_datetime_i64(&value));
        entry.last_accessed_at =
            child_text(&times, "LastAccessTime").and_then(|value| parse_datetime_value(&value));
        entry.usage_count =
            child_text(&times, "UsageCount").and_then(|value| value.trim().parse().ok());
        entry.location_changed_at = child_text(&times, "LocationChanged")
            .and_then(|value| parse_datetime_value(&value))
            .or(Some(0));
    }

    let mut raw_fields = BTreeMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut last_anchor: Option<OpaqueXmlAnchor> = None;
    for child in &element.children {
        if let XMLNode::Element(child) = child {
            match child.name.as_str() {
                "String" => {
                    let (key, field) = parse_string_field(child, protected)?;
                    entry.raw_state.string_order.push(key.clone());
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
                    entry.raw_state.binary_order.push(attachment_name.clone());
                    let value = child_optional(child, "Value").ok_or(KdbxError::InvalidValue)?;
                    let attachment = if let Some(reference) = value.attributes.get("Ref") {
                        if parse_bool_attribute(&value, "Protected")?
                            || parse_bool_attribute(&value, "Compressed")?
                        {
                            return Err(KdbxError::InvalidValue);
                        }
                        let index = reference
                            .trim()
                            .parse::<usize>()
                            .map_err(|_| KdbxError::InvalidValue)?;
                        let binary = binaries.get_binary(index).ok_or(KdbxError::InvalidValue)?;
                        Attachment {
                            name: attachment_name.clone(),
                            data: binary.data.clone(),
                            protect_in_memory: binary.protect_in_memory,
                        }
                    } else {
                        let compressed = parse_bool_attribute(&value, "Compressed")?;
                        let protected_in_memory = parse_bool_attribute(&value, "Protected")?;
                        let encoded = value
                            .get_text()
                            .map(|text| text.to_string())
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
                        Attachment {
                            name: attachment_name.clone(),
                            data: content_pool.intern_vec(data)?,
                            protect_in_memory: protected_in_memory,
                        }
                    };
                    if entry
                        .attachments
                        .insert(attachment_name, attachment)
                        .is_some()
                    {
                        return Err(KdbxError::InvalidValue);
                    }
                    let occurrence = counts.entry(child.name.clone()).or_insert(0);
                    *occurrence += 1;
                    last_anchor = Some(OpaqueXmlAnchor {
                        element_name: child.name.clone(),
                        occurrence: *occurrence,
                    });
                }
                "History" => {
                    for history_child in &child.children {
                        if let XMLNode::Element(history_entry) = history_child
                            && history_entry.name == "Entry"
                        {
                            entry.history.push(parse_entry(
                                history_entry,
                                binaries,
                                content_pool,
                                protected,
                            )?);
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

    let mut collapsed_optional_nodes = Vec::new();
    if child_optional(element, "IconID").is_some() && entry.icon_id.is_none() {
        collapsed_optional_nodes.push("IconID");
    }
    if child_optional(element, "CustomIconUUID").is_some() && entry.custom_icon_id.is_none() {
        collapsed_optional_nodes.push("CustomIconUUID");
    }
    if child_optional(element, "PreviousParentGroup").is_some() && entry.previous_parent.is_none() {
        collapsed_optional_nodes.push("PreviousParentGroup");
    }
    retarget_removed_scope_nodes(
        &mut entry.custom_data_blocks,
        &mut entry.opaque_xml,
        &mut entry.raw_state.node_order,
        &collapsed_optional_nodes,
    )?;

    if legacy_known_bad.is_some() {
        entry.custom_data.remove("KnownBad");
        vaultkern_model::reconcile_custom_data_blocks(
            &mut entry.custom_data_blocks,
            &mut entry.opaque_xml,
            &mut entry.raw_state.node_order,
            &entry.custom_data,
            None,
        );
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

    entry.totp = totp_from_persistent_attributes(&raw_fields);
    entry.passkey = PasskeyRecord::from_attributes(&raw_fields);
    let has_projectable_totp = entry.totp.is_some();
    let has_complete_passkey = entry.passkey.is_some();
    entry.attributes = raw_fields
        .into_iter()
        .filter_map(|(key, mut field)| {
            if !has_projectable_totp && is_totp_secret_persistent_attribute_key(&key) {
                field.protected = true;
            }
            if !has_complete_passkey && PasskeyRecord::is_sensitive_persistent_attribute_key(&key) {
                field.protected = true;
            }
            if has_projectable_totp && is_totp_persistent_attribute_key(&key)
                || has_complete_passkey && PasskeyRecord::is_persistent_attribute_key(&key)
            {
                field.value.zeroize();
                None
            } else {
                Some((key, field))
            }
        })
        .collect();

    Ok(entry)
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
        expiry_time: child_text(element, "ExpiryTime").and_then(|value| parse_datetime_i64(&value)),
        last_accessed_at: child_text(element, "LastAccessTime")
            .and_then(|value| parse_datetime_value(&value)),
        usage_count: child_text(element, "UsageCount").and_then(|value| value.trim().parse().ok()),
        location_changed_at: child_text(element, "LocationChanged")
            .and_then(|value| parse_datetime_value(&value)),
    })
}

fn parse_auto_type(element: &Element) -> AutoTypeConfig {
    let mut auto_type = AutoTypeConfig {
        enabled: child_text(element, "Enabled")
            .as_deref()
            .and_then(parse_nullable_bool),
        obfuscation: child_text(element, "DataTransferObfuscation")
            .and_then(|value| value.trim().parse::<i32>().ok()),
        default_sequence: child_text_preserve_empty(element, "DefaultSequence"),
        ..AutoTypeConfig::default()
    };

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
    let is_protected = parse_bool_attribute(&value_element, "Protected")?;

    if is_protected {
        let mut bytes = Zeroizing::new(
            STANDARD
                .decode(value.as_bytes())
                .map_err(|_| KdbxError::InvalidValue)?,
        );
        protected.apply(bytes.as_mut_slice());
        value =
            String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| KdbxError::InvalidValue)?;
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
) -> Result<HashMap<(usize, String), usize>> {
    let mut refs = HashMap::new();
    let mut dedup = BTreeMap::<(bool, AttachmentContentId), usize>::new();

    fn walk(
        group: &Group,
        refs: &mut HashMap<(usize, String), usize>,
        dedup: &mut BTreeMap<(bool, AttachmentContentId), usize>,
        binaries: &mut Vec<InnerBinary>,
    ) -> Result<()> {
        for entry in &group.entries {
            for (name, attachment) in entry.attachments.iter() {
                if name != &attachment.name {
                    return Err(KdbxError::InvalidValue);
                }
                let index = binary_index_for_content_id(
                    attachment.data.id(),
                    attachment.protect_in_memory,
                    &attachment.data,
                    dedup,
                    binaries,
                )?;
                refs.insert((entry_ref_key(entry), attachment.name.clone()), index);
            }
            for history in &entry.history {
                for (name, attachment) in history.attachments.iter() {
                    if name != &attachment.name {
                        return Err(KdbxError::InvalidValue);
                    }
                    let index = binary_index_for_content_id(
                        attachment.data.id(),
                        attachment.protect_in_memory,
                        &attachment.data,
                        dedup,
                        binaries,
                    )?;
                    refs.insert((entry_ref_key(history), attachment.name.clone()), index);
                }
            }
        }
        for child in &group.children {
            walk(child, refs, dedup, binaries)?;
        }
        Ok(())
    }

    walk(&vault.root, &mut refs, &mut dedup, binaries)?;
    Ok(refs)
}

fn binary_index_for_content_id(
    content_id: AttachmentContentId,
    protect_in_memory: bool,
    content: &AttachmentContent,
    dedup: &mut BTreeMap<(bool, AttachmentContentId), usize>,
    binaries: &mut Vec<InnerBinary>,
) -> Result<usize> {
    let mut canonical_content = None;
    for existing_protection in [false, true] {
        if let Some(index) = dedup.get(&(existing_protection, content_id)).copied() {
            if binaries[index].data.as_bytes() != content.as_bytes() {
                return Err(ModelError::AttachmentContentHashCollision.into());
            }
            canonical_content.get_or_insert_with(|| binaries[index].data.clone());
        }
    }

    let key = (protect_in_memory, content_id);
    if let Some(index) = dedup.get(&key).copied() {
        return Ok(index);
    }

    let index = binaries.len();
    binaries.push(InnerBinary {
        protect_in_memory,
        data: canonical_content.unwrap_or_else(|| content.clone()),
    });
    dedup.insert(key, index);
    Ok(index)
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
    tags.split([',', ';'])
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(|tag| tag.to_string())
        .collect()
}

fn encode_uuid(uuid: Uuid) -> String {
    STANDARD.encode(uuid.as_bytes())
}

fn decode_uuid(text: &str) -> Result<Uuid> {
    let bytes = STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|_| KdbxError::InvalidValue)?;
    Uuid::from_slice(&bytes).map_err(|_| KdbxError::InvalidValue)
}

fn parse_optional_uuid(text: &str) -> Result<Option<Uuid>> {
    if text.trim().is_empty() {
        Ok(None)
    } else {
        let uuid = decode_uuid(text.trim())?;
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

fn child_text_preserve_empty(element: &Element, name: &str) -> Option<String> {
    child_optional(element, name).map(|child| {
        child
            .get_text()
            .map(|text| text.to_string())
            .unwrap_or_default()
    })
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    }
}

fn parse_bool_text(text: &str) -> bool {
    let text = text.trim();
    text.eq_ignore_ascii_case("true") || text == "1"
}

fn parse_bool_text_strict(text: &str) -> Option<bool> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("true") || text == "1" {
        Some(true)
    } else if text.eq_ignore_ascii_case("false") || text == "0" {
        Some(false)
    } else {
        None
    }
}

fn parse_bool_attribute(element: &Element, name: &str) -> Result<bool> {
    let Some(value) = element.attributes.get(name) else {
        return Ok(false);
    };
    let value = value.trim();
    if value.eq_ignore_ascii_case("true") || value == "1" {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") || value == "0" {
        Ok(false)
    } else {
        Err(KdbxError::InvalidValue)
    }
}

fn parse_nullable_bool(text: &str) -> Option<bool> {
    parse_nullable_bool_strict(text).flatten()
}

fn parse_nullable_bool_strict(text: &str) -> Option<Option<bool>> {
    let text = text.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("null") {
        Some(None)
    } else {
        parse_bool_text_strict(text).map(Some)
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
    let text = text.trim();
    if let Ok(value) = text.parse::<u64>() {
        return Some(value);
    }

    parse_datetime_i64(text)?.try_into().ok()
}

fn parse_datetime_i64(text: &str) -> Option<i64> {
    const KDBX4_TIME_OFFSET: i64 = 62_135_596_800;
    let text = text.trim();

    if let Ok(value) = text.parse::<i64>() {
        return Some(value);
    }

    if let Ok(bytes) = STANDARD.decode(text.as_bytes())
        && bytes.len() == 8
    {
        let raw = i64::from_le_bytes(bytes.try_into().ok()?);
        return raw.checked_sub(KDBX4_TIME_OFFSET);
    }

    let parsed = DateTime::parse_from_rfc3339(text).ok()?;
    Some(parsed.with_timezone(&Utc).timestamp())
}

fn parse_optional_datetime(text: &str) -> Option<i64> {
    if text.trim().is_empty() {
        None
    } else {
        parse_datetime_i64(text)
    }
}

fn text_element(name: &str, text: &str) -> Element {
    let mut element = Element::new(name);
    element.children.push(XMLNode::Text(text.to_string()));
    element
}

fn is_xml_10_character(character: char) -> bool {
    matches!(
        character,
        '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'
    )
}

pub fn is_xml_10_text(value: &str) -> bool {
    value.chars().all(is_xml_10_character)
}

fn validate_xml_text(root: &Element) -> Result<()> {
    let mut pending = vec![root];
    while let Some(element) = pending.pop() {
        if element
            .attributes
            .values()
            .any(|value| !is_xml_10_text(value))
        {
            return Err(KdbxError::InvalidValue);
        }
        for child in &element.children {
            match child {
                XMLNode::Element(child) => pending.push(child),
                XMLNode::Comment(value) | XMLNode::CData(value) | XMLNode::Text(value) => {
                    if !is_xml_10_text(value) {
                        return Err(KdbxError::InvalidValue);
                    }
                }
                XMLNode::ProcessingInstruction(target, value) => {
                    if !is_xml_10_text(target)
                        || value.as_deref().is_some_and(|value| !is_xml_10_text(value))
                    {
                        return Err(KdbxError::InvalidValue);
                    }
                }
            }
        }
    }
    Ok(())
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

fn custom_data_requires_41(blocks: &[CustomDataBlock], merged: &BTreeMap<String, String>) -> bool {
    merge_custom_data_blocks(blocks) == *merged
        && blocks
            .iter()
            .flat_map(|block| &block.items)
            .any(|item| item.last_modified.is_some())
}

fn entry_state_requires_41(entry: &Entry) -> bool {
    entry.exclude_from_reports
        || entry.raw_state.quality_check_raw.is_some()
        || entry.previous_parent.is_some()
        || materialize_entry_persistent_attributes(entry).has_projectable_passkey()
        || custom_data_requires_41(&entry.custom_data_blocks, &entry.custom_data)
}

fn entry_requires_41(entry: &Entry) -> bool {
    entry_state_requires_41(entry) || entry.history.iter().any(entry_requires_41)
}

fn group_requires_41(group: &Group) -> bool {
    if !group.tags.is_empty()
        || group.previous_parent.is_some()
        || custom_data_requires_41(&group.custom_data_blocks, &group.custom_data)
    {
        return true;
    }

    if group.entries.iter().any(entry_requires_41) {
        return true;
    }

    group.children.iter().any(group_requires_41)
}

fn validate_vault_model(vault: &Vault) -> Result<()> {
    if [
        vault.generator.as_deref(),
        vault.description.as_deref(),
        vault.default_username.as_deref(),
        vault.color.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(str::is_empty)
        || [
            vault.recycle_bin_group,
            vault.entry_templates_group,
            vault.last_selected_group,
            vault.last_top_visible_group,
        ]
        .into_iter()
        .flatten()
        .any(|id| id.is_nil())
        || vault.public_custom_data.keys().any(String::is_empty)
        || !raw_collapsed_optional_text_matches(
            vault.description.as_deref(),
            vault.meta_raw_state.description_raw.as_deref(),
        )
        || !raw_collapsed_optional_text_matches(
            vault.default_username.as_deref(),
            vault.meta_raw_state.default_username_raw.as_deref(),
        )
        || !raw_collapsed_optional_text_matches(
            vault.color.as_deref(),
            vault.meta_raw_state.color_raw.as_deref(),
        )
        || vault.meta_raw_state.recycle_bin_group_raw.is_some()
        || vault.meta_raw_state.entry_templates_group_raw.is_some()
        || vault
            .meta_raw_state
            .memory_protection_auto_enable_visual_hiding_raw
            .as_deref()
            .is_some_and(|raw| {
                vault.memory_protection.is_none() || parse_bool_text_strict(raw).is_none()
            })
    {
        return Err(KdbxError::InvalidValue);
    }

    validate_raw_node_slots(
        &vault.meta_raw_state.node_order,
        &meta_emitted_node_counts(vault),
    )?;
    let root_counts = BTreeMap::from([
        ("Group", 1_usize),
        (
            "DeletedObjects",
            usize::from(
                !vault.deleted_objects.is_empty() || vault.root_raw_state.has_deleted_objects_node,
            ),
        ),
    ]);
    validate_raw_node_slots(&vault.root_raw_state.node_order, &root_counts)?;

    validate_custom_data_model(&vault.meta_custom_data, &vault.meta_custom_data_blocks)?;
    for timestamp in [
        vault.settings_changed,
        vault.database_name_changed,
        vault.description_changed,
        vault.default_username_changed,
        vault.master_key_changed,
        vault.recycle_bin_changed,
        vault.entry_templates_group_changed,
    ]
    .into_iter()
    .flatten()
    {
        validate_kdbx4_timestamp(timestamp)?;
    }

    let mut custom_icon_ids = BTreeSet::new();
    for icon in &vault.custom_icons {
        if icon.id.is_nil()
            || !custom_icon_ids.insert(icon.id)
            || icon.name.as_deref().is_some_and(str::is_empty)
        {
            return Err(KdbxError::InvalidValue);
        }
        if let Some(last_modified) = icon.last_modified {
            validate_kdbx4_timestamp(last_modified)?;
        }
    }

    let mut live_ids = BTreeSet::new();
    validate_group_model(&vault.root, &mut live_ids)?;

    let mut tombstone_ids = BTreeSet::new();
    for deleted in &vault.deleted_objects {
        if deleted.id.is_nil() || !tombstone_ids.insert(deleted.id) {
            return Err(KdbxError::InvalidValue);
        }
        validate_kdbx4_timestamp(deleted.deleted_at)?;
    }
    Ok(())
}

fn validate_group_model(group: &Group, live_ids: &mut BTreeSet<Uuid>) -> Result<()> {
    if group.id.is_nil()
        || !live_ids.insert(group.id)
        || [
            group.custom_icon_id,
            group.last_top_visible_entry,
            group.previous_parent,
        ]
        .into_iter()
        .flatten()
        .any(|id| id.is_nil())
        || group
            .default_auto_type_sequence
            .as_deref()
            .is_some_and(str::is_empty)
        || !raw_collapsed_optional_text_matches(
            group.default_auto_type_sequence.as_deref(),
            group.raw_state.default_auto_type_sequence_raw.as_deref(),
        )
        || !raw_nullable_bool_matches(
            group.flags.enable_auto_type,
            group.raw_state.enable_auto_type_raw.as_deref(),
        )
        || !raw_nullable_bool_matches(
            group.flags.enable_searching,
            group.raw_state.enable_searching_raw.as_deref(),
        )
        || group.raw_state.last_top_visible_entry_raw.is_some()
        || !tags_are_persistence_valid(&group.tags)
    {
        return Err(KdbxError::InvalidValue);
    }
    validate_raw_node_slots(
        &group.raw_state.node_order,
        &group_emitted_node_counts(group),
    )?;
    let entry_ids = group
        .entries
        .iter()
        .map(|entry| entry.id)
        .collect::<BTreeSet<_>>();
    validate_tracked_identity_slots(
        "Entry",
        &group.raw_state.node_order,
        &group.raw_state.entry_order,
        &entry_ids,
    )?;
    validate_tracked_identity_prefix(&group.raw_state.entry_order, &group.entries, |entry| {
        entry.id
    })?;
    let group_ids = group
        .children
        .iter()
        .map(|child| child.id)
        .collect::<BTreeSet<_>>();
    validate_tracked_identity_slots(
        "Group",
        &group.raw_state.node_order,
        &group.raw_state.group_order,
        &group_ids,
    )?;
    validate_tracked_identity_prefix(&group.raw_state.group_order, &group.children, |child| {
        child.id
    })?;
    validate_custom_data_model(&group.custom_data, &group.custom_data_blocks)?;
    if let Some(times) = group.times {
        validate_unsigned_kdbx4_timestamp(times.created_at)?;
        validate_unsigned_kdbx4_timestamp(times.modified_at)?;
        if let Some(value) = times.expiry_time {
            validate_kdbx4_timestamp(value)?;
        }
        if let Some(value) = times.last_accessed_at {
            validate_unsigned_kdbx4_timestamp(value)?;
        }
        if let Some(value) = times.location_changed_at {
            validate_unsigned_kdbx4_timestamp(value)?;
        }
    }

    for entry in &group.entries {
        if entry.id.is_nil() || !live_ids.insert(entry.id) {
            return Err(KdbxError::InvalidValue);
        }
        validate_entry_model(entry, entry.id, false)?;
    }
    for child in &group.children {
        validate_group_model(child, live_ids)?;
    }
    Ok(())
}

fn validate_entry_model(entry: &Entry, owner_id: Uuid, is_snapshot: bool) -> Result<()> {
    if (is_snapshot
        && (entry.id != owner_id || !entry.history.is_empty() || entry.raw_state.has_history_node))
        || [entry.custom_icon_id, entry.previous_parent]
            .into_iter()
            .flatten()
            .any(|id| id.is_nil())
        || !tags_are_persistence_valid(&entry.tags)
        || entry
            .attributes
            .keys()
            .any(|key| key.is_empty() || is_standard_entry_field_name(key))
        || entry.attachments.iter().any(|(key, attachment)| {
            key.is_empty() || attachment.name.is_empty() || attachment.name != *key
        })
        || !raw_present_text_matches(
            entry.foreground_color.as_deref(),
            entry.raw_state.foreground_color_raw.as_deref(),
        )
        || !raw_present_text_matches(
            entry.background_color.as_deref(),
            entry.raw_state.background_color_raw.as_deref(),
        )
        || !raw_present_text_matches(
            entry.override_url.as_deref(),
            entry.raw_state.override_url_raw.as_deref(),
        )
        || entry
            .raw_state
            .tags_raw
            .as_deref()
            .is_some_and(|raw| parse_tags(raw) != entry.tags)
        || entry.location_changed_at.is_none()
        || (entry.expires && entry.expiry_time.is_none())
        || entry
            .totp
            .as_ref()
            .is_some_and(|totp| !structured_totp_is_persistence_valid(totp))
    {
        return Err(KdbxError::InvalidValue);
    }
    validate_raw_node_slots(
        &entry.raw_state.node_order,
        &entry_emitted_node_counts(entry, !is_snapshot),
    )?;
    let materialized = materialize_entry_persistent_attributes(entry);
    let mut string_keys = BTreeSet::from([
        "Title".to_owned(),
        "UserName".to_owned(),
        "Password".to_owned(),
        "URL".to_owned(),
        "Notes".to_owned(),
    ]);
    string_keys.extend(materialized.iter().map(|(key, _)| key.to_owned()));
    validate_tracked_identity_slots(
        "String",
        &entry.raw_state.node_order,
        &entry.raw_state.string_order,
        &string_keys,
    )?;
    let binary_names = entry.attachments.keys().cloned().collect::<BTreeSet<_>>();
    validate_tracked_identity_slots(
        "Binary",
        &entry.raw_state.node_order,
        &entry.raw_state.binary_order,
        &binary_names,
    )?;
    validate_custom_data_model(&entry.custom_data, &entry.custom_data_blocks)?;
    validate_unsigned_kdbx4_timestamp(entry.created_at)?;
    validate_unsigned_kdbx4_timestamp(entry.modified_at)?;
    if let Some(value) = entry.expiry_time {
        validate_kdbx4_timestamp(value)?;
    }
    if let Some(value) = entry.last_accessed_at {
        validate_unsigned_kdbx4_timestamp(value)?;
    }
    if let Some(value) = entry.location_changed_at {
        validate_unsigned_kdbx4_timestamp(value)?;
    }

    if let Some(raw) = entry.raw_state.quality_check_raw.as_deref() {
        let value = parse_bool_text_strict(raw).ok_or(KdbxError::InvalidValue)?;
        if entry.exclude_from_reports == value {
            return Err(KdbxError::InvalidValue);
        }
    }

    for snapshot in &entry.history {
        validate_entry_model(snapshot, entry.id, true)?;
    }
    Ok(())
}

fn structured_totp_is_persistence_valid(totp: &vaultkern_model::TotpSpec) -> bool {
    let Some(account_name) = totp.account_name.as_deref() else {
        return false;
    };
    !account_name.is_empty()
        && !totp.secret_base32.is_empty()
        && totp
            .issuer
            .as_deref()
            .is_none_or(|issuer| !issuer.is_empty())
        && (totp.issuer.is_some() || !account_name.contains(':'))
}

fn validate_tracked_identity_slots<T: Ord>(
    element_name: &str,
    node_order: &[String],
    tracked_identities: &[T],
    current_identities: &BTreeSet<T>,
) -> Result<()> {
    let slot_count = node_order
        .iter()
        .filter(|name| name.as_str() == element_name)
        .count();
    let unique = tracked_identities.iter().collect::<BTreeSet<_>>();
    if slot_count != tracked_identities.len()
        || unique.len() != tracked_identities.len()
        || tracked_identities
            .iter()
            .any(|identity| !current_identities.contains(identity))
    {
        return Err(KdbxError::InvalidValue);
    }
    Ok(())
}

fn validate_tracked_identity_prefix<T: Copy + Eq, U>(
    tracked_identities: &[T],
    current_values: &[U],
    identity: impl Fn(&U) -> T,
) -> Result<()> {
    if current_values.len() < tracked_identities.len()
        || current_values
            .iter()
            .take(tracked_identities.len())
            .map(identity)
            .ne(tracked_identities.iter().copied())
    {
        return Err(KdbxError::InvalidValue);
    }
    Ok(())
}

fn validate_raw_node_slots(
    node_order: &[String],
    emitted_counts: &BTreeMap<&str, usize>,
) -> Result<()> {
    let mut recorded_counts = BTreeMap::new();
    for name in node_order {
        let Some(emitted_count) = emitted_counts.get(name.as_str()) else {
            return Err(KdbxError::InvalidValue);
        };
        let recorded_count = recorded_counts.entry(name.as_str()).or_insert(0_usize);
        *recorded_count += 1;
        if *recorded_count > *emitted_count {
            return Err(KdbxError::InvalidValue);
        }
    }
    Ok(())
}

fn custom_data_emitted_count(
    blocks: &[CustomDataBlock],
    merged: &BTreeMap<String, String>,
) -> usize {
    if blocks.is_empty() {
        usize::from(!merged.is_empty())
    } else {
        blocks.len()
    }
}

fn meta_emitted_node_counts(vault: &Vault) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    let mut present = |name, is_present| {
        counts.insert(name, usize::from(is_present));
    };
    present("Generator", vault.generator.is_some());
    present("SettingsChanged", vault.settings_changed.is_some());
    present("DatabaseName", true);
    present("DatabaseNameChanged", vault.database_name_changed.is_some());
    present(
        "DatabaseDescription",
        vault.description.is_some() || vault.meta_raw_state.description_raw.is_some(),
    );
    present(
        "DatabaseDescriptionChanged",
        vault.description_changed.is_some(),
    );
    present(
        "DefaultUserName",
        vault.default_username.is_some() || vault.meta_raw_state.default_username_raw.is_some(),
    );
    present(
        "DefaultUserNameChanged",
        vault.default_username_changed.is_some(),
    );
    present(
        "MaintenanceHistoryDays",
        vault.maintenance_history_days.is_some(),
    );
    present(
        "Color",
        vault.color.is_some() || vault.meta_raw_state.color_raw.is_some(),
    );
    present("MemoryProtection", vault.memory_protection.is_some());
    present(
        "CustomIcons",
        !vault.custom_icons.is_empty() || vault.meta_raw_state.has_custom_icons_node,
    );
    present("RecycleBinEnabled", vault.recycle_bin_enabled.is_some());
    present("RecycleBinUUID", vault.recycle_bin_group.is_some());
    present("RecycleBinChanged", vault.recycle_bin_changed.is_some());
    present("EntryTemplatesGroup", vault.entry_templates_group.is_some());
    present(
        "EntryTemplatesGroupChanged",
        vault.entry_templates_group_changed.is_some(),
    );
    present("MasterKeyChanged", vault.master_key_changed.is_some());
    present("MasterKeyChangeRec", vault.master_key_change_rec.is_some());
    present(
        "MasterKeyChangeForce",
        vault.master_key_change_force.is_some(),
    );
    present(
        "MasterKeyChangeForceOnce",
        vault.master_key_change_force_once.is_some(),
    );
    present("LastSelectedGroup", vault.last_selected_group.is_some());
    present(
        "LastTopVisibleGroup",
        vault.last_top_visible_group.is_some(),
    );
    present("HistoryMaxItems", vault.history_max_items.is_some());
    present("HistoryMaxSize", vault.history_max_size.is_some());
    counts.insert(
        "CustomData",
        custom_data_emitted_count(&vault.meta_custom_data_blocks, &vault.meta_custom_data),
    );
    counts
}

fn group_emitted_node_counts(group: &Group) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::from([
        ("UUID", 1),
        ("Name", 1),
        ("Notes", 1),
        ("IconID", 1),
        ("Times", 1),
        ("IsExpanded", 1),
        ("DefaultAutoTypeSequence", 1),
        ("EnableAutoType", 1),
        ("EnableSearching", 1),
    ]);
    counts.insert(
        "LastTopVisibleEntry",
        usize::from(group.last_top_visible_entry.is_some()),
    );
    counts.insert(
        "CustomIconUUID",
        usize::from(group.custom_icon_id.is_some()),
    );
    counts.insert("Tags", usize::from(!group.tags.is_empty()));
    counts.insert(
        "PreviousParentGroup",
        usize::from(group.previous_parent.is_some()),
    );
    counts.insert("Entry", group.entries.len());
    counts.insert("Group", group.children.len());
    counts.insert(
        "CustomData",
        custom_data_emitted_count(&group.custom_data_blocks, &group.custom_data),
    );
    counts
}

fn entry_emitted_node_counts(
    entry: &Entry,
    include_history: bool,
) -> BTreeMap<&'static str, usize> {
    let materialized_count = materialize_entry_persistent_attributes(entry).len();
    let mut counts = BTreeMap::from([("UUID", 1), ("Times", 1)]);
    counts.insert("IconID", usize::from(entry.icon_id.is_some()));
    counts.insert(
        "CustomIconUUID",
        usize::from(entry.custom_icon_id.is_some()),
    );
    counts.insert(
        "ForegroundColor",
        usize::from(
            entry.foreground_color.is_some() || entry.raw_state.foreground_color_raw.is_some(),
        ),
    );
    counts.insert(
        "BackgroundColor",
        usize::from(
            entry.background_color.is_some() || entry.raw_state.background_color_raw.is_some(),
        ),
    );
    counts.insert(
        "OverrideURL",
        usize::from(entry.override_url.is_some() || entry.raw_state.override_url_raw.is_some()),
    );
    counts.insert(
        "Tags",
        usize::from(!entry.tags.is_empty() || entry.raw_state.tags_raw.is_some()),
    );
    counts.insert(
        "PreviousParentGroup",
        usize::from(entry.previous_parent.is_some()),
    );
    counts.insert(
        "QualityCheck",
        usize::from(
            entry.exclude_from_reports
                || entry
                    .raw_state
                    .quality_check_raw
                    .as_deref()
                    .is_some_and(parse_bool_text),
        ),
    );
    counts.insert("String", materialized_count + 5);
    counts.insert("Binary", entry.attachments.len());
    counts.insert("AutoType", usize::from(entry.auto_type.is_some()));
    counts.insert(
        "History",
        usize::from(should_emit_history(entry, include_history)),
    );
    counts.insert(
        "CustomData",
        custom_data_emitted_count(&entry.custom_data_blocks, &entry.custom_data),
    );
    counts
}

fn should_emit_history(entry: &Entry, include_history: bool) -> bool {
    include_history
        && (!entry.history.is_empty()
            || entry.raw_state.has_history_node
            || entry.raw_state.node_order.is_empty())
}

fn validate_custom_data_model(
    merged: &BTreeMap<String, String>,
    blocks: &[CustomDataBlock],
) -> Result<()> {
    if merged.keys().any(String::is_empty)
        || blocks
            .iter()
            .flat_map(|block| &block.items)
            .any(|item| item.key.is_empty())
        || merge_custom_data_blocks(blocks) != *merged
    {
        return Err(KdbxError::InvalidValue);
    }
    for last_modified in blocks
        .iter()
        .flat_map(|block| &block.items)
        .filter_map(|item| item.last_modified)
    {
        validate_kdbx4_timestamp(last_modified)?;
    }
    Ok(())
}

fn tags_are_persistence_valid(tags: &BTreeSet<String>) -> bool {
    tags.iter()
        .all(|tag| !tag.is_empty() && tag.trim() == tag && !tag.contains(',') && !tag.contains(';'))
}

fn raw_collapsed_optional_text_matches(modeled: Option<&str>, raw: Option<&str>) -> bool {
    raw.is_none_or(|raw| modeled == (!raw.is_empty()).then_some(raw))
}

fn raw_present_text_matches(modeled: Option<&str>, raw: Option<&str>) -> bool {
    raw.is_none_or(|raw| modeled == Some(raw))
}

fn raw_nullable_bool_matches(modeled: Option<bool>, raw: Option<&str>) -> bool {
    raw.is_none_or(|raw| parse_nullable_bool_strict(raw) == Some(modeled))
}

fn validate_unsigned_kdbx4_timestamp(timestamp: u64) -> Result<()> {
    let timestamp = i64::try_from(timestamp).map_err(|_| KdbxError::InvalidValue)?;
    validate_kdbx4_timestamp(timestamp)
}

fn validate_kdbx4_timestamp(timestamp: i64) -> Result<()> {
    const KDBX4_TIME_OFFSET: i64 = 62_135_596_800;
    if timestamp
        .checked_add(KDBX4_TIME_OFFSET)
        .is_none_or(|encoded| encoded < 0)
    {
        return Err(KdbxError::InvalidValue);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InnerBinary {
    protect_in_memory: bool,
    data: AttachmentContent,
}

trait BinaryLookup {
    fn get_binary(&self, index: usize) -> Option<&InnerBinary>;
}

impl BinaryLookup for Vec<InnerBinary> {
    fn get_binary(&self, index: usize) -> Option<&InnerBinary> {
        self.get(index)
    }
}

impl BinaryLookup for [InnerBinary] {
    fn get_binary(&self, index: usize) -> Option<&InnerBinary> {
        self.get(index)
    }
}

impl<const N: usize> BinaryLookup for [InnerBinary; N] {
    fn get_binary(&self, index: usize) -> Option<&InnerBinary> {
        self.get(index)
    }
}

impl BinaryLookup for BTreeMap<usize, InnerBinary> {
    fn get_binary(&self, index: usize) -> Option<&InnerBinary> {
        self.get(&index)
    }
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
        let end = self
            .position
            .checked_add(len)
            .ok_or(KdbxError::UnexpectedEof)?;
        if end > self.bytes.len() {
            return Err(KdbxError::UnexpectedEof);
        }
        let slice = &self.bytes[self.position..end];
        self.position = end;
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
mod external_kdf_policy_tests {
    use super::{
        ExternalKdfAlgorithm, ExternalKdfConfirmation, ExternalKdfDecision, ExternalKdfParameter,
        ExternalKdfParameters, ExternalKdfPolicy, KDF_AES_KDBX4_UUID, KDF_ARGON2D_UUID,
        KDF_ARGON2ID_UUID, KdbxError, KdfPolicyEvaluator, VariantDictionary, VariantValue,
        enforce_external_kdf_policy, load_kdbx, load_kdbx_with_policy, save_kdbx,
    };
    use vaultkern_crypto::{CompositeKey, sha256_bytes};
    use vaultkern_model::Vault;

    const MIB: u64 = 1024 * 1024;

    fn argon_request(algorithm: ExternalKdfAlgorithm, memory_bytes: u64) -> ExternalKdfParameters {
        ExternalKdfParameters::argon2_for_test(algorithm, 2, memory_bytes, 1)
    }

    fn aes_request(algorithm: ExternalKdfAlgorithm, rounds: u64) -> ExternalKdfParameters {
        ExternalKdfParameters::aes_for_test(algorithm, rounds)
    }

    #[test]
    fn fixed_policy_threshold_matrix_covers_below_equal_and_above() {
        let desktop = ExternalKdfPolicy::Desktop;
        let mobile = ExternalKdfPolicy::Mobile;
        let extension = ExternalKdfPolicy::Extension;

        for algorithm in [
            ExternalKdfAlgorithm::Argon2d,
            ExternalKdfAlgorithm::Argon2id,
        ] {
            assert_eq!(
                desktop.evaluate(argon_request(algorithm, 256 * MIB - 1024).request()),
                ExternalKdfDecision::Allow
            );
            assert_eq!(
                desktop.evaluate(argon_request(algorithm, 256 * MIB).request()),
                ExternalKdfDecision::Allow
            );
            assert_eq!(
                desktop.evaluate(argon_request(algorithm, 256 * MIB + 1024).request()),
                ExternalKdfDecision::Confirm(256 * MIB)
            );
            assert_eq!(
                desktop.evaluate(argon_request(algorithm, 1024 * MIB - 1024).request()),
                ExternalKdfDecision::Confirm(256 * MIB)
            );
            assert_eq!(
                desktop.evaluate(argon_request(algorithm, 1024 * MIB).request()),
                ExternalKdfDecision::Confirm(256 * MIB)
            );
            assert_eq!(
                desktop.evaluate(argon_request(algorithm, 1024 * MIB + 1024).request()),
                ExternalKdfDecision::Refuse(1024 * MIB)
            );

            assert_eq!(
                mobile.evaluate(argon_request(algorithm, 128 * MIB - 1024).request()),
                ExternalKdfDecision::Allow
            );
            assert_eq!(
                mobile.evaluate(argon_request(algorithm, 128 * MIB).request()),
                ExternalKdfDecision::Allow
            );
            assert_eq!(
                mobile.evaluate(argon_request(algorithm, 128 * MIB + 1024).request()),
                ExternalKdfDecision::Refuse(128 * MIB)
            );
            assert_eq!(
                extension.evaluate(argon_request(algorithm, 1024).request()),
                ExternalKdfDecision::Forbid
            );
        }

        for algorithm in [
            ExternalKdfAlgorithm::AesKdbx3,
            ExternalKdfAlgorithm::AesKdbx4,
        ] {
            assert_eq!(
                desktop.evaluate(aes_request(algorithm, 599_999_999).request()),
                ExternalKdfDecision::Allow
            );
            assert_eq!(
                desktop.evaluate(aes_request(algorithm, 600_000_000).request()),
                ExternalKdfDecision::Allow
            );
            assert_eq!(
                desktop.evaluate(aes_request(algorithm, 600_000_001).request()),
                ExternalKdfDecision::Confirm(600_000_000)
            );
            assert_eq!(
                desktop.evaluate(aes_request(algorithm, 5_999_999_999).request()),
                ExternalKdfDecision::Confirm(600_000_000)
            );
            assert_eq!(
                desktop.evaluate(aes_request(algorithm, 6_000_000_000).request()),
                ExternalKdfDecision::Confirm(600_000_000)
            );
            assert_eq!(
                desktop.evaluate(aes_request(algorithm, 6_000_000_001).request()),
                ExternalKdfDecision::Refuse(6_000_000_000)
            );
            assert_eq!(
                mobile.evaluate(aes_request(algorithm, 599_999_999).request()),
                ExternalKdfDecision::Allow
            );
            assert_eq!(
                mobile.evaluate(aes_request(algorithm, 600_000_000).request()),
                ExternalKdfDecision::Allow
            );
            assert_eq!(
                mobile.evaluate(aes_request(algorithm, 600_000_001).request()),
                ExternalKdfDecision::Refuse(600_000_000)
            );
            assert_eq!(
                extension.evaluate(aes_request(algorithm, 1).request()),
                ExternalKdfDecision::Forbid
            );
        }
    }

    #[test]
    fn confirmation_only_authorizes_confirm_decisions() {
        let confirm = aes_request(ExternalKdfAlgorithm::AesKdbx4, 600_000_001);
        let refuse = aes_request(ExternalKdfAlgorithm::AesKdbx4, 6_000_000_001);

        assert!(matches!(
            enforce_external_kdf_policy(
                &confirm,
                &ExternalKdfPolicy::Desktop,
                ExternalKdfConfirmation::Unconfirmed
            ),
            Err(KdbxError::ExternalKdfPolicy {
                decision: ExternalKdfDecision::Confirm(600_000_000),
                ..
            })
        ));
        assert!(
            enforce_external_kdf_policy(
                &confirm,
                &ExternalKdfPolicy::Desktop,
                ExternalKdfConfirmation::Confirmed
            )
            .is_ok()
        );
        assert!(matches!(
            enforce_external_kdf_policy(
                &refuse,
                &ExternalKdfPolicy::Desktop,
                ExternalKdfConfirmation::Confirmed
            ),
            Err(KdbxError::ExternalKdfPolicy {
                decision: ExternalKdfDecision::Refuse(6_000_000_000),
                ..
            })
        ));
        assert!(matches!(
            enforce_external_kdf_policy(
                &confirm,
                &ExternalKdfPolicy::Extension,
                ExternalKdfConfirmation::Confirmed
            ),
            Err(KdbxError::ExternalKdfPolicy {
                decision: ExternalKdfDecision::Forbid,
                ..
            })
        ));
    }

    fn argon_dict(uuid: uuid::Uuid, iterations: u64, memory_bytes: u64) -> VariantDictionary {
        let mut dict = VariantDictionary::default();
        dict.insert("$UUID", VariantValue::Bytes(uuid.into_bytes().to_vec()));
        dict.insert("I", VariantValue::UInt64(iterations));
        dict.insert("M", VariantValue::UInt64(memory_bytes));
        dict.insert("P", VariantValue::UInt32(1));
        dict.insert("S", VariantValue::Bytes(vec![7; 32]));
        dict
    }

    fn aes_dict(rounds: u64) -> VariantDictionary {
        let mut dict = VariantDictionary::default();
        dict.insert(
            "$UUID",
            VariantValue::Bytes(KDF_AES_KDBX4_UUID.into_bytes().to_vec()),
        );
        dict.insert("R", VariantValue::UInt64(rounds));
        dict.insert("S", VariantValue::Bytes(vec![7; 32]));
        dict
    }

    #[test]
    fn raw_kdbx4_parameters_fail_closed_before_profile_conversion() {
        for uuid in [KDF_ARGON2D_UUID, KDF_ARGON2ID_UUID] {
            for (iterations, memory, parameter) in [
                (0, 1024, ExternalKdfParameter::Iterations),
                (
                    u64::from(u32::MAX) + 1,
                    1024,
                    ExternalKdfParameter::Iterations,
                ),
                (u64::MAX, 1024, ExternalKdfParameter::Iterations),
                (1, 0, ExternalKdfParameter::MemoryBytes),
                (1, 1025, ExternalKdfParameter::MemoryBytes),
                (
                    1,
                    (u64::from(u32::MAX) + 1) * 1024,
                    ExternalKdfParameter::MemoryBytes,
                ),
                (1, u64::MAX, ExternalKdfParameter::MemoryBytes),
            ] {
                assert!(matches!(
                    ExternalKdfParameters::decode_kdbx4(&argon_dict(uuid, iterations, memory)),
                    Err(KdbxError::InvalidKdfParameters { parameter: observed, .. }) if observed == parameter
                ));
            }
        }

        for rounds in [0, u64::MAX] {
            assert!(matches!(
                ExternalKdfParameters::decode_kdbx4(&aes_dict(rounds)),
                Err(KdbxError::InvalidKdfParameters {
                    parameter: ExternalKdfParameter::Rounds,
                    ..
                })
            ));
        }

        let exact = ExternalKdfParameters::decode_kdbx4(&argon_dict(
            KDF_ARGON2ID_UUID,
            u64::from(u32::MAX),
            u64::from(u32::MAX) * 1024,
        ))
        .expect("largest exactly representable Argon2 values");
        assert_eq!(exact.request().observed, u64::from(u32::MAX) * 1024);
        assert_eq!(
            ExternalKdfParameters::decode_kdbx4(&argon_dict(KDF_ARGON2ID_UUID, 1, 1024))
                .expect("one KiB is represented exactly")
                .request()
                .observed,
            1024
        );
    }

    #[test]
    fn memory_conversion_error_reports_the_raw_header_bytes() {
        let memory_bytes = (u64::from(u32::MAX) + 1) * 1024;
        let error =
            ExternalKdfParameters::decode_kdbx4(&argon_dict(KDF_ARGON2ID_UUID, 1, memory_bytes))
                .expect_err("memory above the representable KiB range must fail closed");

        assert!(matches!(
            error,
            KdbxError::InvalidKdfParameters {
                algorithm: ExternalKdfAlgorithm::Argon2id,
                parameter: ExternalKdfParameter::MemoryBytes,
                value,
            } if value == memory_bytes
        ));
    }

    fn header_only_kdbx4(kdf_parameters: VariantDictionary) -> Vec<u8> {
        let mut header =
            super::KdbxHeader::new(super::KdbxVersion::V4_1, super::KdbxCipher::Aes256);
        header.encryption_iv = vec![0; 16];
        header.kdf_parameters = kdf_parameters;
        let header_bytes = header.encode().expect("encode header");
        let mut bytes = header_bytes.clone();
        bytes.extend(sha256_bytes(&header_bytes));
        bytes.extend([0; 32]);
        bytes
    }

    #[test]
    fn compatibility_load_defaults_to_mobile_resource_limits() {
        assert!(matches!(
            load_kdbx(
                &header_only_kdbx4(aes_dict(600_000_001)),
                &CompositeKey::default(),
            ),
            Err(KdbxError::ExternalKdfPolicy {
                algorithm: ExternalKdfAlgorithm::AesKdbx4,
                observed: 600_000_001,
                decision: ExternalKdfDecision::Refuse(600_000_000),
            })
        ));

        let mut argon = argon_dict(KDF_ARGON2ID_UUID, 1, 128 * MIB + 1024);
        argon.insert("S", VariantValue::Bytes(Vec::new()));
        assert!(matches!(
            load_kdbx(
                &header_only_kdbx4(argon),
                &CompositeKey::default(),
            ),
            Err(KdbxError::ExternalKdfPolicy {
                algorithm: ExternalKdfAlgorithm::Argon2id,
                observed,
                decision: ExternalKdfDecision::Refuse(limit),
            }) if observed == 128 * MIB + 1024 && limit == 128 * MIB
        ));
    }

    #[test]
    fn extreme_kdbx4_headers_return_policy_error_before_header_hmac_or_kdf() {
        let cases = [
            (
                argon_dict(KDF_ARGON2D_UUID, 2, 1024 * MIB + 1024),
                ExternalKdfAlgorithm::Argon2d,
                1024 * MIB + 1024,
            ),
            (
                argon_dict(KDF_ARGON2ID_UUID, 2, 1024 * MIB + 1024),
                ExternalKdfAlgorithm::Argon2id,
                1024 * MIB + 1024,
            ),
            (
                aes_dict(6_000_000_001),
                ExternalKdfAlgorithm::AesKdbx4,
                6_000_000_001,
            ),
        ];

        for (parameters, algorithm, observed) in cases {
            let error = load_kdbx_with_policy(
                &header_only_kdbx4(parameters),
                &CompositeKey::default(),
                &ExternalKdfPolicy::Desktop,
                ExternalKdfConfirmation::Confirmed,
            )
            .expect_err("over-refuse-limit header must not reach header HMAC or KDF");
            assert!(matches!(
                error,
                KdbxError::ExternalKdfPolicy {
                    algorithm: actual_algorithm,
                    observed: actual_observed,
                    decision: ExternalKdfDecision::Refuse(_),
                } if actual_algorithm == algorithm && actual_observed == observed
            ));
        }
    }

    fn header_only_kdbx3(rounds: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(0x9AA2_D903_u32.to_le_bytes());
        bytes.extend(0xB54B_FB67_u32.to_le_bytes());
        bytes.extend(super::version_to_u32(super::KdbxVersion::V3_1).to_le_bytes());
        bytes.push(5);
        bytes.extend(32_u16.to_le_bytes());
        bytes.extend([0; 32]);
        bytes.push(6);
        bytes.extend(8_u16.to_le_bytes());
        bytes.extend(rounds.to_le_bytes());
        bytes.push(0);
        bytes.extend(0_u16.to_le_bytes());
        bytes
    }

    #[test]
    fn kdbx3_aes_rounds_use_the_same_policy_and_validation_path() {
        assert!(matches!(
            load_kdbx(&header_only_kdbx3(600_000_001), &CompositeKey::default()),
            Err(KdbxError::ExternalKdfPolicy {
                algorithm: ExternalKdfAlgorithm::AesKdbx3,
                observed: 600_000_001,
                decision: ExternalKdfDecision::Refuse(600_000_000),
            })
        ));
        assert!(matches!(
            load_kdbx(&header_only_kdbx3(u64::MAX), &CompositeKey::default()),
            Err(KdbxError::InvalidKdfParameters {
                algorithm: ExternalKdfAlgorithm::AesKdbx3,
                parameter: ExternalKdfParameter::Rounds,
                value: u64::MAX,
            })
        ));
    }

    struct AlwaysConfirm;

    impl KdfPolicyEvaluator for AlwaysConfirm {
        fn evaluate(&self, _request: super::ExternalKdfRequest) -> ExternalKdfDecision {
            ExternalKdfDecision::Confirm(0)
        }
    }

    #[test]
    fn load_does_not_derive_until_confirmed_and_then_loads_normally() {
        let key = CompositeKey::default();
        let profile = super::SaveProfile {
            kdf: Some(super::SaveKdf::AesKdbx4 { rounds: 1 }),
            ..super::SaveProfile::recommended()
        };
        let bytes = save_kdbx(&Vault::empty("confirm"), &key, &profile).expect("save fixture");

        assert!(matches!(
            load_kdbx_with_policy(
                &bytes,
                &key,
                &AlwaysConfirm,
                ExternalKdfConfirmation::Unconfirmed,
            ),
            Err(KdbxError::ExternalKdfPolicy {
                decision: ExternalKdfDecision::Confirm(0),
                ..
            })
        ));
        let loaded = load_kdbx_with_policy(
            &bytes,
            &key,
            &AlwaysConfirm,
            ExternalKdfConfirmation::Confirmed,
        )
        .expect("explicit confirmation authorizes the KDF");
        assert_eq!(loaded.name, "confirm");
    }

    #[test]
    fn ordinary_save_preserves_the_loaded_kdf_dictionary() {
        let key = CompositeKey::default();
        let profile = super::SaveProfile {
            kdf: Some(super::SaveKdf::AesKdbx4 { rounds: 1 }),
            ..super::SaveProfile::recommended()
        };
        let first =
            save_kdbx(&Vault::empty("preserve kdf"), &key, &profile).expect("save initial vault");
        let loaded = load_kdbx(&first, &key).expect("load initial vault");

        let second =
            save_kdbx(&loaded, &key, &super::SaveProfile::recommended()).expect("ordinary save");
        let first_header = super::KdbxHeader::decode(&first).expect("first header");
        let second_header = super::KdbxHeader::decode(&second).expect("second header");

        assert_eq!(
            super::kdf_generation::kdf_generation(&second_header.kdf_parameters),
            super::kdf_generation::kdf_generation(&first_header.kdf_parameters)
        );
        assert_eq!(
            second_header.kdf_parameters.encode().expect("second KDF"),
            first_header.kdf_parameters.encode().expect("first KDF")
        );
    }
}

#[cfg(test)]
mod compatibility_tests {
    use std::collections::BTreeMap;

    use super::{
        Compression, KdbxCipher, KdbxError, KdbxHeader, KdbxVersion, ProtectedStream, SaveKdf,
        SaveProfile, binary_index_for_content_id, child_text, collect_attachment_refs,
        decode_block_stream, decrypt_payload, encode_block_stream, entry_ref_key, gzip_compress,
        gzip_decompress, header_hmac, kdf_from_variant_dict, load_kdbx, mac_seed,
        parse_inner_header, parse_kdbx3_binaries, required_version, save_kdbx, sha256_seeded,
        text_element, validate_xml_model_shape,
    };
    use base64::Engine as _;
    use vaultkern_crypto::{CompositeKey, sha256_bytes};
    use vaultkern_model::{
        Attachment, AttachmentContent, AttachmentContentId, AutoTypeConfig, CustomDataBlock,
        CustomDataItem, CustomField, CustomIcon, DeletedObject, Entry, Group, ModelError,
        OpaqueXmlAnchor, OpaqueXmlFragment, PasskeyRecord, TotpAlgorithm, TotpSpec, Vault,
        canonical_entry_bytes_v1, canonical_entry_content_hash_v1,
    };
    use xmltree::{Element, XMLNode};

    fn fast_profile() -> SaveProfile {
        SaveProfile {
            version: KdbxVersion::V4_1,
            cipher: KdbxCipher::Aes256,
            compression: Compression::Gzip,
            kdf: Some(SaveKdf::AesKdbx4 { rounds: 1 }),
        }
    }

    fn test_key(password: &str) -> CompositeKey {
        let mut key = CompositeKey::default();
        key.add_password(password);
        key
    }

    #[test]
    fn xml_shape_validation_rejects_malformed_typed_values() {
        let wrap = |body: &str| {
            Element::parse(
                format!(
                    "<KeePassFile><Meta>{body}</Meta><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Group></Root></KeePassFile>"
                )
                .as_bytes(),
            )
            .expect("typed XML fixture")
        };

        for body in [
            "<RecycleBinEnabled>maybe</RecycleBinEnabled>",
            "<MaintenanceHistoryDays>many</MaintenanceHistoryDays>",
            "<SettingsChanged>not-a-time</SettingsChanged>",
            "<RecycleBinUUID>not-base64</RecycleBinUUID>",
            "<MemoryProtection><ProtectPassword>sometimes</ProtectPassword></MemoryProtection>",
        ] {
            assert!(validate_xml_model_shape(&wrap(body)).is_err(), "{body}");
        }

        let entry = Element::parse(
            b"<KeePassFile><Meta/><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Entry><UUID>AgICAgICAgICAgICAgICAg==</UUID><Times><CreationTime>not-a-time</CreationTime></Times><String><Key>field</Key><Value Protected='maybe'>value</Value></String></Entry></Group></Root></KeePassFile>"
                .as_slice(),
        )
        .expect("entry typed XML fixture");
        assert!(validate_xml_model_shape(&entry).is_err());
    }

    #[test]
    fn xml_shape_validation_rejects_nested_elements_inside_modeled_scalar_values() {
        let cases = [
            "<KeePassFile><Meta><DatabaseName>visible<Future/>discarded</DatabaseName></Meta><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Group></Root></KeePassFile>",
            "<KeePassFile><Meta><MemoryProtection><ProtectPassword>True<Future/></ProtectPassword></MemoryProtection></Meta><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Group></Root></KeePassFile>",
            "<KeePassFile><Meta><CustomData><Item><Key>key<Future/></Key><Value>value</Value></Item></CustomData></Meta><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Group></Root></KeePassFile>",
            "<KeePassFile><Meta/><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Entry><UUID>AgICAgICAgICAgICAgICAg==</UUID><String><Key>field<Future/></Key><Value>value</Value></String></Entry></Group></Root></KeePassFile>",
            "<KeePassFile><Meta/><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Entry><UUID>AgICAgICAgICAgICAgICAg==</UUID><AutoType><Association><Window>target<Future/></Window></Association></AutoType></Entry></Group></Root></KeePassFile>",
            "<KeePassFile><Meta><Binaries><Binary ID='0'>Ynl0ZXM=<Future/></Binary></Binaries></Meta><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Group></Root></KeePassFile>",
        ];

        for xml in cases {
            let root = Element::parse(xml.as_bytes()).expect("nested scalar XML fixture");
            assert!(validate_xml_model_shape(&root).is_err(), "{xml}");
        }
    }

    #[test]
    fn attachment_binary_pool_deduplicates_by_content_without_losing_protection() {
        let shared = AttachmentContent::from_bytes(vec![0x7b; 4096]);
        let mut vault = Vault::empty("attachment pool");
        let mut first = Entry::new("first");
        first.attachments.insert(
            "plain.bin".into(),
            Attachment::with_content("plain.bin", shared.clone(), false),
        );
        let mut history = first.clone();
        history.attachments.clear();
        history.attachments.insert(
            "protected.bin".into(),
            Attachment::with_content("protected.bin", shared.clone(), true),
        );
        first.history.push(history);
        let mut second = Entry::new("second");
        second.attachments.insert(
            "same-plain.bin".into(),
            Attachment::with_content("same-plain.bin", shared.clone(), false),
        );
        vault.root.entries.extend([first, second]);

        let mut binaries = Vec::new();
        let refs = collect_attachment_refs(&vault, &mut binaries).expect("collect binaries");

        assert_eq!(binaries.len(), 2);
        let first = &vault.root.entries[0];
        let history = &first.history[0];
        let second = &vault.root.entries[1];
        assert_eq!(
            refs[&(entry_ref_key(first), "plain.bin".into())],
            refs[&(entry_ref_key(second), "same-plain.bin".into())]
        );
        assert_ne!(
            refs[&(entry_ref_key(first), "plain.bin".into())],
            refs[&(entry_ref_key(history), "protected.bin".into())]
        );
        assert!(binaries.iter().all(|binary| binary.data.ptr_eq(&shared)));
    }

    #[test]
    fn attachment_binary_pool_rejects_same_id_with_different_bytes() {
        let forced_id = AttachmentContentId::from_bytes(b"forced binary id");
        let first = AttachmentContent::from_bytes(b"first binary".to_vec());
        let same_bytes = AttachmentContent::from_bytes(b"first binary".to_vec());
        let collision = AttachmentContent::from_bytes(b"different binary".to_vec());
        let mut dedup = std::collections::BTreeMap::new();
        let mut binaries = Vec::new();

        assert_eq!(
            binary_index_for_content_id(forced_id, false, &first, &mut dedup, &mut binaries)
                .expect("insert first binary"),
            0
        );
        assert_eq!(
            binary_index_for_content_id(forced_id, true, &same_bytes, &mut dedup, &mut binaries)
                .expect("insert protected reference"),
            1
        );
        assert!(binaries[0].data.ptr_eq(&binaries[1].data));
        assert!(matches!(
            binary_index_for_content_id(forced_id, true, &collision, &mut dedup, &mut binaries),
            Err(KdbxError::Model(ModelError::AttachmentContentHashCollision))
        ));
        assert_eq!(binaries.len(), 2);
        assert_eq!(binaries[0].data.as_bytes(), b"first binary");
    }

    #[test]
    fn attachment_binary_pool_rejects_map_key_name_mismatch() {
        let mut vault = Vault::empty("attachment names");
        let mut entry = Entry::new("entry");
        entry.attachments.insert(
            "map-name.bin".into(),
            Attachment::new("embedded-name.bin", b"content".to_vec(), false),
        );
        vault.root.entries.push(entry);

        assert!(matches!(
            save_kdbx(&vault, &test_key("attachment-names"), &fast_profile()),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn attachment_parser_rejects_duplicate_names() {
        let mut vault = Vault::empty("duplicate attachment names");
        let mut entry = Entry::new("entry");
        entry.attachments.insert(
            "duplicate.bin".into(),
            Attachment::new("duplicate.bin", b"content".to_vec(), false),
        );
        vault.root.entries.push(entry);

        let key = test_key("duplicate-attachment-names");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save attachment");
        let duplicated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = first_live_entry_mut(root);
            let binary = entry
                .children
                .iter()
                .find(
                    |child| matches!(child, XMLNode::Element(element) if element.name == "Binary"),
                )
                .cloned()
                .expect("binary node");
            entry.children.push(binary);
        })
        .expect("duplicate attachment node");

        assert!(matches!(
            load_kdbx(&duplicated, &key),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn attachment_parser_rejects_malformed_binary_reference() {
        let mut vault = Vault::empty("malformed attachment reference");
        let mut entry = Entry::new("entry");
        entry.attachments.insert(
            "attachment.bin".into(),
            Attachment::new("attachment.bin", b"content".to_vec(), false),
        );
        vault.root.entries.push(entry);

        let key = test_key("malformed-attachment-reference");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save attachment");
        let malformed = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = first_live_entry_mut(root);
            let binary = entry
                .children
                .iter_mut()
                .find_map(|child| match child {
                    XMLNode::Element(element) if element.name == "Binary" => Some(element),
                    _ => None,
                })
                .expect("binary node");
            let value = binary
                .children
                .iter_mut()
                .find_map(|child| match child {
                    XMLNode::Element(element) if element.name == "Value" => Some(element),
                    _ => None,
                })
                .expect("value node");
            value.attributes.insert("Ref".into(), "not-an-index".into());
        })
        .expect("malform attachment reference");

        assert!(matches!(
            load_kdbx(&malformed, &key),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn kdbx3_binary_pool_rejects_duplicate_indexes() {
        let mut meta = Element::new("Meta");
        let mut binaries = Element::new("Binaries");
        for encoded in ["Zmlyc3Q=", "c2Vjb25k"] {
            let mut binary = Element::new("Binary");
            binary.attributes.insert("ID".into(), "0".into());
            binary.children.push(XMLNode::Text(encoded.into()));
            binaries.children.push(XMLNode::Element(binary));
        }
        meta.children.push(XMLNode::Element(binaries));
        let mut protected = ProtectedStream::from_stream(2, &[0x42; 32]).expect("stream");

        assert!(matches!(
            parse_kdbx3_binaries(&meta, &mut protected),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn kdbx3_binary_pool_does_not_allocate_through_sparse_indexes() {
        let mut meta = Element::new("Meta");
        let mut binaries = Element::new("Binaries");
        let mut binary = Element::new("Binary");
        binary
            .attributes
            .insert("ID".into(), usize::MAX.to_string());
        binary.children.push(XMLNode::Text("Y29udGVudA==".into()));
        binaries.children.push(XMLNode::Element(binary));
        meta.children.push(XMLNode::Element(binaries));
        let mut protected = ProtectedStream::from_stream(2, &[0x42; 32]).expect("stream");

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            parse_kdbx3_binaries(&meta, &mut protected)
        }));
        let parsed = outcome
            .expect("sparse binary index must not panic")
            .expect("sparse binary index");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn kdbx3_binary_pool_rejects_invalid_boolean_attributes() {
        let mut meta = Element::new("Meta");
        let mut binaries = Element::new("Binaries");
        let mut binary = Element::new("Binary");
        binary.attributes.insert("ID".into(), "0".into());
        binary
            .attributes
            .insert("Protected".into(), "sometimes".into());
        binary.children.push(XMLNode::Text("Y29udGVudA==".into()));
        binaries.children.push(XMLNode::Element(binary));
        meta.children.push(XMLNode::Element(binaries));
        let mut protected = ProtectedStream::from_stream(2, &[0x42; 32]).expect("stream");

        assert!(matches!(
            parse_kdbx3_binaries(&meta, &mut protected),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn kdbx3_attachment_rejects_reference_to_undefined_sparse_index() {
        let mut meta = Element::new("Meta");
        let mut binaries = Element::new("Binaries");
        let mut binary = Element::new("Binary");
        binary.attributes.insert("ID".into(), "1".into());
        binary.children.push(XMLNode::Text("Y29udGVudA==".into()));
        binaries.children.push(XMLNode::Element(binary));
        meta.children.push(XMLNode::Element(binaries));
        let mut protected = ProtectedStream::from_stream(2, &[0x42; 32]).expect("stream");
        let binaries = parse_kdbx3_binaries(&meta, &mut protected).expect("binary pool");

        let mut entry = Element::new("Entry");
        entry.children.push(XMLNode::Element(text_element(
            "UUID",
            &super::encode_uuid(uuid::Uuid::nil()),
        )));
        let mut attachment = Element::new("Binary");
        attachment
            .children
            .push(XMLNode::Element(text_element("Key", "missing.bin")));
        let mut value = Element::new("Value");
        value.attributes.insert("Ref".into(), "0".into());
        attachment.children.push(XMLNode::Element(value));
        entry.children.push(XMLNode::Element(attachment));

        let mut content_pool = vaultkern_model::AttachmentContentPool::new();
        assert!(matches!(
            super::parse_entry(&entry, &binaries, &mut content_pool, &mut protected),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn inline_protected_attachment_advances_stream_and_preserves_protection() {
        let key = [0x24; 32];
        let mut writer = ProtectedStream::from_stream(2, &key).expect("writer stream");
        let mut attachment_bytes = b"protected attachment".to_vec();
        writer.apply(&mut attachment_bytes);
        let mut password_bytes = b"following password".to_vec();
        writer.apply(&mut password_bytes);

        let mut entry = Element::new("Entry");
        entry.children.push(XMLNode::Element(text_element(
            "UUID",
            &super::encode_uuid(uuid::Uuid::nil()),
        )));
        let mut attachment = Element::new("Binary");
        attachment
            .children
            .push(XMLNode::Element(text_element("Key", "protected.bin")));
        let mut attachment_value = text_element("Value", &super::STANDARD.encode(attachment_bytes));
        attachment_value
            .attributes
            .insert("Protected".into(), "True".into());
        attachment.children.push(XMLNode::Element(attachment_value));
        entry.children.push(XMLNode::Element(attachment));

        let mut password = Element::new("String");
        password
            .children
            .push(XMLNode::Element(text_element("Key", "Password")));
        let mut password_value = text_element("Value", &super::STANDARD.encode(password_bytes));
        password_value
            .attributes
            .insert("Protected".into(), "True".into());
        password.children.push(XMLNode::Element(password_value));
        entry.children.push(XMLNode::Element(password));

        let mut reader = ProtectedStream::from_stream(2, &key).expect("reader stream");
        let mut content_pool = vaultkern_model::AttachmentContentPool::new();
        let parsed = super::parse_entry(&entry, &[], &mut content_pool, &mut reader)
            .expect("parse protected attachment");

        let attachment = &parsed.attachments["protected.bin"];
        assert_eq!(attachment.data.as_bytes(), b"protected attachment");
        assert!(attachment.protect_in_memory);
        assert_eq!(parsed.password, "following password");
    }

    #[test]
    fn inline_attachment_rejects_invalid_boolean_attributes() {
        let mut entry = Element::new("Entry");
        entry.children.push(XMLNode::Element(text_element(
            "UUID",
            &super::encode_uuid(uuid::Uuid::nil()),
        )));
        let mut attachment = Element::new("Binary");
        attachment
            .children
            .push(XMLNode::Element(text_element("Key", "attachment.bin")));
        let mut value = text_element("Value", "Y29udGVudA==");
        value
            .attributes
            .insert("Compressed".into(), "perhaps".into());
        attachment.children.push(XMLNode::Element(value));
        entry.children.push(XMLNode::Element(attachment));

        let mut protected = ProtectedStream::from_stream(2, &[0x42; 32]).expect("stream");
        let mut content_pool = vaultkern_model::AttachmentContentPool::new();
        assert!(matches!(
            super::parse_entry(&entry, &[], &mut content_pool, &mut protected),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn referenced_attachment_rejects_conflicting_inline_protection() {
        let binaries = vec![super::InnerBinary {
            protect_in_memory: false,
            data: AttachmentContent::from_bytes(b"pooled content".to_vec()),
        }];
        let mut entry = Element::new("Entry");
        entry.children.push(XMLNode::Element(text_element(
            "UUID",
            &super::encode_uuid(uuid::Uuid::nil()),
        )));
        let mut attachment = Element::new("Binary");
        attachment
            .children
            .push(XMLNode::Element(text_element("Key", "attachment.bin")));
        let mut value = Element::new("Value");
        value.attributes.insert("Ref".into(), "0".into());
        value.attributes.insert("Protected".into(), "True".into());
        attachment.children.push(XMLNode::Element(value));
        entry.children.push(XMLNode::Element(attachment));

        let mut protected = ProtectedStream::from_stream(2, &[0x42; 32]).expect("stream");
        let mut content_pool = vaultkern_model::AttachmentContentPool::new();
        assert!(matches!(
            super::parse_entry(&entry, &binaries, &mut content_pool, &mut protected),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn inner_binary_rejects_unknown_protection_flags() {
        let mut payload = Vec::new();
        super::write_field(&mut payload, 1, &3_i32.to_le_bytes());
        super::write_field(&mut payload, 2, &[0x42; 64]);
        super::write_field(&mut payload, 3, &[0x02, b'x']);
        super::write_field(&mut payload, 0, &[]);

        assert!(matches!(
            parse_inner_header(&payload),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn cursor_rejects_overflowing_read_length_without_panicking() {
        let mut cursor = super::Cursor::new(&[0]);
        cursor.read_exact(1).expect("advance cursor");

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cursor.read_exact(usize::MAX)
        }));
        assert!(matches!(
            outcome.expect("overflowing read must not panic"),
            Err(KdbxError::UnexpectedEof)
        ));
    }

    #[test]
    fn protected_and_unprotected_shared_content_roundtrips_with_one_memory_owner() {
        let shared = AttachmentContent::from_bytes(b"shared attachment".to_vec());
        let mut vault = Vault::empty("attachment roundtrip");
        let mut entry = Entry::new("entry");
        entry.attachments.insert(
            "plain.txt".into(),
            Attachment::with_content("plain.txt", shared.clone(), false),
        );
        entry.attachments.insert(
            "protected.txt".into(),
            Attachment::with_content("protected.txt", shared, true),
        );
        vault.root.entries.push(entry);

        let key = test_key("attachment-roundtrip");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save attachments");
        let loaded = load_kdbx(&bytes, &key).expect("load attachments");
        let loaded = &loaded.root.entries[0].attachments;

        assert_eq!(loaded["plain.txt"].data.as_bytes(), b"shared attachment");
        assert_eq!(
            loaded["protected.txt"].data.as_bytes(),
            b"shared attachment"
        );
        assert!(!loaded["plain.txt"].protect_in_memory);
        assert!(loaded["protected.txt"].protect_in_memory);
        assert!(
            loaded["plain.txt"]
                .data
                .ptr_eq(&loaded["protected.txt"].data)
        );
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

    fn projection_string_fields(
        entry: &Element,
    ) -> std::collections::BTreeMap<String, (String, Option<String>)> {
        let mut fields = std::collections::BTreeMap::new();
        for child in &entry.children {
            let XMLNode::Element(field) = child else {
                continue;
            };
            if field.name != "String" {
                continue;
            }
            let Some(key) = child_text(field, "Key") else {
                continue;
            };
            if !matches!(
                key.as_str(),
                "otp"
                    | "TimeOtp-Secret-Base32"
                    | "TimeOtp-Algorithm"
                    | "TimeOtp-Length"
                    | "TimeOtp-Period"
            ) && !key.starts_with("KPEX_PASSKEY_")
            {
                continue;
            }
            let value = field.get_child("Value").expect("projection value");
            let previous = fields.insert(
                key.clone(),
                (
                    value.get_text().unwrap_or_default().into_owned(),
                    value.attributes.get("Protected").cloned(),
                ),
            );
            assert!(previous.is_none(), "duplicate projection field: {key}");
        }
        fields
    }

    fn credential_entry() -> Entry {
        let mut entry = Entry::new("Example Login");
        entry.username = "alice@example.com".into();
        entry.created_at = 101;
        entry.modified_at = 202;
        entry.expires = true;
        entry.expiry_time = Some(303);
        entry.last_accessed_at = Some(404);
        entry.usage_count = Some(5);
        entry.location_changed_at = Some(606);
        entry.icon_id = Some(0);
        entry.auto_type = Some(AutoTypeConfig::default());
        entry.totp = Some(TotpSpec {
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
            algorithm: TotpAlgorithm::Sha256,
            digits: 8,
            period_seconds: 45,
            issuer: Some("Example Inc".into()),
            account_name: Some("alice+prod@example.com".into()),
        });
        entry.passkey = Some(PasskeyRecord {
            username: "alice@example.com".into(),
            credential_id: "credential-1".into(),
            generated_user_id: Some("generated-1".into()),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nkey-1\n-----END PRIVATE KEY-----".into(),
            relying_party: "example.com".into(),
            user_handle: Some("user-handle-1".into()),
            backup_eligible: true,
            backup_state: false,
        });
        entry
    }

    #[test]
    fn loader_rejects_duplicate_known_singletons_and_repeated_field_identities() {
        let mut vault = Vault::empty("duplicate known nodes");
        let mut entry = Entry::new("entry");
        entry.attachments.insert(
            "file.bin".into(),
            Attachment::new("file.bin", b"data".to_vec(), false),
        );
        vault.root.entries.push(entry);
        let key = test_key("duplicate-known-nodes");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save fixture");

        let duplicate_entry_uuid = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = first_live_entry_mut(root);
            let uuid = entry.get_child("UUID").expect("entry UUID").clone();
            entry.children.push(XMLNode::Element(uuid));
        })
        .expect("duplicate UUID");

        let duplicate_string_key = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = first_live_entry_mut(root);
            let title = entry
                .children
                .iter()
                .find_map(|child| match child {
                    XMLNode::Element(field)
                        if field.name == "String"
                            && child_text(field, "Key").as_deref() == Some("Title") =>
                    {
                        Some(field.clone())
                    }
                    _ => None,
                })
                .expect("Title field");
            entry.children.push(XMLNode::Element(title));
        })
        .expect("duplicate String key");

        let duplicate_binary_name = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = first_live_entry_mut(root);
            let binary = entry.get_child("Binary").expect("Binary").clone();
            entry.children.push(XMLNode::Element(binary));
        })
        .expect("duplicate Binary name");

        let duplicate_root_group = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let root_node = root.get_mut_child("Root").expect("Root");
            let group = root_node.get_child("Group").expect("Group").clone();
            root_node.children.push(XMLNode::Element(group));
        })
        .expect("duplicate root Group");

        let duplicate_meta = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let meta = root.get_child("Meta").expect("Meta").clone();
            root.children.push(XMLNode::Element(meta));
        })
        .expect("duplicate Meta");

        for (case, malformed) in [
            ("entry UUID", duplicate_entry_uuid),
            ("String key", duplicate_string_key),
            ("Binary name", duplicate_binary_name),
            ("root Group", duplicate_root_group),
            ("Meta", duplicate_meta),
        ] {
            assert!(
                matches!(load_kdbx(&malformed, &key), Err(KdbxError::InvalidValue)),
                "duplicate {case} was accepted"
            );
        }
    }

    #[test]
    fn loader_rejects_live_uuid_collisions_and_history_uuid_mismatches() {
        let mut vault = Vault::empty("UUID graph");
        let first = Entry::new("first");
        let mut second = Entry::new("second");
        let mut snapshot = second.clone();
        snapshot.history.clear();
        second.history.push(snapshot);
        vault.root.entries.extend([first, second]);
        let key = test_key("uuid-graph");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save UUID fixture");

        let collision = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let group = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .expect("root Group");
            let mut entries = group.children.iter_mut().filter_map(|child| match child {
                XMLNode::Element(entry) if entry.name == "Entry" => Some(entry),
                _ => None,
            });
            let first_uuid =
                child_text(entries.next().expect("first entry"), "UUID").expect("first UUID");
            let second = entries.next().expect("second entry");
            second.get_mut_child("UUID").expect("second UUID").children =
                vec![XMLNode::Text(first_uuid)];
        })
        .expect("rewrite collision");

        let history_mismatch = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let group = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .expect("root Group");
            let second = group
                .children
                .iter_mut()
                .filter_map(|child| match child {
                    XMLNode::Element(entry) if entry.name == "Entry" => Some(entry),
                    _ => None,
                })
                .nth(1)
                .expect("second entry");
            let history_entry = second
                .get_mut_child("History")
                .and_then(|history| history.get_mut_child("Entry"))
                .expect("history entry");
            history_entry
                .get_mut_child("UUID")
                .expect("history UUID")
                .children = vec![XMLNode::Text(super::encode_uuid(uuid::Uuid::new_v4()))];
        })
        .expect("rewrite history UUID");

        for (case, malformed) in [
            ("live collision", collision),
            ("history mismatch", history_mismatch),
        ] {
            assert!(
                matches!(load_kdbx(&malformed, &key), Err(KdbxError::InvalidValue)),
                "invalid UUID graph was accepted: {case}"
            );
        }
    }

    #[test]
    fn absent_entry_icon_id_survives_kdbx_roundtrip_in_canonical_v1() {
        let mut entry = Entry::new("No icon");
        entry.icon_id = None;
        entry.auto_type = Some(AutoTypeConfig::default());
        let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let mut vault = Vault::empty("NoIcon");
        vault.root.entries.push(entry);

        let key = test_key("no-icon");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save entry");
        let loaded = load_kdbx(&bytes, &key).expect("load entry");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert_eq!(loaded_entry.icon_id, None);
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected_bytes
        );
    }

    #[test]
    fn absent_entry_auto_type_survives_kdbx_roundtrip_in_canonical_v1() {
        let mut entry = Entry::new("No auto type");
        entry.icon_id = Some(0);
        entry.auto_type = None;
        let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let mut vault = Vault::empty("NoAutoType");
        vault.root.entries.push(entry);

        let key = test_key("no-auto-type");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save entry");
        let loaded = load_kdbx(&bytes, &key).expect("load entry");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert_eq!(loaded_entry.auto_type, None);
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected_bytes
        );
    }

    #[test]
    fn present_empty_entry_text_options_survive_kdbx_roundtrip() {
        let mut foreground = Entry::new("empty foreground");
        foreground.foreground_color = Some(String::new());

        let mut background = Entry::new("empty background");
        background.background_color = Some(String::new());

        let mut override_url = Entry::new("empty override URL");
        override_url.override_url = Some(String::new());

        let mut auto_type = Entry::new("empty auto type sequence");
        auto_type
            .auto_type
            .as_mut()
            .expect("default auto type")
            .default_sequence = Some(String::new());

        for (case, entry) in [
            ("foreground", foreground),
            ("background", background),
            ("override-url", override_url),
            ("auto-type-default-sequence", auto_type),
        ] {
            let expected = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
            let mut vault = Vault::empty(case);
            vault.root.entries.push(entry);
            let key = test_key(case);
            let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save entry");
            let loaded = load_kdbx(&bytes, &key).expect("load entry");
            let loaded_entry = loaded.root.entries.first().expect("loaded entry");

            assert_eq!(
                canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
                expected,
                "{case}"
            );
        }
    }

    #[test]
    fn save_rejects_present_nil_entry_custom_icon_id() {
        let mut entry = Entry::new("nil custom icon");
        entry.custom_icon_id = Some(uuid::Uuid::nil());
        let mut vault = Vault::empty("nil custom icon");
        vault.root.entries.push(entry);
        let key = test_key("nil-custom-icon");

        assert!(matches!(
            save_kdbx(&vault, &key, &fast_profile()),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn blank_entry_custom_icon_id_parses_as_none() {
        let mut element = Element::new("Entry");
        element.children.push(XMLNode::Element(text_element(
            "UUID",
            &super::encode_uuid(uuid::Uuid::nil()),
        )));
        element
            .children
            .push(XMLNode::Element(text_element("CustomIconUUID", " \n\t ")));
        let mut protected = ProtectedStream::from_stream(2, &[0x42; 32]).expect("stream");
        let mut content_pool = vaultkern_model::AttachmentContentPool::new();

        let entry = super::parse_entry(&element, &[], &mut content_pool, &mut protected)
            .expect("parse entry with blank custom icon");

        assert_eq!(entry.custom_icon_id, None);
    }

    #[test]
    fn nil_entry_custom_icon_id_parses_as_none() {
        let mut element = Element::new("Entry");
        element.children.push(XMLNode::Element(text_element(
            "UUID",
            &super::encode_uuid(uuid::Uuid::new_v4()),
        )));
        element.children.push(XMLNode::Element(text_element(
            "CustomIconUUID",
            &super::encode_uuid(uuid::Uuid::nil()),
        )));
        let mut protected = ProtectedStream::from_stream(2, &[0x42; 32]).expect("stream");
        let mut content_pool = vaultkern_model::AttachmentContentPool::new();

        let entry = super::parse_entry(&element, &[], &mut content_pool, &mut protected)
            .expect("parse entry with nil custom icon");

        assert_eq!(entry.custom_icon_id, None);
    }

    #[test]
    fn negative_signed_entry_times_survive_kdbx_roundtrip() {
        let mut entry = Entry::new("negative timestamps");
        entry.expiry_time = Some(-1);
        entry
            .custom_data
            .insert("timestamped".into(), "value".into());
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "timestamped".into(),
                value: "value".into(),
                last_modified: Some(-2),
            }],
            after: None,
        });
        let expected = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let mut vault = Vault::empty("negative timestamps");
        vault.root.entries.push(entry);
        let key = test_key("negative-timestamps");

        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save entry");
        let loaded = load_kdbx(&bytes, &key).expect("load entry");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert_eq!(loaded_entry.expiry_time, Some(-1));
        assert_eq!(
            loaded_entry.custom_data_blocks[0].items[0].last_modified,
            Some(-2)
        );
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected
        );
    }

    #[test]
    fn chained_custom_data_anchors_preserve_duplicate_key_order() {
        let mut entry = Entry::new("chained custom data anchors");
        entry.custom_data.insert("duplicate".into(), "third".into());
        entry.custom_data_blocks = [
            ("first", "Times"),
            ("second", "CustomData"),
            ("third", "AutoType"),
        ]
        .into_iter()
        .map(|(value, anchor)| CustomDataBlock {
            items: vec![CustomDataItem {
                key: "duplicate".into(),
                value: value.into(),
                last_modified: None,
            }],
            after: Some(OpaqueXmlAnchor {
                element_name: anchor.into(),
                occurrence: 1,
            }),
        })
        .collect();
        entry.raw_state.node_order = [
            "Times",
            "CustomData",
            "CustomData",
            "AutoType",
            "CustomData",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let expected = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let mut vault = Vault::empty("chained custom data anchors");
        vault.root.entries.push(entry);
        let key = test_key("chained-custom-data-anchors");

        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save entry");
        let loaded = load_kdbx(&bytes, &key).expect("load entry");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");
        let values = loaded_entry
            .custom_data_blocks
            .iter()
            .flat_map(|block| &block.items)
            .map(|item| item.value.as_str())
            .collect::<Vec<_>>();

        assert_eq!(values, ["first", "second", "third"]);
        assert_eq!(loaded_entry.custom_data["duplicate"], "third");
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected
        );
    }

    #[test]
    fn raw_typed_spellings_survive_write_when_they_match_semantics() {
        let mut vault = Vault::empty("raw typed spellings");
        vault.root.flags.enable_auto_type = Some(true);
        vault.root.raw_state.enable_auto_type_raw = Some(" 1 ".into());

        let mut entry = Entry::new("entry");
        entry.tags = ["alpha".into(), "beta".into()].into_iter().collect();
        entry.raw_state.tags_raw = Some(" beta , alpha ".into());
        entry.exclude_from_reports = true;
        entry.raw_state.quality_check_raw = Some(" 0 ".into());
        vault.root.entries.push(entry);

        let xml = super::build_xml(
            &vault,
            &std::collections::HashMap::new(),
            &[0_u8; 64],
            KdbxVersion::V4_1,
        )
        .expect("build xml");
        let parsed = Element::parse(std::io::Cursor::new(xml)).expect("parse generated xml");
        let group = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .expect("group");
        assert_eq!(child_text(group, "EnableAutoType").as_deref(), Some(" 1 "));
        let entry = group.get_child("Entry").expect("entry");
        assert_eq!(child_text(entry, "Tags").as_deref(), Some(" beta , alpha "));
        assert_eq!(child_text(entry, "QualityCheck").as_deref(), Some(" 0 "));
    }

    #[test]
    fn save_rejects_contradictory_raw_and_typed_replicas() {
        let mut meta = Vault::empty("meta raw contradiction");
        meta.description = Some("semantic".into());
        meta.meta_raw_state.description_raw = Some("different".into());

        let mut group = Vault::empty("group raw contradiction");
        group.root.flags.enable_searching = Some(true);
        group.root.raw_state.enable_searching_raw = Some("False".into());

        let mut entry = Vault::empty("entry raw contradiction");
        let mut item = Entry::new("entry");
        item.tags.insert("semantic".into());
        item.raw_state.tags_raw = Some("different".into());
        entry.root.entries.push(item);

        for vault in [meta, group, entry] {
            assert!(matches!(
                save_kdbx(&vault, &test_key("raw contradiction"), &fast_profile()),
                Err(KdbxError::InvalidValue)
            ));
        }
    }

    #[test]
    fn missing_custom_data_anchor_is_rejected() {
        let mut entry = Entry::new("missing custom data anchor");
        entry
            .custom_data
            .insert("duplicate".into(), "second".into());
        entry.custom_data_blocks = [("first", "ForegroundColor"), ("second", "Times")]
            .into_iter()
            .map(|(value, anchor)| CustomDataBlock {
                items: vec![CustomDataItem {
                    key: "duplicate".into(),
                    value: value.into(),
                    last_modified: None,
                }],
                after: Some(OpaqueXmlAnchor {
                    element_name: anchor.into(),
                    occurrence: 1,
                }),
            })
            .collect();
        entry.raw_state.node_order = ["Times", "ForegroundColor", "CustomData", "CustomData"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut vault = Vault::empty("missing custom data anchor");
        vault.root.entries.push(entry);
        let key = test_key("missing-custom-data-anchor");

        assert!(matches!(
            save_kdbx(&vault, &key, &fast_profile()),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn mixed_empty_and_timestamped_custom_data_blocks_roundtrip_without_flattening() {
        let mut entry = Entry::new("mixed custom data blocks");
        entry
            .custom_data
            .insert("timestamped".into(), "value".into());
        entry.custom_data_blocks = vec![
            CustomDataBlock {
                items: Vec::new(),
                after: None,
            },
            CustomDataBlock {
                items: vec![CustomDataItem {
                    key: "timestamped".into(),
                    value: "value".into(),
                    last_modified: Some(456),
                }],
                after: Some(OpaqueXmlAnchor {
                    element_name: "CustomData".into(),
                    occurrence: 1,
                }),
            },
        ];
        let expected = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let mut vault = Vault::empty("mixed custom data blocks");
        vault.root.entries.push(entry);
        let key = test_key("mixed-custom-data-blocks");

        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save entry");
        let loaded = load_kdbx(&bytes, &key).expect("load entry");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert_eq!(loaded_entry.custom_data_blocks.len(), 2);
        assert!(loaded_entry.custom_data_blocks[0].items.is_empty());
        assert_eq!(
            loaded_entry.custom_data_blocks[1].items[0].last_modified,
            Some(456)
        );
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected
        );
    }

    #[test]
    fn required_version_accounts_for_timestamped_custom_data_at_every_level() {
        fn add_timestamped_item(
            merged: &mut std::collections::BTreeMap<String, String>,
            blocks: &mut Vec<CustomDataBlock>,
        ) {
            merged.insert("timestamped".into(), "value".into());
            blocks.push(CustomDataBlock {
                items: vec![CustomDataItem {
                    key: "timestamped".into(),
                    value: "value".into(),
                    last_modified: Some(7),
                }],
                after: None,
            });
        }

        let mut meta = Vault::empty("meta custom data");
        add_timestamped_item(
            &mut meta.meta_custom_data,
            &mut meta.meta_custom_data_blocks,
        );

        let mut group = Vault::empty("group custom data");
        add_timestamped_item(
            &mut group.root.custom_data,
            &mut group.root.custom_data_blocks,
        );

        let mut current = Vault::empty("entry custom data");
        let mut current_entry = Entry::new("current");
        add_timestamped_item(
            &mut current_entry.custom_data,
            &mut current_entry.custom_data_blocks,
        );
        current.root.entries.push(current_entry);

        let mut history = Vault::empty("history custom data");
        let mut live_entry = Entry::new("live");
        let mut history_entry = Entry::new("history");
        add_timestamped_item(
            &mut history_entry.custom_data,
            &mut history_entry.custom_data_blocks,
        );
        live_entry.history.push(history_entry);
        history.root.entries.push(live_entry);

        for (case, vault) in [
            ("meta", meta),
            ("group", group),
            ("current entry", current),
            ("history entry", history),
        ] {
            assert_eq!(required_version(&vault), KdbxVersion::V4_1, "{case}");
        }
    }

    #[test]
    fn required_version_accounts_for_each_custom_icon_4_1_field() {
        for (case, name, last_modified) in [
            ("name", Some("icon".to_string()), None),
            ("last modified", None, Some(11)),
        ] {
            let mut vault = Vault::empty(case);
            vault.custom_icons.push(CustomIcon {
                id: uuid::Uuid::new_v4(),
                data: vec![1, 2, 3],
                name,
                last_modified,
            });

            assert_eq!(required_version(&vault), KdbxVersion::V4_1, "{case}");
        }
    }

    #[test]
    fn required_version_recurses_into_history_entry_metadata() {
        let root = Vault::empty("history metadata").root;
        for (case, previous_parent, exclude_from_reports) in [
            ("previous parent", Some(root.id), false),
            ("exclude from reports", None, true),
        ] {
            let mut vault = Vault::empty(case);
            let mut live_entry = Entry::new("live");
            let mut history_entry = Entry::new("history");
            history_entry.previous_parent = previous_parent;
            history_entry.exclude_from_reports = exclude_from_reports;
            live_entry.history.push(history_entry);
            vault.root.entries.push(live_entry);

            assert_eq!(required_version(&vault), KdbxVersion::V4_1, "{case}");
        }
    }

    #[test]
    fn required_version_observes_raw_quality_check_and_projectable_passkey_sources() {
        let mut raw_quality = Vault::empty("raw quality check");
        let mut entry = Entry::new("entry");
        entry.raw_state.quality_check_raw = Some("true".into());
        raw_quality.root.entries.push(entry);
        assert_eq!(required_version(&raw_quality), KdbxVersion::V4_1);

        let mut raw_passkey = Vault::empty("raw passkey");
        let mut entry = Entry::new("entry");
        for (key, value) in [
            (PasskeyRecord::USERNAME_KEY, "alice"),
            (PasskeyRecord::CREDENTIAL_ID_KEY, "credential"),
            (PasskeyRecord::PRIVATE_KEY_PEM_KEY, "private-key"),
            (PasskeyRecord::RELYING_PARTY_KEY, "example.com"),
        ] {
            entry.attributes.insert(
                key.into(),
                CustomField {
                    value: value.into(),
                    protected: false,
                },
            );
        }
        raw_passkey.root.entries.push(entry);
        assert_eq!(required_version(&raw_passkey), KdbxVersion::V4_1);
    }

    #[test]
    fn save_rejects_a_profile_below_the_vaults_required_version() {
        let mut vault = Vault::empty("minimum version");
        let mut entry = Entry::new("timestamped");
        entry.custom_data.insert("key".into(), "value".into());
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "key".into(),
                value: "value".into(),
                last_modified: Some(13),
            }],
            after: None,
        });
        vault.root.entries.push(entry);
        let mut profile = fast_profile();
        profile.version = KdbxVersion::V4_0;

        assert!(matches!(
            save_kdbx(&vault, &test_key("minimum-version"), &profile),
            Err(KdbxError::UnsupportedVersion)
        ));
    }

    #[test]
    fn save_rejects_legacy_write_profiles_before_emitting_kdbx4_payloads() {
        let vault = Vault::empty("unsupported writer version");
        for version in [KdbxVersion::V2_0, KdbxVersion::V3_0, KdbxVersion::V3_1] {
            let mut profile = fast_profile();
            profile.version = version;
            assert!(
                matches!(
                    save_kdbx(&vault, &test_key("unsupported-version"), &profile),
                    Err(KdbxError::UnsupportedVersion)
                ),
                "legacy writer version was accepted: {version:?}"
            );
        }
    }

    #[test]
    fn save_rejects_nil_and_duplicate_live_object_ids() {
        let mut cases = Vec::new();

        let mut nil_group = Vault::empty("nil group");
        nil_group.root.id = uuid::Uuid::nil();
        cases.push(("nil group", nil_group));

        let mut nil_entry = Vault::empty("nil entry");
        let mut entry = Entry::new("entry");
        entry.id = uuid::Uuid::nil();
        nil_entry.root.entries.push(entry);
        cases.push(("nil entry", nil_entry));

        let mut duplicate_live = Vault::empty("duplicate live");
        let mut entry = Entry::new("entry");
        entry.id = duplicate_live.root.id;
        duplicate_live.root.entries.push(entry);
        cases.push(("duplicate live", duplicate_live));

        let mut duplicate_icons = Vault::empty("duplicate icons");
        let icon_id = uuid::Uuid::new_v4();
        duplicate_icons.custom_icons.extend([
            CustomIcon {
                id: icon_id,
                data: vec![1],
                name: None,
                last_modified: None,
            },
            CustomIcon {
                id: icon_id,
                data: vec![2],
                name: None,
                last_modified: None,
            },
        ]);
        cases.push(("duplicate custom icons", duplicate_icons));

        let mut mismatched_history = Vault::empty("history UUID");
        let mut live = Entry::new("live");
        live.history.push(Entry::new("snapshot with another UUID"));
        mismatched_history.root.entries.push(live);
        cases.push(("history UUID mismatch", mismatched_history));

        for (case, vault) in cases {
            assert!(
                matches!(
                    save_kdbx(&vault, &test_key(case), &fast_profile()),
                    Err(KdbxError::InvalidValue)
                ),
                "invalid graph was accepted: {case}"
            );
        }
    }

    #[test]
    fn save_rejects_nil_optional_uuid_values_at_every_graph_level() {
        let mut cases = Vec::new();

        let mut meta = Vault::empty("meta optional UUID");
        meta.recycle_bin_group = Some(uuid::Uuid::nil());
        cases.push(("meta", meta));

        let mut group = Vault::empty("group optional UUID");
        group.root.previous_parent = Some(uuid::Uuid::nil());
        cases.push(("group", group));

        let mut entry = Vault::empty("entry optional UUID");
        let mut live = Entry::new("entry");
        live.previous_parent = Some(uuid::Uuid::nil());
        entry.root.entries.push(live);
        cases.push(("entry", entry));

        for (case, vault) in cases {
            assert!(
                matches!(
                    save_kdbx(&vault, &test_key(case), &fast_profile()),
                    Err(KdbxError::InvalidValue)
                ),
                "nil optional UUID was accepted at {case} scope"
            );
        }
    }

    #[test]
    fn previous_parent_uuid_loader_uses_the_typed_optional_matrix() {
        let valid = uuid::Uuid::new_v4();
        for (case, wire_value, expected) in [
            ("empty", String::new(), None),
            ("whitespace", " \t\n".into(), None),
            ("nil", super::encode_uuid(uuid::Uuid::nil()), None),
            ("valid", super::encode_uuid(valid), Some(valid)),
        ] {
            let mut vault = Vault::empty(case);
            vault.root.previous_parent = Some(valid);
            let mut entry = Entry::new("entry");
            entry.previous_parent = Some(valid);
            vault.root.entries.push(entry);
            let mut xml = super::group_to_xml(
                &vault.root,
                &std::collections::HashMap::new(),
                KdbxVersion::V4_1,
            )
            .expect("build group XML");
            xml.get_mut_child("PreviousParentGroup")
                .expect("group previous parent")
                .children = vec![XMLNode::Text(wire_value.clone())];
            xml.get_mut_child("Entry")
                .and_then(|entry| entry.get_mut_child("PreviousParentGroup"))
                .expect("entry previous parent")
                .children = vec![XMLNode::Text(wire_value)];

            let mut content_pool = vaultkern_model::AttachmentContentPool::new();
            let parsed = super::parse_group(
                &xml,
                &[],
                &mut content_pool,
                &mut ProtectedStream::new_plain(),
            )
            .unwrap_or_else(|error| panic!("parse {case} group XML: {error:?}"));
            assert_eq!(parsed.previous_parent, expected, "group {case}");
            assert_eq!(parsed.entries[0].previous_parent, expected, "entry {case}");
        }

        let mut vault = Vault::empty("malformed");
        vault.root.previous_parent = Some(valid);
        let mut xml = super::group_to_xml(
            &vault.root,
            &std::collections::HashMap::new(),
            KdbxVersion::V4_1,
        )
        .expect("build malformed group XML");
        xml.get_mut_child("PreviousParentGroup")
            .expect("group previous parent")
            .children = vec![XMLNode::Text("not-a-uuid".into())];
        let mut content_pool = vaultkern_model::AttachmentContentPool::new();
        assert!(matches!(
            super::parse_group(
                &xml,
                &[],
                &mut content_pool,
                &mut ProtectedStream::new_plain(),
            ),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn save_rejects_optional_text_values_that_collapse_to_absence() {
        let mut cases = Vec::new();
        let mut generator = Vault::empty("generator");
        generator.generator = Some(String::new());
        cases.push(("generator", generator));
        let mut description = Vault::empty("description");
        description.description = Some(String::new());
        cases.push(("description", description));
        let mut default_username = Vault::empty("default username");
        default_username.default_username = Some(String::new());
        cases.push(("default username", default_username));
        let mut color = Vault::empty("color");
        color.color = Some(String::new());
        cases.push(("color", color));
        let mut icon_name = Vault::empty("icon name");
        icon_name.custom_icons.push(CustomIcon {
            id: uuid::Uuid::new_v4(),
            data: vec![1],
            name: Some(String::new()),
            last_modified: None,
        });
        cases.push(("custom icon name", icon_name));
        let mut group_sequence = Vault::empty("group sequence");
        group_sequence.root.default_auto_type_sequence = Some(String::new());
        cases.push(("group default sequence", group_sequence));

        for (case, vault) in cases {
            assert!(
                matches!(
                    save_kdbx(&vault, &test_key(case), &fast_profile()),
                    Err(KdbxError::InvalidValue)
                ),
                "collapsible optional text was accepted: {case}"
            );
        }
    }

    #[test]
    fn save_rejects_tags_with_ambiguous_delimiters_or_boundary_whitespace() {
        for tag in [
            "",
            "one,two",
            "one;two",
            " leading",
            "trailing ",
            "\u{2003}wide",
        ] {
            let mut vault = Vault::empty("invalid tag");
            vault.root.tags.insert(tag.into());
            let mut entry = Entry::new("entry");
            entry.tags.insert(tag.into());
            vault.root.entries.push(entry);

            assert!(
                matches!(
                    save_kdbx(&vault, &test_key("invalid-tag"), &fast_profile()),
                    Err(KdbxError::InvalidValue)
                ),
                "invalid tag was accepted: {tag:?}"
            );
        }
    }

    #[test]
    fn loaded_tags_split_both_delimiters_and_trim_unicode_whitespace() {
        assert_eq!(
            super::parse_tags(" alpha,\u{2003}beta ; gamma ,, ; "),
            std::collections::BTreeSet::from(["alpha".into(), "beta".into(), "gamma".into(),])
        );
    }

    #[test]
    fn save_rejects_unrepresentable_kdbx4_timestamps() {
        let mut unsigned = Vault::empty("unsigned timestamp");
        unsigned.root.times = Some(vaultkern_model::GroupTimes {
            created_at: u64::MAX,
            modified_at: 0,
            expires: false,
            expiry_time: None,
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        });
        let mut too_early = Vault::empty("early timestamp");
        too_early.settings_changed = Some(i64::MIN);
        let mut too_late = Vault::empty("late timestamp");
        too_late.settings_changed = Some(i64::MAX);

        for (case, vault) in [
            ("unsigned", unsigned),
            ("too early", too_early),
            ("too late", too_late),
        ] {
            assert!(
                matches!(
                    save_kdbx(&vault, &test_key(case), &fast_profile()),
                    Err(KdbxError::InvalidValue)
                ),
                "unrepresentable timestamp was accepted: {case}"
            );
        }
    }

    #[test]
    fn save_rejects_invalid_opaque_and_custom_data_anchors() {
        let mut dangling = Vault::empty("dangling opaque anchor");
        let mut entry = Entry::new("entry");
        entry.opaque_xml.push(OpaqueXmlFragment {
            xml: "<FutureNode/>".into(),
            after: Some(OpaqueXmlAnchor {
                element_name: "String".into(),
                occurrence: 99,
            }),
        });
        dangling.root.entries.push(entry);

        let mut known_collision = Vault::empty("known opaque collision");
        let mut entry = Entry::new("entry");
        entry.opaque_xml.push(OpaqueXmlFragment {
            xml: "<Tags>shadow</Tags>".into(),
            after: None,
        });
        known_collision.root.entries.push(entry);

        let mut forward_block = Vault::empty("forward block anchor");
        let mut entry = Entry::new("entry");
        entry.custom_data.insert("key".into(), "value".into());
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "key".into(),
                value: "value".into(),
                last_modified: None,
            }],
            after: Some(OpaqueXmlAnchor {
                element_name: "CustomData".into(),
                occurrence: 1,
            }),
        });
        forward_block.root.entries.push(entry);

        for (case, vault) in [
            ("dangling opaque anchor", dangling),
            ("known opaque collision", known_collision),
            ("forward custom-data anchor", forward_block),
        ] {
            assert!(
                matches!(
                    save_kdbx(&vault, &test_key(case), &fast_profile()),
                    Err(KdbxError::InvalidValue) | Err(KdbxError::Xml(_))
                ),
                "invalid fidelity state was accepted: {case}"
            );
        }
    }

    #[test]
    fn save_rejects_raw_fidelity_slots_without_modeled_nodes() {
        let mut missing_key = Vault::empty("missing keyed identity");
        let mut entry = Entry::new("entry");
        entry.raw_state.node_order.push("String".into());
        entry.raw_state.string_order.push("missing".into());
        missing_key.root.entries.push(entry);

        let mut missing_singleton = Vault::empty("missing singleton");
        let mut entry = Entry::new("entry");
        entry.raw_state.node_order.push("CustomIconUUID".into());
        missing_singleton.root.entries.push(entry);

        for vault in [missing_key, missing_singleton] {
            assert!(matches!(
                save_kdbx(&vault, &test_key("raw fidelity"), &fast_profile()),
                Err(KdbxError::InvalidValue)
            ));
        }
    }

    #[test]
    fn deleted_objects_fold_latest_reject_unknown_and_write_in_uuid_order() {
        fn deleted_element(id: uuid::Uuid, deleted_at: i64) -> Element {
            let mut element = Element::new("DeletedObject");
            element.children.push(XMLNode::Element(text_element(
                "UUID",
                &super::encode_uuid(id),
            )));
            element.children.push(XMLNode::Element(text_element(
                "DeletionTime",
                &super::datetime_text(KdbxVersion::V4_1, deleted_at),
            )));
            element
        }

        fn root_with_deleted(children: Vec<Element>) -> Element {
            let mut deleted = Element::new("DeletedObjects");
            deleted
                .children
                .extend(children.into_iter().map(XMLNode::Element));
            let mut root_node = Element::new("Root");
            root_node.children.push(XMLNode::Element(deleted));
            let mut root = Element::new("KeePassFile");
            root.children.push(XMLNode::Element(root_node));
            root
        }

        let lower = uuid::Uuid::from_bytes([0x10; 16]);
        let higher = uuid::Uuid::from_bytes([0x20; 16]);
        let root = root_with_deleted(vec![
            deleted_element(higher, 7),
            deleted_element(lower, 3),
            deleted_element(higher, 11),
            deleted_element(lower, 3),
        ]);
        let parsed = super::parse_deleted_objects(&root).expect("fold tombstones");
        assert_eq!(
            parsed,
            vec![
                DeletedObject {
                    id: lower,
                    deleted_at: 3,
                },
                DeletedObject {
                    id: higher,
                    deleted_at: 11,
                },
            ]
        );

        let mut unknown = Element::new("UnknownTombstoneState");
        unknown
            .children
            .push(XMLNode::Text("must not disappear".into()));
        assert!(matches!(
            super::parse_deleted_objects(&root_with_deleted(vec![unknown])),
            Err(KdbxError::InvalidValue)
        ));

        let written = super::deleted_objects_to_xml(
            &[
                DeletedObject {
                    id: higher,
                    deleted_at: 11,
                },
                DeletedObject {
                    id: lower,
                    deleted_at: 3,
                },
            ],
            KdbxVersion::V4_1,
        );
        let written_ids: Vec<_> = written
            .children
            .iter()
            .filter_map(|child| match child {
                XMLNode::Element(child) => child_text(child, "UUID"),
                _ => None,
            })
            .map(|value| super::decode_uuid(&value).expect("written UUID"))
            .collect();
        assert_eq!(written_ids, vec![lower, higher]);
    }

    #[test]
    fn save_rejects_nil_or_duplicate_deleted_objects() {
        let duplicate_id = uuid::Uuid::new_v4();
        for (case, deleted_objects) in [
            (
                "nil",
                vec![DeletedObject {
                    id: uuid::Uuid::nil(),
                    deleted_at: 1,
                }],
            ),
            (
                "duplicate",
                vec![
                    DeletedObject {
                        id: duplicate_id,
                        deleted_at: 1,
                    },
                    DeletedObject {
                        id: duplicate_id,
                        deleted_at: 2,
                    },
                ],
            ),
        ] {
            let mut vault = Vault::empty(case);
            vault.deleted_objects = deleted_objects;
            assert!(
                matches!(
                    save_kdbx(&vault, &test_key(case), &fast_profile()),
                    Err(KdbxError::InvalidValue)
                ),
                "invalid tombstones were accepted: {case}"
            );
        }
    }

    #[test]
    fn save_rejects_standard_entry_field_names_in_custom_attributes() {
        for field_name in ["Title", "UserName", "Password", "URL", "Notes"] {
            let mut entry = Entry::new(format!("reserved {field_name}"));
            entry.attributes.insert(
                field_name.into(),
                CustomField {
                    value: "shadowed".into(),
                    protected: false,
                },
            );
            let mut vault = Vault::empty(field_name);
            vault.root.entries.push(entry);

            assert!(
                matches!(
                    save_kdbx(&vault, &test_key(field_name), &fast_profile()),
                    Err(KdbxError::InvalidValue)
                ),
                "{field_name}"
            );
        }
    }

    #[test]
    fn save_rejects_entry_text_values_that_cannot_roundtrip() {
        let mut empty_tag = Entry::new("empty tag");
        empty_tag.tags.insert(String::new());

        let mut delimited_tag = Entry::new("delimited tag");
        delimited_tag.tags.insert("one;two".into());

        let mut empty_attribute_key = Entry::new("empty attribute key");
        empty_attribute_key.attributes.insert(
            String::new(),
            CustomField {
                value: "value".into(),
                protected: false,
            },
        );

        let mut empty_attachment_name = Entry::new("empty attachment name");
        empty_attachment_name.attachments.insert(
            String::new(),
            Attachment::new(String::new(), b"content".to_vec(), false),
        );

        let mut empty_custom_data_key = Entry::new("empty custom data key");
        empty_custom_data_key
            .custom_data
            .insert(String::new(), "value".into());

        let mut empty_custom_data_item_key = Entry::new("empty custom data item key");
        empty_custom_data_item_key
            .custom_data_blocks
            .push(CustomDataBlock {
                items: vec![CustomDataItem {
                    key: String::new(),
                    value: "value".into(),
                    last_modified: None,
                }],
                after: None,
            });

        for (case, entry) in [
            ("empty-tag", empty_tag),
            ("delimited-tag", delimited_tag),
            ("empty-attribute-key", empty_attribute_key),
            ("empty-attachment-name", empty_attachment_name),
            ("empty-custom-data-key", empty_custom_data_key),
            ("empty-custom-data-item-key", empty_custom_data_item_key),
        ] {
            let mut vault = Vault::empty(case);
            vault.root.entries.push(entry);
            assert!(matches!(
                save_kdbx(&vault, &test_key(case), &fast_profile()),
                Err(KdbxError::InvalidValue)
            ));
        }
    }

    #[test]
    fn credential_projections_roundtrip_with_stable_canonical_content_and_times() {
        let entry = credential_entry();
        let expected_times = (
            entry.created_at,
            entry.modified_at,
            entry.expires,
            entry.expiry_time,
            entry.last_accessed_at,
            entry.usage_count,
            entry.location_changed_at,
        );
        let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let expected_hash = canonical_entry_content_hash_v1(&entry).expect("canonical hash");
        let mut vault = Vault::empty("CredentialRoundtrip");
        vault.root.entries.push(entry);

        let key = test_key("credential-roundtrip");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save credentials");
        let loaded = load_kdbx(&bytes, &key).expect("load credentials");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        for reserved_key in [
            "otp",
            "TimeOtp-Secret-Base32",
            "TimeOtp-Algorithm",
            "TimeOtp-Length",
            "TimeOtp-Period",
            PasskeyRecord::USERNAME_KEY,
            PasskeyRecord::CREDENTIAL_ID_KEY,
            PasskeyRecord::GENERATED_USER_ID_KEY,
            PasskeyRecord::PRIVATE_KEY_PEM_KEY,
            PasskeyRecord::RELYING_PARTY_KEY,
            PasskeyRecord::USER_HANDLE_KEY,
            PasskeyRecord::FLAG_BE_KEY,
            PasskeyRecord::FLAG_BS_KEY,
        ] {
            assert!(
                !loaded_entry.attributes.contains_key(reserved_key),
                "reserved projection field leaked into custom attributes: {reserved_key}"
            );
        }
        assert_eq!(
            (
                loaded_entry.created_at,
                loaded_entry.modified_at,
                loaded_entry.expires,
                loaded_entry.expiry_time,
                loaded_entry.last_accessed_at,
                loaded_entry.usage_count,
                loaded_entry.location_changed_at,
            ),
            expected_times
        );
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected_bytes
        );
        assert_eq!(
            canonical_entry_content_hash_v1(loaded_entry).expect("loaded canonical hash"),
            expected_hash
        );

        let mut changed = loaded_entry.clone();
        changed.totp.as_mut().expect("loaded TOTP").secret_base32 = "KRSXG5DSNFXGOIDB".into();
        assert_eq!(changed.modified_at, loaded_entry.modified_at);
        assert_ne!(
            canonical_entry_bytes_v1(&changed).expect("changed canonical bytes"),
            expected_bytes
        );
        assert_ne!(
            canonical_entry_content_hash_v1(&changed).expect("changed canonical hash"),
            expected_hash
        );
    }

    #[test]
    fn model_matrix_preserves_projection_replica_and_anchor_laws() {
        for totp_case in 0..4 {
            for passkey_case in 0..4 {
                for custom_data_case in 0..3 {
                    for anchored in [false, true] {
                        let mut entry = Entry::new(format!(
                            "matrix-{totp_case}-{passkey_case}-{custom_data_case}-{anchored}"
                        ));
                        match totp_case {
                            0 => {}
                            1 => {
                                entry.totp = Some(TotpSpec {
                                    secret_base32: "JBSWY3DPEHPK3PXP".into(),
                                    algorithm: TotpAlgorithm::Sha256,
                                    digits: 8,
                                    period_seconds: 45,
                                    issuer: Some("Matrix".into()),
                                    account_name: Some("user@example.com".into()),
                                });
                            }
                            2 => {
                                entry.attributes.insert(
                                    "otp".into(),
                                    CustomField {
                                        value: "otpauth://totp/Matrix:user%40example.com?secret=jbswy3dp%3D&issuer=Matrix&algorithm=SHA1&digits=6&period=30".into(),
                                        protected: false,
                                    },
                                );
                            }
                            3 => {
                                entry.attributes.insert(
                                    "HmacOtp-Secret-Hex".into(),
                                    CustomField {
                                        value: "deadbeef".into(),
                                        protected: false,
                                    },
                                );
                                entry.attributes.insert(
                                    "HmacOtp-Counter".into(),
                                    CustomField {
                                        value: "7".into(),
                                        protected: false,
                                    },
                                );
                            }
                            _ => unreachable!(),
                        }
                        match passkey_case {
                            0 => {}
                            1 => {
                                entry.passkey = Some(PasskeyRecord {
                                    username: "matrix-user".into(),
                                    credential_id: "Y3JlZGVudGlhbA".into(),
                                    generated_user_id: None,
                                    private_key_pem: "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n".into(),
                                    relying_party: "example.com".into(),
                                    user_handle: Some("aGFuZGxl".into()),
                                    backup_eligible: true,
                                    backup_state: false,
                                });
                            }
                            2 => {
                                for (key, value) in [
                                    (PasskeyRecord::USERNAME_KEY, "matrix-user"),
                                    (PasskeyRecord::CREDENTIAL_ID_KEY, "credential"),
                                    (PasskeyRecord::PRIVATE_KEY_PEM_KEY, "private-key"),
                                    (PasskeyRecord::RELYING_PARTY_KEY, "example.com"),
                                    (PasskeyRecord::FLAG_BE_KEY, "true"),
                                    (PasskeyRecord::FLAG_BS_KEY, "0"),
                                ] {
                                    entry.attributes.insert(
                                        key.into(),
                                        CustomField {
                                            value: value.into(),
                                            protected: false,
                                        },
                                    );
                                }
                            }
                            3 => {
                                entry.attributes.insert(
                                    PasskeyRecord::PRIVATE_KEY_PEM_KEY.into(),
                                    CustomField {
                                        value: "future-private-key".into(),
                                        protected: false,
                                    },
                                );
                                entry.attributes.insert(
                                    PasskeyRecord::FLAG_BE_KEY.into(),
                                    CustomField {
                                        value: "future".into(),
                                        protected: false,
                                    },
                                );
                            }
                            _ => unreachable!(),
                        }
                        match custom_data_case {
                            0 => {}
                            1 => {
                                entry.custom_data.insert("scope".into(), "one".into());
                                entry.custom_data_blocks.push(CustomDataBlock {
                                    items: vec![CustomDataItem {
                                        key: "scope".into(),
                                        value: "one".into(),
                                        last_modified: None,
                                    }],
                                    after: None,
                                });
                            }
                            2 => {
                                entry.custom_data = BTreeMap::from([
                                    ("scope".into(), "new".into()),
                                    ("stable".into(), "value".into()),
                                ]);
                                entry.custom_data_blocks = vec![
                                    CustomDataBlock {
                                        items: vec![CustomDataItem {
                                            key: "scope".into(),
                                            value: "old".into(),
                                            last_modified: None,
                                        }],
                                        after: None,
                                    },
                                    CustomDataBlock {
                                        items: vec![
                                            CustomDataItem {
                                                key: "scope".into(),
                                                value: "new".into(),
                                                last_modified: None,
                                            },
                                            CustomDataItem {
                                                key: "stable".into(),
                                                value: "value".into(),
                                                last_modified: None,
                                            },
                                        ],
                                        after: Some(OpaqueXmlAnchor {
                                            element_name: "CustomData".into(),
                                            occurrence: 1,
                                        }),
                                    },
                                ];
                            }
                            _ => unreachable!(),
                        }
                        if anchored {
                            entry.opaque_xml.push(OpaqueXmlFragment {
                                xml: "<MatrixOpaque />".into(),
                                after: Some(OpaqueXmlAnchor {
                                    element_name: "Times".into(),
                                    occurrence: 1,
                                }),
                            });
                        }

                        let expected_canonical =
                            canonical_entry_bytes_v1(&entry).expect("matrix canonical bytes");
                        let expected_blocks = entry.custom_data_blocks.clone();
                        let mut vault = Vault::empty("matrix");
                        vault.root.entries.push(entry);
                        let key = test_key("model-matrix");
                        let bytes = save_kdbx(&vault, &key, &fast_profile())
                            .expect("save valid matrix state");
                        let loaded = load_kdbx(&bytes, &key).expect("load valid matrix state");
                        let loaded_entry = &loaded.root.entries[0];

                        assert_eq!(
                            canonical_entry_bytes_v1(loaded_entry)
                                .expect("loaded matrix canonical bytes"),
                            expected_canonical
                        );
                        assert_eq!(loaded_entry.custom_data_blocks, expected_blocks);
                        assert_eq!(loaded_entry.opaque_xml.len(), usize::from(anchored));
                        if anchored {
                            assert_eq!(
                                loaded_entry.opaque_xml[0].after,
                                Some(OpaqueXmlAnchor {
                                    element_name: "Times".into(),
                                    occurrence: 1,
                                })
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn totp_label_edge_cases_roundtrip_with_stable_canonical_content() {
        for (case, issuer, account_name) in [
            ("leading-space-account", "Issuer", " alice"),
            ("encoded-colons", "Issuer:Prod", "account:west"),
        ] {
            let mut entry = credential_entry();
            let totp = entry.totp.as_mut().expect("credential TOTP");
            totp.issuer = Some(issuer.into());
            totp.account_name = Some(account_name.into());
            let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
            let expected_hash = canonical_entry_content_hash_v1(&entry).expect("canonical hash");
            let mut vault = Vault::empty(case);
            vault.root.entries.push(entry);

            let key = test_key(case);
            let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save credentials");
            let loaded = load_kdbx(&bytes, &key).expect("load credentials");
            let loaded_entry = loaded.root.entries.first().expect("loaded entry");

            assert_eq!(
                loaded_entry
                    .totp
                    .as_ref()
                    .and_then(|totp| totp.account_name.as_deref()),
                Some(account_name),
                "account name changed for {case}"
            );
            assert_eq!(
                canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
                expected_bytes,
                "canonical bytes changed for {case}"
            );
            assert_eq!(
                canonical_entry_content_hash_v1(loaded_entry).expect("loaded canonical hash"),
                expected_hash,
                "canonical hash changed for {case}"
            );
        }
    }

    #[test]
    fn persistence_rejects_noninvertible_structured_totp_states() {
        let key = test_key("invalid-structured-totp");
        for (case, mutate) in [
            ("missing-account", 0_u8),
            ("empty-account", 1),
            ("empty-secret", 2),
            ("empty-issuer", 3),
            ("colon-account-without-issuer", 4),
        ] {
            let mut entry = credential_entry();
            let totp = entry.totp.as_mut().expect("credential TOTP");
            match mutate {
                0 => totp.account_name = None,
                1 => totp.account_name = Some(String::new()),
                2 => totp.secret_base32.clear(),
                3 => totp.issuer = Some(String::new()),
                4 => {
                    totp.issuer = None;
                    totp.account_name = Some("account:west".into());
                }
                _ => unreachable!(),
            }
            let mut vault = Vault::empty(case);
            vault.root.entries.push(entry);

            assert!(matches!(
                save_kdbx(&vault, &key, &fast_profile()),
                Err(KdbxError::InvalidValue)
            ));
        }
    }

    #[test]
    fn persistence_rejects_missing_required_entry_time_state() {
        let key = test_key("invalid-entry-times");
        let mut missing_location = credential_entry();
        missing_location.location_changed_at = None;
        let mut vault = Vault::empty("missing location");
        vault.root.entries.push(missing_location);
        assert!(matches!(
            save_kdbx(&vault, &key, &fast_profile()),
            Err(KdbxError::InvalidValue)
        ));

        let mut missing_expiry = credential_entry();
        missing_expiry.expiry_time = None;
        let mut vault = Vault::empty("missing expiry");
        vault.root.entries.push(missing_expiry);
        assert!(matches!(
            save_kdbx(&vault, &key, &fast_profile()),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn absent_optional_entry_elements_remain_absent_while_location_becomes_epoch() {
        fn remove_options(entry: &mut Element) {
            entry.children.retain(|child| {
                !matches!(child, XMLNode::Element(element) if element.name == "IconID" || element.name == "AutoType")
            });
            let times = entry
                .children
                .iter_mut()
                .find_map(|child| match child {
                    XMLNode::Element(element) if element.name == "Times" => Some(element),
                    _ => None,
                })
                .expect("times");
            times.children.retain(|child| {
                !matches!(child, XMLNode::Element(element) if matches!(element.name.as_str(), "ExpiryTime" | "LastAccessTime" | "UsageCount" | "LocationChanged"))
            });
        }

        let mut entry = Entry::new("entry");
        let mut history = Entry::new("history");
        history.id = entry.id;
        entry.history.push(history);
        let mut vault = Vault::empty("absent entry options");
        vault.root.entries.push(entry);
        let key = test_key("absent-entry-options");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save source");
        let without_options = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = first_live_entry_mut(root);
            remove_options(entry);
            let history = entry
                .get_mut_child("History")
                .expect("history")
                .get_mut_child("Entry")
                .expect("history entry");
            remove_options(history);
        })
        .expect("remove optional elements");

        let loaded = load_kdbx(&without_options, &key).expect("load absent options");
        let entry = &loaded.root.entries[0];
        for candidate in [entry, &entry.history[0]] {
            assert_eq!(candidate.icon_id, None);
            assert_eq!(candidate.auto_type, None);
            assert_eq!(candidate.expiry_time, None);
            assert_eq!(candidate.last_accessed_at, None);
            assert_eq!(candidate.usage_count, None);
            assert_eq!(candidate.location_changed_at, Some(0));
        }

        let rewritten = save_kdbx(&loaded, &key, &fast_profile()).expect("rewrite absent options");
        let reloaded = load_kdbx(&rewritten, &key).expect("reload absent options");
        assert_eq!(reloaded.root.entries[0], *entry);
    }

    #[test]
    fn ordinary_saves_refresh_physical_encryption_material_but_not_kdf_state() {
        let key = test_key("fresh-physical-state");
        let first = save_kdbx(&Vault::empty("fresh physical state"), &key, &fast_profile())
            .expect("first save");
        let loaded = load_kdbx(&first, &key).expect("load first save");
        let second =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("ordinary second save");
        let first_header = KdbxHeader::decode(&first).expect("first header");
        let second_header = KdbxHeader::decode(&second).expect("second header");

        assert_eq!(
            first_header.kdf_parameters.encode().expect("first KDF"),
            second_header.kdf_parameters.encode().expect("second KDF")
        );
        assert_ne!(first_header.master_seed, second_header.master_seed);
        assert_ne!(first_header.encryption_iv, second_header.encryption_iv);
        assert_ne!(
            extract_kdbx4_inner_key(&first, &key).expect("first inner key"),
            extract_kdbx4_inner_key(&second, &key).expect("second inner key")
        );
    }

    #[test]
    fn ordinary_save_reemits_unknown_kdf_entries_verbatim_until_explicit_change() {
        fn push_entry(encoded: &mut Vec<u8>, kind: u8, key: &str, value: &[u8]) {
            encoded.push(kind);
            encoded.extend((key.len() as i32).to_le_bytes());
            encoded.extend(key.as_bytes());
            encoded.extend((value.len() as i32).to_le_bytes());
            encoded.extend(value);
        }

        let mut retained = 0x0100_u16.to_le_bytes().to_vec();
        push_entry(&mut retained, 0x42, "S", &[0x5a; 32]);
        push_entry(&mut retained, 0x77, "X-Future", &[0xde, 0xad]);
        push_entry(
            &mut retained,
            0x42,
            "$UUID",
            super::KDF_AES_KDBX4_UUID.as_bytes(),
        );
        push_entry(&mut retained, 0x05, "R", &1_u64.to_le_bytes());
        retained.push(0);

        let key = test_key("unknown-kdf-entry");
        let mut vault = Vault::empty("unknown KDF entry");
        vault.kdf_parameters = Some(retained.clone());
        let ordinary = save_kdbx(&vault, &key, &SaveProfile::recommended())
            .expect("ordinary save with retained dictionary");
        let ordinary_header = KdbxHeader::decode(&ordinary).expect("ordinary header");
        assert_eq!(
            ordinary_header
                .kdf_parameters
                .encode()
                .expect("ordinary KDF"),
            retained
        );

        let explicit = save_kdbx(&vault, &key, &fast_profile()).expect("explicit KDF change");
        let explicit_header = KdbxHeader::decode(&explicit).expect("explicit header");
        let explicit_kdf = explicit_header
            .kdf_parameters
            .encode()
            .expect("explicit KDF");
        assert_ne!(explicit_kdf, retained);
        assert!(explicit_header.kdf_parameters.get("X-Future").is_none());
    }

    #[test]
    fn ordinary_save_reemits_argon2_version_and_unknown_entries_verbatim() {
        fn push_entry(encoded: &mut Vec<u8>, kind: u8, key: &str, value: &[u8]) {
            encoded.push(kind);
            encoded.extend((key.len() as i32).to_le_bytes());
            encoded.extend(key.as_bytes());
            encoded.extend((value.len() as i32).to_le_bytes());
            encoded.extend(value);
        }

        let mut retained = 0x0100_u16.to_le_bytes().to_vec();
        push_entry(&mut retained, 0x04, "V", &0x13_u32.to_le_bytes());
        push_entry(&mut retained, 0x77, "X-Future", &[0xde, 0xad]);
        push_entry(&mut retained, 0x05, "M", &(8 * 1024_u64).to_le_bytes());
        push_entry(&mut retained, 0x42, "S", &[0x5a; 32]);
        push_entry(&mut retained, 0x04, "P", &1_u32.to_le_bytes());
        push_entry(
            &mut retained,
            0x42,
            "$UUID",
            super::KDF_ARGON2ID_UUID.as_bytes(),
        );
        push_entry(&mut retained, 0x05, "I", &1_u64.to_le_bytes());
        retained.push(0);

        let key = test_key("argon-version");
        let mut vault = Vault::empty("Argon version");
        vault.kdf_parameters = Some(retained.clone());
        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended())
            .expect("ordinary save with retained Argon2 dictionary");
        let header = KdbxHeader::decode(&bytes).expect("ordinary header");

        assert_eq!(
            header.kdf_parameters.encode().expect("ordinary KDF"),
            retained
        );
        load_kdbx(&bytes, &key).expect("retained Argon2 output decrypts");
    }

    #[test]
    fn whitespace_optional_entry_values_map_to_none_without_losing_text_children() {
        fn blank_options(entry: &mut Element) {
            let set_blank = |element: &mut Element| {
                element.children.clear();
                element.children.push(XMLNode::Text(" \n ".into()));
            };
            let icon = entry.get_mut_child("IconID").expect("icon ID");
            set_blank(icon);
            let times = entry.get_mut_child("Times").expect("times");
            for name in [
                "ExpiryTime",
                "LastAccessTime",
                "UsageCount",
                "LocationChanged",
            ] {
                set_blank(times.get_mut_child(name).expect("optional time"));
            }
            let auto_type = entry.get_mut_child("AutoType").expect("auto type");
            auto_type
                .children
                .push(XMLNode::Element(text_element("Enabled", " \n ")));
            auto_type.children.push(XMLNode::Element(text_element(
                "DataTransferObfuscation",
                " \n ",
            )));
            auto_type.children.push(XMLNode::Element(text_element(
                "DefaultSequence",
                " {USERNAME} ",
            )));
        }

        let mut entry = Entry::new("entry");
        let mut history = Entry::new("history");
        history.id = entry.id;
        entry.history.push(history);
        let mut vault = Vault::empty("blank entry options");
        vault.root.entries.push(entry);
        let key = test_key("blank-entry-options");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save source");
        let blank_options = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = first_live_entry_mut(root);
            blank_options(entry);
            let history = entry
                .get_mut_child("History")
                .expect("history")
                .get_mut_child("Entry")
                .expect("history entry");
            blank_options(history);
        })
        .expect("blank optional elements");

        let loaded = load_kdbx(&blank_options, &key).expect("load blank options");
        let entry = &loaded.root.entries[0];
        for candidate in [entry, &entry.history[0]] {
            assert_eq!(candidate.icon_id, None);
            assert_eq!(candidate.expiry_time, None);
            assert_eq!(candidate.last_accessed_at, None);
            assert_eq!(candidate.usage_count, None);
            assert_eq!(candidate.location_changed_at, Some(0));
            let auto_type = candidate.auto_type.as_ref().expect("present auto type");
            assert_eq!(auto_type.enabled, None);
            assert_eq!(auto_type.obfuscation, None);
            assert_eq!(auto_type.default_sequence.as_deref(), Some(" {USERNAME} "));
        }
    }

    #[test]
    fn present_empty_auto_type_maps_to_some_default_for_current_and_history_entries() {
        let mut entry = Entry::new("entry");
        let mut history = Entry::new("history");
        history.id = entry.id;
        entry.history.push(history);

        let mut vault = Vault::empty("empty auto type");
        vault.root.entries.push(entry);
        let key = test_key("empty-auto-type");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save source");
        let empty_auto_types = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = first_live_entry_mut(root);
            entry
                .get_mut_child("AutoType")
                .expect("current auto type")
                .children
                .clear();
            entry
                .get_mut_child("History")
                .expect("history")
                .get_mut_child("Entry")
                .expect("history entry")
                .get_mut_child("AutoType")
                .expect("history auto type")
                .children
                .clear();
        })
        .expect("empty auto type containers");

        let loaded = load_kdbx(&empty_auto_types, &key).expect("load empty auto types");
        let entry = &loaded.root.entries[0];
        assert_eq!(entry.auto_type, Some(AutoTypeConfig::default()));
        assert_eq!(entry.history[0].auto_type, Some(AutoTypeConfig::default()));

        let rewritten = save_kdbx(&loaded, &key, &SaveProfile::recommended())
            .expect("rewrite empty auto types");
        let reloaded = load_kdbx(&rewritten, &key).expect("reload empty auto types");
        assert_eq!(reloaded.root.entries[0].auto_type, entry.auto_type);
        assert_eq!(
            reloaded.root.entries[0].history[0].auto_type,
            entry.history[0].auto_type
        );
    }

    #[test]
    fn model_created_map_only_custom_data_is_rejected_as_unpersistable() {
        let mut entry = Entry::new("map-only-custom-data");
        entry
            .custom_data
            .insert("model-key".into(), "model-value".into());
        let mut vault = Vault::empty("map-only-custom-data");
        vault.root.entries.push(entry);
        let key = test_key("map-only-custom-data");

        assert!(matches!(
            save_kdbx(&vault, &key, &fast_profile()),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn unprojectable_totp_source_attributes_keep_canonical_content_after_roundtrip() {
        let mut entry = Entry::new("unmodeled-totp-source");
        entry.attributes.insert(
            "otp".into(),
            CustomField {
                value: "not-an-otpauth-uri".into(),
                protected: false,
            },
        );
        entry.attributes.insert(
            "TimeOtp-Period".into(),
            CustomField {
                value: "45".into(),
                protected: false,
            },
        );
        entry.attributes.insert(
            "ordinary".into(),
            CustomField {
                value: "kept".into(),
                protected: false,
            },
        );
        let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let expected_hash = canonical_entry_content_hash_v1(&entry).expect("canonical hash");
        let mut vault = Vault::empty("unmodeled-totp-source");
        vault.root.entries.push(entry);
        let key = test_key("unmodeled-totp-source");

        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save entry");
        let loaded = load_kdbx(&bytes, &key).expect("load entry");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert_eq!(loaded_entry.totp, None);
        assert_eq!(loaded_entry.attributes.len(), 3);
        assert_eq!(loaded_entry.attributes["otp"].value, "not-an-otpauth-uri");
        assert!(loaded_entry.attributes["otp"].protected);
        assert_eq!(loaded_entry.attributes["TimeOtp-Period"].value, "45");
        assert_eq!(loaded_entry.attributes["ordinary"].value, "kept");
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected_bytes
        );
        assert_eq!(
            canonical_entry_content_hash_v1(loaded_entry).expect("loaded canonical hash"),
            expected_hash
        );
    }

    #[test]
    fn lossy_otpauth_query_shapes_survive_kdbx_roundtrip_verbatim() {
        for (case, uri) in [
            (
                "unknown-query",
                "otpauth://totp/alice?secret=SECRET&image=logo.png",
            ),
            (
                "duplicate-query",
                "otpauth://totp/alice?secret=SECRET&secret=OTHER",
            ),
            (
                "missing-equals",
                "otpauth://totp/alice?secret=SECRET&issuer",
            ),
            (
                "empty-query-component",
                "otpauth://totp/alice?secret=SECRET&&period=30",
            ),
            ("invalid-query-utf8", "otpauth://totp/alice?secret=%FF"),
        ] {
            let mut entry = Entry::new(case);
            entry.attributes.insert(
                "otp".into(),
                CustomField {
                    value: uri.into(),
                    protected: false,
                },
            );
            let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
            let expected_hash = canonical_entry_content_hash_v1(&entry).expect("canonical hash");
            let mut vault = Vault::empty(case);
            vault.root.entries.push(entry);
            let key = test_key(case);

            let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save raw URI");
            let loaded = load_kdbx(&bytes, &key).expect("load raw URI");
            let loaded_entry = loaded.root.entries.first().expect("loaded entry");

            assert_eq!(loaded_entry.totp, None, "projected {case}");
            assert_eq!(loaded_entry.attributes["otp"].value, uri, "URI for {case}");
            assert!(
                loaded_entry.attributes["otp"].protected,
                "protection for {case}"
            );
            assert_eq!(
                canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
                expected_bytes,
                "bytes for {case}"
            );
            assert_eq!(
                canonical_entry_content_hash_v1(loaded_entry).expect("loaded canonical hash"),
                expected_hash,
                "hash for {case}"
            );
        }
    }

    #[test]
    fn conflicting_and_malformed_discrete_totp_sources_survive_roundtrip_verbatim() {
        let cases = [
            (
                "conflicting-secret",
                vec![
                    (
                        "otp",
                        "otpauth://totp/alice?secret=URISECRET&algorithm=SHA256&digits=8&period=45",
                    ),
                    ("TimeOtp-Secret-Base32", "DIFFERENT"),
                    ("TimeOtp-Algorithm", "HMAC-SHA-256"),
                    ("TimeOtp-Length", "8"),
                    ("TimeOtp-Period", "45"),
                ],
            ),
            (
                "malformed-algorithm",
                vec![
                    ("TimeOtp-Secret-Base32", "SECRET"),
                    ("TimeOtp-Algorithm", "MD5"),
                ],
            ),
            (
                "malformed-length",
                vec![
                    ("TimeOtp-Secret-Base32", "SECRET"),
                    ("TimeOtp-Length", "six"),
                ],
            ),
            (
                "malformed-period",
                vec![
                    ("TimeOtp-Secret-Base32", "SECRET"),
                    ("TimeOtp-Period", "thirty"),
                ],
            ),
        ];

        for (case, fields) in cases {
            let mut entry = Entry::new(case);
            for (key, value) in &fields {
                entry.attributes.insert(
                    (*key).into(),
                    CustomField {
                        value: (*value).into(),
                        protected: key == &"otp" || key == &"TimeOtp-Secret-Base32",
                    },
                );
            }
            let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
            let expected_hash = canonical_entry_content_hash_v1(&entry).expect("canonical hash");
            let mut vault = Vault::empty(case);
            vault.root.entries.push(entry);
            let key = test_key(case);

            let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save raw TOTP");
            let loaded = load_kdbx(&bytes, &key).expect("load raw TOTP");
            let loaded_entry = loaded.root.entries.first().expect("loaded entry");

            assert_eq!(loaded_entry.totp, None, "projected {case}");
            for (field_key, value) in fields {
                assert_eq!(
                    loaded_entry.attributes[field_key].value, value,
                    "value for {case}/{field_key}"
                );
            }
            assert_eq!(
                canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
                expected_bytes,
                "bytes for {case}"
            );
            assert_eq!(
                canonical_entry_content_hash_v1(loaded_entry).expect("loaded canonical hash"),
                expected_hash,
                "hash for {case}"
            );
        }
    }

    #[test]
    fn alternate_and_hotp_sources_survive_kdbx_roundtrip_verbatim() {
        let mut entry = Entry::new("raw OTP namespace");
        for (key, value) in [
            ("TimeOtp-Secret", "alternate-secret"),
            ("TimeOtp-Secret-Hex", "616c7465726e617465"),
            ("TimeOtp-Secret-Base64", "YWx0ZXJuYXRl"),
            ("HmacOtp-Secret", "hotp-secret"),
            ("HmacOtp-Secret-Hex", "686f7470"),
            ("HmacOtp-Secret-Base32", "NBUHI4A"),
            ("HmacOtp-Secret-Base64", "aG90cA=="),
            ("HmacOtp-Counter", "42"),
        ] {
            entry.attributes.insert(
                key.into(),
                CustomField {
                    value: value.into(),
                    protected: false,
                },
            );
        }
        let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let expected_hash = canonical_entry_content_hash_v1(&entry).expect("canonical hash");
        let mut vault = Vault::empty("raw OTP namespace");
        vault.root.entries.push(entry);
        let key = test_key("raw-otp-namespace");

        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save raw OTP");
        let loaded = load_kdbx(&bytes, &key).expect("load raw OTP");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert_eq!(loaded_entry.totp, None);
        assert_eq!(loaded_entry.attributes.len(), 8);
        for field in loaded_entry.attributes.values() {
            assert!(field.protected);
        }
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected_bytes
        );
        assert_eq!(
            canonical_entry_content_hash_v1(loaded_entry).expect("loaded canonical hash"),
            expected_hash
        );
    }

    #[test]
    fn invalid_passkey_flags_survive_kdbx_roundtrip_verbatim() {
        let mut entry = Entry::new("invalid passkey flag");
        for (key, value) in [
            (PasskeyRecord::USERNAME_KEY, "alice"),
            (PasskeyRecord::CREDENTIAL_ID_KEY, "credential"),
            (PasskeyRecord::PRIVATE_KEY_PEM_KEY, "private-key"),
            (PasskeyRecord::RELYING_PARTY_KEY, "example.com"),
            (PasskeyRecord::FLAG_BE_KEY, "yes"),
        ] {
            entry.attributes.insert(
                key.into(),
                CustomField {
                    value: value.into(),
                    protected: false,
                },
            );
        }
        let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let expected_hash = canonical_entry_content_hash_v1(&entry).expect("canonical hash");
        let mut vault = Vault::empty("invalid passkey flag");
        vault.root.entries.push(entry);
        let key = test_key("invalid-passkey-flag");

        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save raw passkey");
        let loaded = load_kdbx(&bytes, &key).expect("load raw passkey");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert_eq!(loaded_entry.passkey, None);
        assert_eq!(
            loaded_entry.attributes[PasskeyRecord::FLAG_BE_KEY].value,
            "yes"
        );
        assert!(loaded_entry.attributes[PasskeyRecord::CREDENTIAL_ID_KEY].protected);
        assert!(loaded_entry.attributes[PasskeyRecord::PRIVATE_KEY_PEM_KEY].protected);
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected_bytes
        );
        assert_eq!(
            canonical_entry_content_hash_v1(loaded_entry).expect("loaded canonical hash"),
            expected_hash
        );
    }

    #[test]
    fn save_rejects_nested_entry_history_for_every_write_version() {
        let mut snapshot = Entry::new("snapshot");
        snapshot.history.push(Entry::new("nested snapshot"));
        let mut live = Entry::new("live");
        live.history.push(snapshot);
        let mut vault = Vault::empty("nested history");
        vault.root.entries.push(live);

        for version in [KdbxVersion::V4_0, KdbxVersion::V4_1] {
            let mut profile = fast_profile();
            profile.version = version;
            assert!(
                matches!(
                    save_kdbx(&vault, &test_key("nested-history"), &profile),
                    Err(KdbxError::InvalidValue)
                ),
                "nested history was accepted for {version:?}"
            );
        }
    }

    #[test]
    fn complete_unprojected_passkey_attributes_keep_canonical_content_after_roundtrip() {
        let mut entry = Entry::new("unprojected-passkey-source");
        for (key, value) in [
            (PasskeyRecord::USERNAME_KEY, "alice"),
            (PasskeyRecord::CREDENTIAL_ID_KEY, "credential"),
            (PasskeyRecord::PRIVATE_KEY_PEM_KEY, "private-key"),
            (PasskeyRecord::RELYING_PARTY_KEY, "example.com"),
        ] {
            entry.attributes.insert(
                key.into(),
                CustomField {
                    value: value.into(),
                    protected: false,
                },
            );
        }
        let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let expected_hash = canonical_entry_content_hash_v1(&entry).expect("canonical hash");
        let mut vault = Vault::empty("unprojected-passkey-source");
        vault.root.entries.push(entry);
        let key = test_key("unprojected-passkey-source");

        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save entry");
        let loaded = load_kdbx(&bytes, &key).expect("load entry");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert!(loaded_entry.passkey.is_some());
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected_bytes
        );
        assert_eq!(
            canonical_entry_content_hash_v1(loaded_entry).expect("loaded canonical hash"),
            expected_hash
        );
    }

    #[test]
    fn incomplete_sensitive_passkey_attribute_keeps_canonical_content_after_roundtrip() {
        let mut entry = Entry::new("incomplete-passkey-source");
        entry.attributes.insert(
            PasskeyRecord::CREDENTIAL_ID_KEY.into(),
            CustomField {
                value: "credential".into(),
                protected: false,
            },
        );
        let expected_bytes = canonical_entry_bytes_v1(&entry).expect("canonical bytes");
        let expected_hash = canonical_entry_content_hash_v1(&entry).expect("canonical hash");
        let mut vault = Vault::empty("incomplete-passkey-source");
        vault.root.entries.push(entry);
        let key = test_key("incomplete-passkey-source");

        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save entry");
        let loaded = load_kdbx(&bytes, &key).expect("load entry");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert_eq!(loaded_entry.passkey, None);
        assert!(loaded_entry.attributes[PasskeyRecord::CREDENTIAL_ID_KEY].protected);
        assert_eq!(
            canonical_entry_bytes_v1(loaded_entry).expect("loaded canonical bytes"),
            expected_bytes
        );
        assert_eq!(
            canonical_entry_content_hash_v1(loaded_entry).expect("loaded canonical hash"),
            expected_hash
        );
    }

    #[test]
    fn imported_standard_otpauth_labels_materialize_stably() {
        for (case, uri, expected_issuer, expected_account) in [
            (
                "unprefixed-account",
                "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP",
                None,
                "alice",
            ),
            (
                "unprefixed-account-matching-issuer",
                "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                Some("GitHub"),
                "GitHub",
            ),
            (
                "encoded-separator",
                "otpauth://totp/Example%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
                Some("Example"),
                "alice",
            ),
            (
                "label-only-issuer",
                "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
                Some("Example"),
                "alice",
            ),
        ] {
            let mut entry = Entry::new("Fallback Issuer");
            entry.username = "fallback-account".into();
            entry.attributes.insert(
                "otp".into(),
                CustomField {
                    value: uri.into(),
                    protected: true,
                },
            );
            let mut vault = Vault::empty(case);
            vault.root.entries.push(entry);
            let key = test_key(case);

            let imported_bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save import");
            let imported = load_kdbx(&imported_bytes, &key).expect("load import");
            let imported_entry = imported.root.entries.first().expect("imported entry");
            let imported_totp = imported_entry.totp.as_ref().expect("imported TOTP");
            assert_eq!(imported_totp.issuer.as_deref(), expected_issuer, "{case}");
            assert_eq!(
                imported_totp.account_name.as_deref(),
                Some(expected_account),
                "{case}"
            );
            let expected_bytes =
                canonical_entry_bytes_v1(imported_entry).expect("imported canonical bytes");

            let rewritten = save_kdbx(&imported, &key, &fast_profile()).expect("rewrite import");
            let reloaded = load_kdbx(&rewritten, &key).expect("reload import");
            let reloaded_entry = reloaded.root.entries.first().expect("reloaded entry");
            assert_eq!(
                canonical_entry_bytes_v1(reloaded_entry).expect("reloaded canonical bytes"),
                expected_bytes,
                "canonical bytes changed for {case}"
            );
        }
    }

    #[test]
    fn credential_projection_writer_fields_are_exact() {
        let entry = credential_entry();
        let xml = super::entry_to_xml(
            &entry,
            &std::collections::HashMap::new(),
            false,
            KdbxVersion::V4_1,
        )
        .expect("build entry XML");
        let fields = projection_string_fields(&xml);
        let expected = [
            (PasskeyRecord::USERNAME_KEY, "alice@example.com", None),
            (
                PasskeyRecord::CREDENTIAL_ID_KEY,
                "credential-1",
                Some("True"),
            ),
            (PasskeyRecord::GENERATED_USER_ID_KEY, "generated-1", None),
            (
                PasskeyRecord::PRIVATE_KEY_PEM_KEY,
                "-----BEGIN PRIVATE KEY-----\nkey-1\n-----END PRIVATE KEY-----",
                Some("True"),
            ),
            (PasskeyRecord::RELYING_PARTY_KEY, "example.com", None),
            (
                PasskeyRecord::USER_HANDLE_KEY,
                "user-handle-1",
                Some("True"),
            ),
            (PasskeyRecord::FLAG_BE_KEY, "1", None),
            (PasskeyRecord::FLAG_BS_KEY, "0", None),
            (
                "otp",
                "otpauth://totp/Example%20Inc:alice%2Bprod%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Inc&algorithm=SHA256&digits=8&period=45",
                Some("True"),
            ),
            ("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP", Some("True")),
            ("TimeOtp-Algorithm", "HMAC-SHA-256", None),
            ("TimeOtp-Length", "8", None),
            ("TimeOtp-Period", "45", None),
        ];

        assert_eq!(fields.len(), expected.len());
        for (key, value, protected) in expected {
            assert_eq!(
                fields.get(key).map(|(actual_value, actual_protected)| {
                    (actual_value.as_str(), actual_protected.as_deref())
                }),
                Some((value, protected)),
                "unexpected persistent field: {key}"
            );
        }
    }

    #[test]
    fn loaded_entry_with_history_accepts_new_protected_totp_and_custom_field() {
        let mut vault = Vault::empty("ProtectedHistoryMutation");
        let mut entry = Entry::new("Live");
        entry.password = "live-password".into();
        let mut history = Entry::new("History");
        history.id = entry.id;
        history.password = "history-password".into();
        entry.history.push(history);
        vault.root.entries.push(entry);

        let key = test_key("protected-history-mutation");
        let seed = save_kdbx(&vault, &key, &fast_profile()).expect("save seed");
        let mut loaded = load_kdbx(&seed, &key).expect("load seed");
        let entry = &mut loaded.root.entries[0];
        entry.attributes.insert(
            "NewProtectedField".into(),
            CustomField {
                value: "new-custom-secret".into(),
                protected: true,
            },
        );
        entry.totp = Some(TotpSpec {
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
            algorithm: TotpAlgorithm::Sha256,
            digits: 8,
            period_seconds: 45,
            issuer: Some("Example".into()),
            account_name: Some("alice".into()),
        });

        let rewritten = save_kdbx(&loaded, &key, &fast_profile()).expect("save mutation");
        let reloaded = load_kdbx(&rewritten, &key).expect("load mutation");
        let entry = &reloaded.root.entries[0];

        assert_eq!(entry.password, "live-password");
        assert_eq!(entry.history[0].password, "history-password");
        assert_eq!(
            entry
                .attributes
                .get("NewProtectedField")
                .map(|field| (field.value.as_str(), field.protected)),
            Some(("new-custom-secret", true))
        );
        assert_eq!(
            entry.totp.as_ref().map(|totp| (
                totp.secret_base32.as_str(),
                totp.algorithm.clone(),
                totp.digits,
                totp.period_seconds,
            )),
            Some(("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha256, 8, 45))
        );
    }

    #[test]
    fn save_rejects_unprotected_xml_forbidden_characters() {
        let invalid_title = Entry::new("invalid\0title");
        let mut invalid_custom = Entry::new("Valid title");
        invalid_custom.attributes.insert(
            "Unprotected".into(),
            CustomField {
                value: "invalid\0value".into(),
                protected: false,
            },
        );

        for entry in [invalid_title, invalid_custom] {
            let mut vault = Vault::empty("InvalidXmlText");
            vault.root.entries.push(entry);
            assert!(matches!(
                save_kdbx(&vault, &test_key("invalid-xml-text"), &fast_profile()),
                Err(super::KdbxError::InvalidValue)
            ));
        }
    }

    #[test]
    fn protected_xml_forbidden_characters_roundtrip() {
        let mut vault = Vault::empty("ProtectedInvalidXmlText");
        let mut entry = Entry::new("Protected");
        entry.password = "password\0value".into();
        entry.attributes.insert(
            "ProtectedValue".into(),
            CustomField {
                value: "custom\0value".into(),
                protected: true,
            },
        );
        vault.root.entries.push(entry);
        let key = test_key("protected-invalid-xml-text");

        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save protected text");
        let loaded = load_kdbx(&bytes, &key).expect("load protected text");

        assert_eq!(loaded.root.entries[0].password, "password\0value");
        assert_eq!(
            loaded.root.entries[0].attributes["ProtectedValue"].value,
            "custom\0value"
        );
    }

    #[test]
    fn entry_history_and_strings_use_final_xml_order_for_protected_stream() {
        let mut vault = Vault::empty("MixedEntryOrder");
        let mut entry = Entry::new("Live");
        entry.password = "live-secret".into();
        let mut history = Entry::new("History");
        history.id = entry.id;
        history.password = "history-secret".into();
        entry.history.push(history);
        entry.raw_state.node_order = vec![
            "UUID".into(),
            "IconID".into(),
            "Times".into(),
            "History".into(),
            "String".into(),
            "String".into(),
            "String".into(),
            "String".into(),
            "String".into(),
            "AutoType".into(),
        ];
        entry.raw_state.string_order = vec![
            "Title".into(),
            "UserName".into(),
            "Password".into(),
            "URL".into(),
            "Notes".into(),
        ];
        vault.root.entries.push(entry);

        let key = test_key("mixed-entry-order");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save mixed entry order");
        let loaded = load_kdbx(&bytes, &key).expect("load mixed entry order");

        assert_eq!(loaded.root.entries[0].password, "live-secret");
        assert_eq!(loaded.root.entries[0].history[0].password, "history-secret");
    }

    #[test]
    fn group_entries_and_children_use_final_xml_order_for_protected_stream() {
        let mut vault = Vault::empty("MixedGroupOrder");
        let mut root_entry = Entry::new("Root entry");
        root_entry.password = "root-entry-secret".into();
        vault.root.entries.push(root_entry);

        let mut child = Group::new("Child");
        let mut child_entry = Entry::new("Child entry");
        child_entry.password = "child-entry-secret".into();
        child.entries.push(child_entry);
        vault.root.children.push(child);
        vault.root.raw_state.node_order = vec!["Group".into(), "Entry".into()];
        vault.root.raw_state.group_order = vec![vault.root.children[0].id];
        vault.root.raw_state.entry_order = vec![vault.root.entries[0].id];

        let key = test_key("mixed-group-order");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save mixed group order");
        let loaded = load_kdbx(&bytes, &key).expect("load mixed group order");

        assert_eq!(loaded.root.entries[0].password, "root-entry-secret");
        assert_eq!(
            loaded.root.children[0].entries[0].password,
            "child-entry-secret"
        );
    }

    #[test]
    fn final_order_protection_matches_kdbx3_and_kdbx4_parsers() {
        let mut vault = Vault::empty("VersionedProtectedOrder");
        let mut root_entry = Entry::new("Root entry");
        root_entry.password = "root-entry-secret".into();
        let mut history = Entry::new("History");
        history.id = root_entry.id;
        history.password = "history-secret".into();
        root_entry.history.push(history);
        root_entry.raw_state.node_order = vec!["History".into(), "String".into()];
        vault.root.entries.push(root_entry);

        let mut child = Group::new("Child");
        let mut child_entry = Entry::new("Child entry");
        child_entry.password = "child-entry-secret".into();
        child.entries.push(child_entry);
        vault.root.children.push(child);
        vault.root.raw_state.node_order = vec!["Group".into(), "Entry".into()];

        for (version, stream_id) in [(KdbxVersion::V3_1, 2), (KdbxVersion::V4_1, 3)] {
            let inner_key = [0x42_u8; 64];
            let mut group =
                super::group_to_xml(&vault.root, &std::collections::HashMap::new(), version)
                    .expect("build group xml");
            let mut writer =
                super::ProtectedStream::from_stream(stream_id, &inner_key).expect("writer stream");
            super::protect_xml_group(&mut group, &mut writer).expect("protect group xml");

            let mut reader =
                super::ProtectedStream::from_stream(stream_id, &inner_key).expect("reader stream");
            let mut content_pool = vaultkern_model::AttachmentContentPool::new();
            let parsed = super::parse_group(&group, &[], &mut content_pool, &mut reader)
                .expect("parse group xml");

            assert_eq!(parsed.entries[0].password, "root-entry-secret");
            assert_eq!(parsed.entries[0].history[0].password, "history-secret");
            assert_eq!(parsed.children[0].entries[0].password, "child-entry-secret");
        }
    }

    #[test]
    fn new_string_occurrences_stay_before_existing_history_node() {
        let mut vault = Vault::empty("NewStringPlacement");
        let mut entry = Entry::new("Live");
        entry.password = "live-secret".into();
        let mut history = Entry::new("History");
        history.id = entry.id;
        history.password = "history-secret".into();
        entry.history.push(history);
        vault.root.entries.push(entry);

        let key = test_key("new-string-placement");
        let seed = save_kdbx(&vault, &key, &fast_profile()).expect("save seed");
        let mut loaded = load_kdbx(&seed, &key).expect("load seed");
        loaded.root.entries[0].attributes.insert(
            "NewProtectedField".into(),
            CustomField {
                value: "new-secret".into(),
                protected: true,
            },
        );

        let rewritten = save_kdbx(&loaded, &key, &fast_profile()).expect("save new field");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten xml");
        let parsed = Element::parse(std::io::Cursor::new(xml.as_bytes())).expect("parse xml");
        let entry = first_live_entry(&parsed);
        let names = entry
            .children
            .iter()
            .filter_map(|child| match child {
                XMLNode::Element(element) => Some(element.name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let history_index = names
            .iter()
            .position(|name| *name == "History")
            .expect("history node");

        assert!(
            names
                .iter()
                .enumerate()
                .filter(|(_, name)| **name == "String")
                .all(|(index, _)| index < history_index),
            "all String nodes must remain before History: {names:?}"
        );
    }

    #[test]
    fn new_known_node_name_uses_its_canonical_neighbor() {
        let mut vault = Vault::empty("NewKnownNodePlacement");
        let mut entry = Entry::new("Live");
        let mut history = Entry::new("History");
        history.id = entry.id;
        entry.history.push(history);
        vault.root.entries.push(entry);

        let key = test_key("new-known-node-placement");
        let seed = save_kdbx(&vault, &key, &fast_profile()).expect("save seed");
        let mut loaded = load_kdbx(&seed, &key).expect("load seed");
        loaded.root.entries[0].tags.insert("new-tag".into());

        let rewritten = save_kdbx(&loaded, &key, &fast_profile()).expect("save new tag");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract rewritten xml");
        let parsed = Element::parse(std::io::Cursor::new(xml.as_bytes())).expect("parse xml");
        let names = first_live_entry(&parsed)
            .children
            .iter()
            .filter_map(|child| match child {
                XMLNode::Element(element) => Some(element.name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let tags_index = names
            .iter()
            .position(|name| *name == "Tags")
            .expect("tags node");
        let times_index = names
            .iter()
            .position(|name| *name == "Times")
            .expect("times node");

        assert_eq!(tags_index + 1, times_index, "unexpected order: {names:?}");
    }

    #[test]
    fn known_bad_custom_data_upgrades_to_quality_check_false() {
        let mut vault = Vault::empty("KnownBad");
        let mut entry = Entry::new("Legacy");
        entry.custom_data.insert("KnownBad".into(), "True".into());
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "KnownBad".into(),
                value: "True".into(),
                last_modified: None,
            }],
            after: None,
        });
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
    fn unrecognized_known_bad_value_remains_ordinary_custom_data() {
        let mut vault = Vault::empty("UnknownKnownBad");
        let mut entry = Entry::new("Legacy");
        entry.custom_data.insert("KnownBad".into(), "maybe".into());
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "KnownBad".into(),
                value: "maybe".into(),
                last_modified: None,
            }],
            after: None,
        });
        vault.root.entries.push(entry);

        let key = test_key("unknown-known-bad");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save custom data");
        let loaded = load_kdbx(&bytes, &key).expect("load custom data");
        let loaded_entry = &loaded.root.entries[0];

        assert!(!loaded_entry.exclude_from_reports);
        assert_eq!(
            loaded_entry.custom_data.get("KnownBad").map(String::as_str),
            Some("maybe")
        );
        assert_eq!(loaded_entry.custom_data_blocks[0].items[0].value, "maybe");
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
        for (key, value, protected) in [
            (
                PasskeyRecord::USERNAME_KEY,
                "partial-user@example.com",
                false,
            ),
            (PasskeyRecord::CREDENTIAL_ID_KEY, "partial-credential", true),
            (PasskeyRecord::RELYING_PARTY_KEY, "example.com", false),
            (PasskeyRecord::USER_HANDLE_KEY, "partial-user-handle", true),
            (PasskeyRecord::FLAG_BE_KEY, "1", false),
            (PasskeyRecord::FLAG_BS_KEY, "0", false),
        ] {
            entry.attributes.insert(
                key.into(),
                CustomField {
                    value: value.into(),
                    protected,
                },
            );
        }
        vault.root.entries.push(entry);

        let key = test_key("partial-passkey");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save kdbx");
        let loaded = load_kdbx(&bytes, &key).expect("load kdbx");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert!(loaded_entry.passkey.is_none());
        assert_partial_passkey_fields_preserved(loaded_entry);

        let rewritten = save_kdbx(&loaded, &key, &fast_profile()).expect("save kdbx");
        let reloaded = load_kdbx(&rewritten, &key).expect("reload kdbx");
        let reloaded_entry = reloaded.root.entries.first().expect("reloaded entry");

        assert_partial_passkey_fields_preserved(reloaded_entry);
    }

    fn assert_partial_passkey_fields_preserved(entry: &Entry) {
        for (key, expected_value, expected_protected) in [
            (
                PasskeyRecord::USERNAME_KEY,
                "partial-user@example.com",
                false,
            ),
            (PasskeyRecord::CREDENTIAL_ID_KEY, "partial-credential", true),
            (PasskeyRecord::RELYING_PARTY_KEY, "example.com", false),
            (PasskeyRecord::USER_HANDLE_KEY, "partial-user-handle", true),
            (PasskeyRecord::FLAG_BE_KEY, "1", false),
            (PasskeyRecord::FLAG_BS_KEY, "0", false),
        ] {
            assert_eq!(
                entry
                    .attributes
                    .get(key)
                    .map(|field| (field.value.as_str(), field.protected)),
                Some((expected_value, expected_protected)),
                "partial passkey field should roundtrip as a custom field: {key}"
            );
        }
    }

    #[test]
    fn incomplete_passkey_private_key_roundtrips_as_protected_custom_field() {
        let mut vault = Vault::empty("PartialPasskeyPrivateKey");
        let mut entry = Entry::new("Example");
        for (key, value, protected) in [
            (PasskeyRecord::CREDENTIAL_ID_KEY, "partial-credential", true),
            (
                PasskeyRecord::PRIVATE_KEY_PEM_KEY,
                "-----BEGIN PRIVATE KEY-----\npartial\n-----END PRIVATE KEY-----",
                false,
            ),
            (PasskeyRecord::RELYING_PARTY_KEY, "example.com", false),
        ] {
            entry.attributes.insert(
                key.into(),
                CustomField {
                    value: value.into(),
                    protected,
                },
            );
        }
        vault.root.entries.push(entry);

        let key = test_key("partial-passkey-private-key");
        let bytes = save_kdbx(&vault, &key, &fast_profile()).expect("save kdbx");
        let loaded = load_kdbx(&bytes, &key).expect("load kdbx");
        let loaded_entry = loaded.root.entries.first().expect("loaded entry");

        assert!(loaded_entry.passkey.is_none());
        assert_eq!(
            loaded_entry
                .attributes
                .get(PasskeyRecord::PRIVATE_KEY_PEM_KEY)
                .map(|field| field.protected),
            Some(true)
        );

        let rewritten = save_kdbx(&loaded, &key, &fast_profile()).expect("save kdbx");
        let reloaded = load_kdbx(&rewritten, &key).expect("reload kdbx");
        let reloaded_entry = reloaded.root.entries.first().expect("reloaded entry");

        assert_eq!(
            reloaded_entry
                .attributes
                .get(PasskeyRecord::PRIVATE_KEY_PEM_KEY)
                .map(|field| field.protected),
            Some(true)
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

    fn extract_kdbx4_inner_key(
        bytes: &[u8],
        composite_key: &CompositeKey,
    ) -> super::Result<Vec<u8>> {
        let (header, header_len) = KdbxHeader::decode_with_consumed(bytes)?;
        let mut cursor = super::Cursor::new(&bytes[header_len..]);
        cursor.read_exact(32)?;
        cursor.read_exact(32)?;
        let raw_key = composite_key.raw_key()?;
        let kdf = kdf_from_variant_dict(&header.kdf_parameters)?;
        let transformed = kdf.derive_key(&raw_key)?;
        let encryption_key = sha256_seeded(&header.master_seed, &transformed);
        let mac_seed = mac_seed(&header.master_seed, &transformed);
        let encrypted_payload = decode_block_stream(&mac_seed, cursor.read_remaining())?;
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
        let (_, inner_key, _, _) = parse_inner_header(&payload)?;
        Ok(inner_key)
    }
}

#[cfg(test)]
mod transformed_key_tests {
    use super::{
        Compression, KdbxCipher, KdbxError, KdbxVersion, SaveKdf, SaveProfile,
        derive_transformed_key, load_kdbx_with_transformed_key, save_kdbx,
        save_kdbx_with_transformed_key,
    };
    use vaultkern_crypto::CompositeKey;
    use vaultkern_model::Vault;

    fn fast_profile() -> SaveProfile {
        SaveProfile {
            version: KdbxVersion::V4_1,
            cipher: KdbxCipher::Aes256,
            compression: Compression::None,
            kdf: Some(SaveKdf::AesKdbx4 { rounds: 16 }),
        }
    }

    #[test]
    fn transformed_key_cache_is_validated_by_file_hmac_and_refreshes_on_miss() {
        let mut key = CompositeKey::default();
        key.add_password("correct horse battery staple");
        let first = save_kdbx(&Vault::empty("first"), &key, &fast_profile()).unwrap();
        let second = save_kdbx(&Vault::empty("second"), &key, &fast_profile()).unwrap();

        let cached = derive_transformed_key(&first, &key).unwrap();
        let opened = load_kdbx_with_transformed_key(&first, &cached).unwrap();
        assert_eq!(opened.name, "first");

        assert!(matches!(
            load_kdbx_with_transformed_key(&second, &cached),
            Err(KdbxError::HeaderHmacMismatch)
        ));

        let refreshed = derive_transformed_key(&second, &key).unwrap();
        let opened = load_kdbx_with_transformed_key(&second, &refreshed).unwrap();
        assert_eq!(opened.name, "second");
    }

    #[test]
    fn ordinary_save_reuses_loaded_kdf_and_the_session_transformed_key() {
        let mut key = CompositeKey::default();
        key.add_password("save password");
        let initial = save_kdbx(&Vault::empty("before"), &key, &fast_profile()).unwrap();
        let transformed = derive_transformed_key(&initial, &key).unwrap();
        let mut vault = load_kdbx_with_transformed_key(&initial, &transformed).unwrap();
        vault.name = "after".into();

        let saved = save_kdbx_with_transformed_key(
            &vault,
            &transformed,
            &SaveProfile {
                kdf: None,
                ..fast_profile()
            },
        )
        .unwrap();

        let reopened = load_kdbx_with_transformed_key(&saved, &transformed).unwrap();
        assert_eq!(reopened.name, "after");

        let error =
            save_kdbx_with_transformed_key(&vault, &transformed, &fast_profile()).unwrap_err();
        assert!(matches!(error, KdbxError::InvalidValue));
    }
}

#[cfg(all(test, feature = "external-fixtures"))]
mod tests {
    use super::{
        Compression, KdbxCipher, KdbxError, KdbxHeader, KdbxVersion, SaveProfile,
        VariantDictionary, VariantValue, bool_text, child_text, decode_block_stream,
        decode_kdbx3_header, decode_legacy_block_stream, decrypt_payload, detect_file_version,
        encode_block_stream, gzip_compress, gzip_decompress, header_hmac, kdf_from_variant_dict,
        load_kdbx, mac_seed, parse_inner_header, parse_xml_fragment, required_version, save_kdbx,
        sha256_seeded, text_element,
    };
    use base64::Engine as _;
    use vaultkern_crypto::{CompositeKey, KdfProfile, sha256_bytes};
    use vaultkern_model::{
        Attachment, CustomDataBlock, CustomDataItem, CustomField, Entry, Group, MemoryProtection,
        Vault,
    };
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
    fn variant_dictionary_reemits_loaded_entry_order_and_unknown_keys_verbatim() {
        let mut encoded = 0x0100_u16.to_le_bytes().to_vec();
        for (kind, key, value) in [
            (0x42_u8, "S", vec![0x55; 32]),
            (0x08, "X-ThirdParty", vec![1]),
            (0x77, "X-Future-Type", vec![0xde, 0xad]),
            (0x05, "R", 42_u64.to_le_bytes().to_vec()),
        ] {
            encoded.push(kind);
            encoded.extend((key.len() as i32).to_le_bytes());
            encoded.extend(key.as_bytes());
            encoded.extend((value.len() as i32).to_le_bytes());
            encoded.extend(value);
        }
        encoded.push(0);

        let decoded = VariantDictionary::decode(&encoded).expect("decode dictionary");

        assert_eq!(decoded.get("X-ThirdParty"), Some(&VariantValue::Bool(true)));
        assert_eq!(decoded.encode().expect("re-encode dictionary"), encoded);
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
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "EntryKey".into(),
                value: "EntryValue".into(),
                last_modified: None,
            }],
            after: Some(vaultkern_model::OpaqueXmlAnchor {
                element_name: "AutoType".into(),
                occurrence: 1,
            }),
        });
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
    fn kdbx4_roundtrip_preserves_keyed_string_and_binary_identity_order() {
        let mut vault = Vault::empty("KeyedOrder");
        let mut entry = Entry::new("Entry");
        entry.attributes.insert(
            "Alpha".into(),
            CustomField {
                value: "one".into(),
                protected: false,
            },
        );
        entry.attributes.insert(
            "Zeta".into(),
            CustomField {
                value: "two".into(),
                protected: false,
            },
        );
        entry.attachments.insert(
            "alpha.bin".into(),
            Attachment::new("alpha.bin", vec![1], false),
        );
        entry.attachments.insert(
            "zeta.bin".into(),
            Attachment::new("zeta.bin", vec![2], false),
        );
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("keyed-order");
        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .and_then(|group| group.get_mut_child("Entry"))
                .expect("entry");
            let child_key = |node: &XMLNode, name: &str| match node {
                XMLNode::Element(element) if element.name == name => child_text(element, "Key"),
                _ => None,
            };
            let alpha = entry
                .children
                .iter()
                .position(|node| child_key(node, "String").as_deref() == Some("Alpha"))
                .expect("alpha string");
            let zeta = entry
                .children
                .iter()
                .position(|node| child_key(node, "String").as_deref() == Some("Zeta"))
                .expect("zeta string");
            entry.children.swap(alpha, zeta);
            let zeta = entry
                .children
                .iter()
                .position(|node| child_key(node, "String").as_deref() == Some("Zeta"))
                .expect("moved zeta string");
            entry.children.insert(
                zeta + 1,
                XMLNode::Element(parse_xml_fragment("<AfterZeta />").expect("opaque node")),
            );

            let alpha = entry
                .children
                .iter()
                .position(|node| child_key(node, "Binary").as_deref() == Some("alpha.bin"))
                .expect("alpha binary");
            let zeta = entry
                .children
                .iter()
                .position(|node| child_key(node, "Binary").as_deref() == Some("zeta.bin"))
                .expect("zeta binary");
            entry.children.swap(alpha, zeta);
        })
        .expect("rewrite keyed order");

        let loaded = load_kdbx(&mutated, &key).expect("load keyed order");
        let loaded_entry = &loaded.root.entries[0];
        assert!(
            loaded_entry
                .raw_state
                .string_order
                .iter()
                .position(|name| name == "Zeta")
                < loaded_entry
                    .raw_state
                    .string_order
                    .iter()
                    .position(|name| name == "Alpha")
        );
        assert_eq!(
            loaded_entry.raw_state.binary_order,
            ["zeta.bin", "alpha.bin"]
        );

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save keyed order");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract keyed order xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse keyed order xml");
        let entry = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("entry");
        let position = |name: &str, key: Option<&str>| {
            entry
                .children
                .iter()
                .position(|node| match node {
                    XMLNode::Element(element) if element.name == name => key
                        .map(|key| child_text(element, "Key").as_deref() == Some(key))
                        .unwrap_or(true),
                    _ => false,
                })
                .expect("expected keyed node")
        };
        assert!(position("String", Some("Zeta")) < position("AfterZeta", None));
        assert!(position("AfterZeta", None) < position("String", Some("Alpha")));
        assert!(position("Binary", Some("zeta.bin")) < position("Binary", Some("alpha.bin")));
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
    fn kdbx4_roundtrip_preserves_mixed_root_known_and_opaque_order() {
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
        assert_in_order(
            child_element_names(root_node),
            &["DeletedObjects", "UnknownRootMixed", "Group"],
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_absent_empty_deleted_objects_container() {
        let vault = Vault::empty("RootWithoutDeletedObjects");
        let mut key = CompositeKey::default();
        key.add_password("root-without-deleted-objects");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let root_node = root.get_mut_child("Root").expect("root node");
            root_node.children.retain(
                |child| !matches!(child, XMLNode::Element(element) if element.name == "DeletedObjects"),
            );
        })
        .expect("rewrite root xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        assert!(!loaded.root_raw_state.has_deleted_objects_node);

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse rewritten xml");
        assert!(
            parsed
                .get_child("Root")
                .expect("root node")
                .get_child("DeletedObjects")
                .is_none()
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_absent_empty_history_container() {
        let mut vault = Vault::empty("EntryWithoutHistory");
        vault.root.entries.push(Entry::new("Entry"));
        let mut key = CompositeKey::default();
        key.add_password("entry-without-history");

        let bytes = save_kdbx(&vault, &key, &SaveProfile::recommended()).expect("save kdbx");
        let mutated = rewrite_kdbx4_xml(&bytes, &key, |root| {
            let entry = root
                .get_mut_child("Root")
                .and_then(|root| root.get_mut_child("Group"))
                .and_then(|group| group.get_mut_child("Entry"))
                .expect("entry");
            entry.children.retain(
                |child| !matches!(child, XMLNode::Element(element) if element.name == "History"),
            );
        })
        .expect("rewrite entry xml");

        let loaded = load_kdbx(&mutated, &key).expect("load mutated kdbx");
        assert!(!loaded.root.entries[0].raw_state.has_history_node);

        let rewritten =
            save_kdbx(&loaded, &key, &SaveProfile::recommended()).expect("save rewritten kdbx");
        let xml = extract_kdbx4_xml(&rewritten, &key).expect("extract xml");
        let parsed = Element::parse(xml.as_bytes()).expect("parse rewritten xml");
        let entry = parsed
            .get_child("Root")
            .and_then(|root| root.get_child("Group"))
            .and_then(|group| group.get_child("Entry"))
            .expect("entry");
        assert!(entry.get_child("History").is_none());
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
        vault.root.custom_data_blocks.push(CustomDataBlock {
            items: vec![
                CustomDataItem {
                    key: "group-a".into(),
                    value: "1".into(),
                    last_modified: None,
                },
                CustomDataItem {
                    key: "group-b".into(),
                    value: "2".into(),
                    last_modified: None,
                },
            ],
            after: None,
        });

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
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "entry-a".into(),
                value: "1".into(),
                last_modified: None,
            }],
            after: None,
        });
        entry.auto_type = Some(vaultkern_model::AutoTypeConfig {
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into()),
            ..Default::default()
        });
        let mut history_entry = Entry::new("Old");
        history_entry.id = entry.id;
        entry.history.push(history_entry);
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
    fn kdbx4_save_rejects_nested_history_fidelity_nodes() {
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

        assert!(matches!(
            save_kdbx(&vault, &key, &SaveProfile::recommended()),
            Err(KdbxError::InvalidValue)
        ));
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
        vault
            .meta_custom_data
            .insert("meta-key".into(), "meta-value".into());
        vault.root.previous_parent = Some(uuid::Uuid::nil());
        vault.root.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "group-key".into(),
                value: "group-value".into(),
                last_modified: Some(1_700_000_007),
            }],
            after: None,
        });
        vault
            .root
            .custom_data
            .insert("group-key".into(), "group-value".into());

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
        entry
            .custom_data
            .insert("entry-key".into(), "entry-value".into());
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
    fn kdbx3_xml_builder_rejects_legacy_write_versions() {
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
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "entry-key".into(),
                value: "entry-value".into(),
                last_modified: None,
            }],
            after: None,
        });
        vault.root.entries.push(entry);

        for version in [KdbxVersion::V2_0, KdbxVersion::V3_0, KdbxVersion::V3_1] {
            assert!(matches!(
                super::build_xml(
                    &vault,
                    &std::collections::HashMap::new(),
                    &[0_u8; 64],
                    version,
                ),
                Err(KdbxError::UnsupportedVersion)
            ));
        }
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
        assert!(group.get_child("LastTopVisibleEntry").is_none());

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
        vault.meta_custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "meta-a".into(),
                value: "A".into(),
                last_modified: None,
            }],
            after: None,
        });
        vault
            .public_custom_data
            .insert("client".into(), b"web".to_vec());

        let mut group = Group::new("Nested");
        group.custom_data.insert("group-a".into(), "A".into());
        group.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "group-a".into(),
                value: "A".into(),
                last_modified: None,
            }],
            after: None,
        });

        let mut entry = Entry::new("Entry");
        entry.custom_data.insert("entry-a".into(), "A".into());
        entry.custom_data_blocks.push(CustomDataBlock {
            items: vec![CustomDataItem {
                key: "entry-a".into(),
                value: "A".into(),
                last_modified: None,
            }],
            after: None,
        });
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
        let mut history_entry = Entry::new("History");
        history_entry.id = entry.id;
        entry.history.push(history_entry);
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
    fn mutated_meta_custom_data_map_is_rejected_as_unpersistable() {
        let mut key = CompositeKey::default();
        key.add_password("a");

        let mutated = rewrite_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key, |root| {
            let meta = root.get_mut_child("Meta").expect("meta");
            split_first_custom_data_block(meta);
        })
        .expect("rewrite browser fixture");

        let mut loaded = load_kdbx(&mutated, &key).expect("load mutated browser fixture");
        loaded
            .meta_custom_data
            .insert("KeePassXC-Browser Settings".into(), "mutated-meta".into());

        assert!(matches!(
            save_kdbx(&loaded, &key, &SaveProfile::recommended()),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn mutated_entry_custom_data_map_is_rejected_as_unpersistable() {
        let mut key = CompositeKey::default();
        key.add_password("a");
        let mut loaded = load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key).expect("load fixture");
        loaded.root.entries[0]
            .custom_data
            .insert("KPH: {USERNAME}".into(), "mutated-entry".into());

        assert!(matches!(
            save_kdbx(&loaded, &key, &SaveProfile::recommended()),
            Err(KdbxError::InvalidValue)
        ));
    }

    #[test]
    fn deleting_custom_data_item_preserves_empty_split_block() {
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

        assert_eq!(custom_data_blocks(rewritten_meta).len(), 2);
        assert!(custom_data_blocks(rewritten_meta)[0].is_empty());
        assert_eq!(
            custom_data_blocks(rewritten_meta)[1]
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
        assert_eq!(loaded.recycle_bin_group, None);
        assert_eq!(loaded.entry_templates_group, None);

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
        assert!(rewritten_meta.get_child("RecycleBinUUID").is_none());
        assert!(rewritten_meta.get_child("EntryTemplatesGroup").is_none());
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
        let expected_order = child_element_names_after_optional_uuid_normalization(original_meta);

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
            let settings_changed = meta
                .children
                .iter_mut()
                .find_map(|child| match child {
                    XMLNode::Element(element) if element.name == "SettingsChanged" => Some(element),
                    _ => None,
                })
                .expect("settings changed");
            settings_changed.children = vec![XMLNode::Text("1700000000".into())];

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
            &["HistoryMaxSize", "SettingsChanged", "CustomData"],
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

        assert_datetime_text(rewritten_meta, "SettingsChanged", 1_700_000_000, true);
        assert_eq!(
            meta_child_text_or_empty(rewritten_meta, "MasterKeyChangeForceOnce"),
            Some("True".into())
        );
        assert_in_order(
            child_element_names(rewritten_meta),
            &["HistoryMaxSize", "SettingsChanged", "CustomData"],
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
        let icon_id = uuid::Uuid::new_v4();

        let mutated = rewrite_kdbx4_xml(FIXTURE_NEW_DATABASE_BROWSER, &key, |root| {
            let custom_icons = root
                .get_mut_child("Meta")
                .and_then(|meta| meta.get_mut_child("CustomIcons"))
                .expect("custom icons");
            custom_icons.children.push(XMLNode::Element(
                parse_xml_fragment(&format!(
                    "<Icon>\
                        <UUID>{}</UUID>\
                        <Data>AQIDBA==</Data>\
                        <Name>Browser Icon</Name>\
                        <LastModificationTime>1700000005</LastModificationTime>\
                    </Icon>",
                    super::encode_uuid(icon_id),
                ))
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

    fn child_element_names_after_optional_uuid_normalization(element: &Element) -> Vec<&str> {
        element
            .children
            .iter()
            .filter_map(|child| {
                let XMLNode::Element(child) = child else {
                    return None;
                };
                let optional_uuid = matches!(
                    child.name.as_str(),
                    "RecycleBinUUID"
                        | "EntryTemplatesGroup"
                        | "LastSelectedGroup"
                        | "LastTopVisibleGroup"
                        | "CustomIconUUID"
                        | "LastTopVisibleEntry"
                        | "PreviousParentGroup"
                );
                if optional_uuid
                    && matches!(
                        super::parse_optional_uuid(child.get_text().as_deref().unwrap_or_default()),
                        Ok(None)
                    )
                {
                    None
                } else {
                    Some(child.name.as_str())
                }
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
            child_element_names_after_optional_uuid_normalization(group)
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
