use aes::Aes256;
use aes::cipher::{
    BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher,
    block_padding::Pkcs7, generic_array::GenericArray,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use chacha20::ChaCha20;
use data_encoding::{HEXLOWER, HEXUPPER};
use hmac::{Hmac, Mac};
use rust_argon2::{Config as Argon2Config, ThreadMode as Argon2ThreadMode};
use salsa20::Salsa20;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::{fmt, io::Cursor};
use thiserror::Error;
use twofish::Twofish;
use uuid::Uuid;
use xmltree::{Element, XMLNode};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("feature not implemented yet")]
    Unimplemented,
    #[error("composite key has no components")]
    EmptyCompositeKey,
    #[error("invalid key file")]
    InvalidKeyFile,
    #[error("key file integrity mismatch")]
    KeyFileIntegrityMismatch,
    #[error("invalid KDF parameters")]
    InvalidKdfParameters,
    #[error("invalid TOTP parameters")]
    InvalidTotpParameters,
    #[error("invalid cipher parameters")]
    InvalidCipherParameters,
    #[error("decryption failed")]
    DecryptionFailed,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(PartialEq, Eq)]
pub enum KeyComponent {
    Password(Vec<u8>),
    KeyFile(Vec<u8>),
    OpaqueProviderBytes(Vec<u8>),
}

impl fmt::Debug for KeyComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Password(_) => "Password",
            Self::KeyFile(_) => "KeyFile",
            Self::OpaqueProviderBytes(_) => "OpaqueProviderBytes",
        };
        formatter.debug_tuple(name).field(&Redacted).finish()
    }
}

impl Zeroize for KeyComponent {
    fn zeroize(&mut self) {
        match self {
            Self::Password(bytes) | Self::KeyFile(bytes) | Self::OpaqueProviderBytes(bytes) => {
                bytes.zeroize()
            }
        }
    }
}

impl Drop for KeyComponent {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyComponent {}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Default, PartialEq, Eq)]
pub struct CompositeKey {
    components: Vec<KeyComponent>,
}

impl fmt::Debug for CompositeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompositeKey")
            .field("components", &self.components)
            .finish()
    }
}

impl Zeroize for CompositeKey {
    fn zeroize(&mut self) {
        self.components.zeroize();
    }
}

impl Drop for CompositeKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CompositeKey {}

impl CompositeKey {
    pub fn add_password(&mut self, password: impl AsRef<str>) {
        self.add_password_bytes(password.as_ref().as_bytes());
    }

    pub fn add_password_bytes(&mut self, password: impl AsRef<[u8]>) {
        self.components
            .push(KeyComponent::Password(password.as_ref().to_vec()));
    }

    pub fn add_key_file(&mut self, bytes: impl Into<Vec<u8>>) {
        self.components.push(KeyComponent::KeyFile(bytes.into()));
    }

    pub fn add_key_file_content(&mut self, bytes: &[u8]) -> Result<()> {
        let contribution = parse_key_file_bytes(bytes)?;
        self.add_key_file(contribution.as_ref());
        Ok(())
    }

    pub fn add_provider_bytes(&mut self, bytes: impl Into<Vec<u8>>) {
        self.components
            .push(KeyComponent::OpaqueProviderBytes(bytes.into()));
    }

    pub fn components(&self) -> &[KeyComponent] {
        &self.components
    }

    pub fn raw_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let mut stream = Zeroizing::new(Vec::new());
        for component in &self.components {
            match component {
                KeyComponent::Password(password) => {
                    let password_hash = Zeroizing::new(Sha256::digest(password));
                    stream.extend_from_slice(&password_hash);
                }
                KeyComponent::KeyFile(bytes) | KeyComponent::OpaqueProviderBytes(bytes) => {
                    stream.extend_from_slice(bytes);
                }
            }
        }

        let raw_key = Zeroizing::new(Sha256::digest(stream.as_slice()));
        Ok(Zeroizing::new((*raw_key).into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfProfile {
    AesKdbx3 {
        rounds: u64,
        salt: [u8; 32],
    },
    AesKdbx4 {
        rounds: u64,
        salt: [u8; 32],
    },
    Argon2d {
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
        salt: Vec<u8>,
    },
    Argon2id {
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
        salt: Vec<u8>,
    },
}

impl KdfProfile {
    pub fn derive_key(&self, raw_key: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        match self {
            KdfProfile::AesKdbx3 { rounds, salt } | KdfProfile::AesKdbx4 { rounds, salt } => {
                derive_aes_kdf(raw_key, *rounds, salt)
            }
            KdfProfile::Argon2d {
                iterations,
                memory_kib,
                parallelism,
                salt,
            } => derive_argon2(
                raw_key,
                rust_argon2::Variant::Argon2d,
                *iterations,
                *memory_kib,
                *parallelism,
                salt,
            ),
            KdfProfile::Argon2id {
                iterations,
                memory_kib,
                parallelism,
                salt,
            } => derive_argon2(
                raw_key,
                rust_argon2::Variant::Argon2id,
                *iterations,
                *memory_kib,
                *parallelism,
                salt,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub fn generate_totp(
    secret: &[u8],
    algorithm: OtpAlgorithm,
    digits: u32,
    period_seconds: u64,
    unix_time: u64,
) -> Result<String> {
    if secret.is_empty() || !(1..=9).contains(&digits) || period_seconds == 0 {
        return Err(CryptoError::InvalidTotpParameters);
    }

    let counter = unix_time / period_seconds;
    let counter_bytes = counter.to_be_bytes();
    let digest = Zeroizing::new(match algorithm {
        OtpAlgorithm::Sha1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret)
                .map_err(|_| CryptoError::InvalidTotpParameters)?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
                .map_err(|_| CryptoError::InvalidTotpParameters)?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(secret)
                .map_err(|_| CryptoError::InvalidTotpParameters)?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    });

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let code = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        code % modulus,
        width = digits as usize
    ))
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn parse_key_file_bytes(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let trimmed = strip_utf8_bom(bytes);
    if looks_like_xml(trimmed) {
        parse_xml_key_file(trimmed)
    } else {
        parse_binary_key_file(trimmed)
    }
}

pub fn sha512_bytes(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidCipherParameters)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    }
    bytes.truncate(len);
    bytes
}

fn looks_like_xml(bytes: &[u8]) -> bool {
    let mut cursor = 0;
    while let Some(byte) = bytes.get(cursor) {
        if byte.is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        return *byte == b'<';
    }
    false
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    }
}

fn parse_binary_key_file(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if bytes.len() == 32 {
        let mut contribution = Zeroizing::new([0_u8; 32]);
        contribution.copy_from_slice(bytes);
        return Ok(contribution);
    }

    let compact_hex = Zeroizing::new(
        bytes
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>(),
    );
    if compact_hex.len() == 64 && compact_hex.iter().all(u8::is_ascii_hexdigit) {
        let decoded = Zeroizing::new(
            HEXLOWER
                .decode(&compact_hex)
                .or_else(|_| HEXUPPER.decode(&compact_hex))
                .map_err(|_| CryptoError::InvalidKeyFile)?,
        );
        return zeroizing_array_32(&decoded);
    }

    Ok(Zeroizing::new(sha256_bytes(bytes)))
}

fn parse_xml_key_file(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let root = ZeroizingKeyFileXml::new(
        Element::parse(Cursor::new(bytes)).map_err(|_| CryptoError::InvalidKeyFile)?,
    );
    let root = root.element();
    if root.name != "KeyFile" {
        return Err(CryptoError::InvalidKeyFile);
    }

    let version = child_text(&root, &["Meta", "Version"]).ok_or(CryptoError::InvalidKeyFile)?;
    if version.starts_with('1') {
        parse_xml_key_file_v1(&root)
    } else if version.starts_with('2') {
        parse_xml_key_file_v2(&root)
    } else {
        Err(CryptoError::InvalidKeyFile)
    }
}

fn parse_xml_key_file_v1(root: &Element) -> Result<Zeroizing<[u8; 32]>> {
    let data = child_element(root, &["Key", "Data"])
        .and_then(Element::get_text)
        .ok_or(CryptoError::InvalidKeyFile)?;
    let decoded = Zeroizing::new(
        STANDARD
            .decode(data.trim().as_bytes())
            .map_err(|_| CryptoError::InvalidKeyFile)?,
    );
    zeroizing_array_32(&decoded)
}

fn parse_xml_key_file_v2(root: &Element) -> Result<Zeroizing<[u8; 32]>> {
    let data_element = child_element(root, &["Key", "Data"]).ok_or(CryptoError::InvalidKeyFile)?;
    let hex_text = Zeroizing::new(
        data_element
            .get_text()
            .map(|text| {
                text.chars()
                    .filter(|ch| !ch.is_whitespace())
                    .collect::<String>()
            })
            .ok_or(CryptoError::InvalidKeyFile)?,
    );
    let decoded = Zeroizing::new(
        HEXUPPER
            .decode(hex_text.as_bytes())
            .or_else(|_| HEXLOWER.decode(hex_text.as_bytes()))
            .map_err(|_| CryptoError::InvalidKeyFile)?,
    );
    let decoded = zeroizing_array_32(&decoded)?;

    if let Some(expected_hash) = data_element.attributes.get("Hash") {
        let actual_hash = HEXUPPER.encode(&sha256_bytes(decoded.as_ref())[..4]);
        if !expected_hash.eq_ignore_ascii_case(&actual_hash) {
            return Err(CryptoError::KeyFileIntegrityMismatch);
        }
    }

    Ok(decoded)
}

fn zeroizing_array_32(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyFile);
    }
    let mut output = Zeroizing::new([0_u8; 32]);
    output.copy_from_slice(bytes);
    Ok(output)
}

struct ZeroizingKeyFileXml(Option<Element>);

impl ZeroizingKeyFileXml {
    fn new(element: Element) -> Self {
        Self(Some(element))
    }

    fn element(&self) -> &Element {
        self.0.as_ref().expect("live key-file XML guard")
    }
}

impl Drop for ZeroizingKeyFileXml {
    fn drop(&mut self) {
        if let Some(element) = self.0.as_mut() {
            zeroize_xml_element(element);
        }
    }
}

fn zeroize_xml_element(element: &mut Element) {
    element.name.zeroize();
    for (mut key, mut value) in std::mem::take(&mut element.attributes) {
        key.zeroize();
        value.zeroize();
    }
    for child in &mut element.children {
        match child {
            XMLNode::Element(child) => zeroize_xml_element(child),
            XMLNode::Text(text) | XMLNode::CData(text) | XMLNode::Comment(text) => text.zeroize(),
            _ => {}
        }
    }
}

fn child_element<'a>(element: &'a Element, path: &[&str]) -> Option<&'a Element> {
    let mut current = element;
    for name in path {
        current = current.children.iter().find_map(|child| match child {
            XMLNode::Element(child) if child.name == *name => Some(child),
            _ => None,
        })?;
    }
    Some(current)
}

fn child_text(element: &Element, path: &[&str]) -> Option<String> {
    child_element(element, path).and_then(|child| child.get_text().map(|text| text.to_string()))
}

pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = CbcEncryptor::<Aes256>::new(key.into(), iv.into());
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    let pos = buffer.len();
    buffer.resize(pos + 16, 0);
    let output_len = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, pos)
        .map_err(|_| CryptoError::InvalidCipherParameters)?
        .len();
    buffer.truncate(output_len);
    Ok(std::mem::take(&mut *buffer))
}

pub fn aes256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = CbcDecryptor::<Aes256>::new(key.into(), iv.into());
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let output_len = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| CryptoError::DecryptionFailed)?
        .len();
    buffer.truncate(output_len);
    Ok(buffer)
}

pub fn twofish_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = CbcEncryptor::<Twofish>::new(key.into(), iv.into());
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    let pos = buffer.len();
    buffer.resize(pos + 16, 0);
    let output_len = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, pos)
        .map_err(|_| CryptoError::InvalidCipherParameters)?
        .len();
    buffer.truncate(output_len);
    Ok(std::mem::take(&mut *buffer))
}

pub fn twofish_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = CbcDecryptor::<Twofish>::new(key.into(), iv.into());
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let output_len = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| CryptoError::DecryptionFailed)?
        .len();
    buffer.truncate(output_len);
    Ok(buffer)
}

pub fn chacha20_ietf_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    let mut bytes = Zeroizing::new(plaintext.to_vec());
    cipher.apply_keystream(&mut bytes);
    Ok(std::mem::take(&mut *bytes))
}

pub fn chacha20_ietf_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    let mut bytes = Zeroizing::new(ciphertext.to_vec());
    cipher.apply_keystream(&mut bytes);
    Ok(bytes)
}

pub struct ChaCha20Stream {
    cipher: ChaCha20,
}

impl ChaCha20Stream {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self {
            cipher: ChaCha20::new(key.into(), nonce.into()),
        }
    }

    pub fn apply(&mut self, bytes: &mut [u8]) {
        self.cipher.apply_keystream(bytes);
    }
}

pub struct Salsa20Stream {
    cipher: Salsa20,
}

impl Salsa20Stream {
    pub fn new(key: &[u8; 32], nonce: &[u8; 8]) -> Self {
        Self {
            cipher: Salsa20::new(key.into(), nonce.into()),
        }
    }

    pub fn apply(&mut self, bytes: &mut [u8]) {
        self.cipher.apply_keystream(bytes);
    }
}

fn derive_aes_kdf(raw_key: &[u8], rounds: u64, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    if raw_key.len() != 32 {
        return Err(CryptoError::InvalidKdfParameters);
    }

    let cipher = Aes256::new_from_slice(salt).map_err(|_| CryptoError::InvalidKdfParameters)?;
    let mut transformed = Zeroizing::new(raw_key.to_vec());
    let (left, right) = transformed.split_at_mut(16);
    let left = GenericArray::from_mut_slice(left);
    let right = GenericArray::from_mut_slice(right);

    for _ in 0..rounds {
        cipher.encrypt_block(left);
        cipher.encrypt_block(right);
    }

    let digest = Zeroizing::new(Sha256::digest(&*transformed));
    let mut derived = Zeroizing::new([0_u8; 32]);
    derived.copy_from_slice(&digest);
    Ok(derived)
}

fn derive_argon2(
    raw_key: &[u8],
    variant: rust_argon2::Variant,
    iterations: u32,
    memory_kib: u32,
    parallelism: u32,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let config = Argon2Config {
        ad: &[],
        hash_length: 32,
        lanes: parallelism,
        mem_cost: memory_kib,
        secret: &[],
        thread_mode: argon2_thread_mode(parallelism),
        time_cost: iterations,
        variant,
        version: rust_argon2::Version::Version13,
    };
    let output = Zeroizing::new(
        rust_argon2::hash_raw(raw_key, salt, &config)
            .map_err(|_| CryptoError::InvalidKdfParameters)?,
    );
    let mut derived = Zeroizing::new([0_u8; 32]);
    if output.len() != derived.len() {
        return Err(CryptoError::InvalidKdfParameters);
    }
    derived.copy_from_slice(&output);
    Ok(derived)
}

fn argon2_thread_mode(parallelism: u32) -> Argon2ThreadMode {
    Argon2ThreadMode::from_threads(parallelism)
}

#[cfg(all(test, feature = "external-fixtures"))]
fn argon2_thread_mode_name_for_tests(parallelism: u32) -> &'static str {
    match argon2_thread_mode(parallelism) {
        Argon2ThreadMode::Sequential => "sequential",
        Argon2ThreadMode::Parallel => "parallel",
    }
}

#[cfg(test)]
mod password_bytes_tests {
    use super::CompositeKey;

    #[test]
    fn password_bytes_have_the_same_composite_contribution_as_text() {
        let mut text = CompositeKey::default();
        text.add_password("密钥 password");
        let mut bytes = CompositeKey::default();
        bytes.add_password_bytes("密钥 password".as_bytes());

        assert_eq!(bytes.raw_key().unwrap(), text.raw_key().unwrap());
    }
}

#[cfg(test)]
mod totp_parameter_tests {
    use super::{CryptoError, OtpAlgorithm, generate_totp};

    #[test]
    fn generation_rejects_digit_counts_that_overflow_the_decimal_modulus() {
        assert!(matches!(
            generate_totp(b"secret", OtpAlgorithm::Sha1, 10, 30, 0),
            Err(CryptoError::InvalidTotpParameters)
        ));
    }
}

#[cfg(test)]
mod composite_key_memory_hygiene_tests {
    use super::{
        CompositeKey, KeyComponent, aes256_cbc_decrypt, aes256_cbc_encrypt, chacha20_ietf_decrypt,
        chacha20_ietf_encrypt, twofish_cbc_decrypt, twofish_cbc_encrypt,
    };
    use zeroize::{Zeroize, ZeroizeOnDrop};

    static_assertions::assert_not_impl_any!(KeyComponent: Clone);
    static_assertions::assert_not_impl_any!(CompositeKey: Clone);

    #[test]
    fn key_component_debug_redacts_secret_bytes() {
        let component = KeyComponent::Password(vec![240, 241, 242, 243]);

        assert_eq!(format!("{component:?}"), "Password([REDACTED])");
    }

    #[test]
    fn composite_key_debug_redacts_component_bytes() {
        let mut key = CompositeKey::default();
        key.add_password_bytes([240, 241, 242, 243]);

        assert_eq!(
            format!("{key:?}"),
            "CompositeKey { components: [Password([REDACTED])] }"
        );
    }

    #[test]
    fn explicit_zeroize_removes_all_owned_key_material() {
        let mut key = CompositeKey::default();
        key.add_password_bytes([1, 2, 3, 4]);
        key.add_key_file([5, 6, 7, 8]);
        key.add_provider_bytes([9, 10, 11, 12]);

        key.zeroize();

        assert!(key.components().is_empty());
    }

    #[test]
    fn owned_key_material_types_guarantee_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<KeyComponent>();
        assert_zeroize_on_drop::<CompositeKey>();
    }

    #[test]
    fn raw_composite_key_is_returned_in_a_zeroizing_owner() {
        fn assert_zeroizing_key(_: &zeroize::Zeroizing<[u8; 32]>) {}

        let mut key = CompositeKey::default();
        key.add_password_bytes([1, 2, 3, 4]);

        let raw_key = key.raw_key().expect("raw key");

        assert_zeroizing_key(&raw_key);
    }

    #[test]
    fn every_kdf_returns_a_zeroizing_transformed_key_owner() {
        fn assert_zeroizing_key(_: &zeroize::Zeroizing<[u8; 32]>) {}

        let profile = super::KdfProfile::AesKdbx4 {
            rounds: 1,
            salt: [3_u8; 32],
        };
        let transformed = profile.derive_key(&[5_u8; 32]).expect("derive key");

        assert_zeroizing_key(&transformed);
    }

    #[test]
    fn key_file_parser_returns_a_zeroizing_key_owner() {
        fn assert_zeroizing_key(_: &zeroize::Zeroizing<[u8; 32]>) {}

        let parsed = super::parse_key_file_bytes(&[7_u8; 32]).expect("parse binary key file");

        assert_zeroizing_key(&parsed);
    }

    #[test]
    fn every_payload_decryptor_returns_a_zeroizing_plaintext_owner() {
        fn assert_zeroizing_plaintext(_: &zeroize::Zeroizing<Vec<u8>>) {}

        let key = [7_u8; 32];
        let iv = [9_u8; 16];
        let nonce = [11_u8; 12];
        let plaintext = b"secret payload";

        let aes = aes256_cbc_decrypt(
            &key,
            &iv,
            &aes256_cbc_encrypt(&key, &iv, plaintext).unwrap(),
        )
        .unwrap();
        let twofish = twofish_cbc_decrypt(
            &key,
            &iv,
            &twofish_cbc_encrypt(&key, &iv, plaintext).unwrap(),
        )
        .unwrap();
        let chacha = chacha20_ietf_decrypt(
            &key,
            &nonce,
            &chacha20_ietf_encrypt(&key, &nonce, plaintext).unwrap(),
        )
        .unwrap();

        assert_zeroizing_plaintext(&aes);
        assert_zeroizing_plaintext(&twofish);
        assert_zeroizing_plaintext(&chacha);
        assert_eq!(aes.as_slice(), plaintext);
        assert_eq!(twofish.as_slice(), plaintext);
        assert_eq!(chacha.as_slice(), plaintext);
    }
}

#[cfg(all(test, feature = "external-fixtures"))]
mod tests {
    use super::{
        CompositeKey, CryptoError, KdfProfile, argon2_thread_mode_name_for_tests,
        parse_key_file_bytes,
    };
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};

    const FIXTURE_KEY_FILE_BINARY: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyBinary.key");
    const FIXTURE_KEY_FILE_HEX: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyHex.key");
    const FIXTURE_KEY_FILE_HASHED: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyHashed.key");
    const FIXTURE_KEY_FILE_XML_V1: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyXml.key");
    const FIXTURE_KEY_FILE_XML_V2: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyXmlV2.keyx");
    const FIXTURE_KEY_FILE_XML_BROKEN_BASE64: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyXmlBrokenBase64.key");
    const FIXTURE_KEY_FILE_XML_V2_HASH_FAIL: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyXmlV2HashFail.keyx");
    const FIXTURE_KEY_FILE_XML_V2_BROKEN_HEX: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyXmlV2BrokenHex.keyx");

    #[test]
    fn composite_key_hashes_password_and_components_in_order() {
        let mut key = CompositeKey::default();
        key.add_password("master");
        key.add_key_file([0xAA, 0xBB, 0xCC]);
        key.add_provider_bytes([0x10, 0x11, 0x12]);

        let raw = key.raw_key().expect("raw key");

        let mut stream = Vec::new();
        stream.extend(Sha256::digest("master".as_bytes()));
        stream.extend([0xAA, 0xBB, 0xCC]);
        stream.extend([0x10, 0x11, 0x12]);
        let expected: [u8; 32] = Sha256::digest(stream).into();

        assert_eq!(raw, expected);
    }

    #[test]
    fn kdf_profiles_derive_distinct_32_byte_keys() {
        let raw = [7_u8; 32];
        let salt = [9_u8; 32];

        let aes = KdfProfile::AesKdbx4 { rounds: 16, salt }
            .derive_key(&raw)
            .expect("aes key");

        let argon = KdfProfile::Argon2id {
            iterations: 2,
            memory_kib: 64 * 1024,
            parallelism: 1,
            salt: vec![3_u8; 16],
        }
        .derive_key(&raw)
        .expect("argon key");

        assert_eq!(aes.len(), 32);
        assert_eq!(argon.len(), 32);
        assert_ne!(aes, raw);
        assert_ne!(argon, raw);
        assert_ne!(aes, argon);
    }

    #[test]
    fn argon2_parallelism_above_one_uses_parallel_thread_mode() {
        assert_eq!(argon2_thread_mode_name_for_tests(1), "sequential");
        assert_eq!(argon2_thread_mode_name_for_tests(4), "parallel");
    }

    #[test]
    fn key_file_parser_supports_binary_hex_hashed_and_xml_formats() {
        assert_eq!(
            parse_key_file_bytes(FIXTURE_KEY_FILE_BINARY)
                .expect("binary key file")
                .to_vec(),
            FIXTURE_KEY_FILE_BINARY.to_vec()
        );
        assert_eq!(
            parse_key_file_bytes(FIXTURE_KEY_FILE_HEX)
                .expect("hex key file")
                .to_vec(),
            HEXLOWER
                .decode(b"0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210")
                .expect("decode expected hex")
        );
        assert_eq!(
            parse_key_file_bytes(FIXTURE_KEY_FILE_HASHED)
                .expect("hashed key file")
                .to_vec(),
            HEXLOWER
                .decode(b"a86c55910c7e33606dfe88eb3da46b80b73287c63544ea82eb40dadf80fe8df4")
                .expect("decode expected hash")
        );
        assert_eq!(
            parse_key_file_bytes(FIXTURE_KEY_FILE_XML_V1)
                .expect("xml v1 key file")
                .to_vec(),
            HEXLOWER
                .decode(b"9e135a97e53da7a875ad600027962b36431accc4d990858b8b7582e0942fe639")
                .expect("decode expected xml v1")
        );
        assert_eq!(
            parse_key_file_bytes(FIXTURE_KEY_FILE_XML_V2)
                .expect("xml v2 key file")
                .to_vec(),
            HEXLOWER
                .decode(b"a7007945d07d54ba28df64341b4500fc9750dfb1d36ada2d9c32dc194c7ab01b")
                .expect("decode expected xml v2")
        );
    }

    #[test]
    fn key_file_parser_rejects_invalid_xml_payloads() {
        assert!(matches!(
            parse_key_file_bytes(FIXTURE_KEY_FILE_XML_BROKEN_BASE64),
            Err(CryptoError::InvalidKeyFile)
        ));
        assert!(matches!(
            parse_key_file_bytes(FIXTURE_KEY_FILE_XML_V2_HASH_FAIL),
            Err(CryptoError::KeyFileIntegrityMismatch)
        ));
        assert!(matches!(
            parse_key_file_bytes(FIXTURE_KEY_FILE_XML_V2_BROKEN_HEX),
            Err(CryptoError::InvalidKeyFile)
        ));
    }
}
