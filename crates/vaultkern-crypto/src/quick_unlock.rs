use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use hkdf::Hkdf;
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::{
        rand_core::{OsRng, RngCore},
        sec1::ToEncodedPoint,
    },
};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const FORMAT_VERSION: u8 = 1;
pub const MAX_ENVELOPE_LEN: usize = 256;
const MAX_BINDING_COMPONENT_LEN: usize = 1024;
const AAD_DOMAIN: &[u8] = b"vaultkern.quick-unlock.aad/v1";
const HKDF_SALT: &[u8] = b"vaultkern.quick-unlock.hkdf-salt/v1";
const HKDF_INFO: &[u8] = b"vaultkern.quick-unlock.kek/v1";
const ENVELOPE_MAGIC: &[u8; 4] = b"VKQE";
const EPHEMERAL_KEY_LEN: usize = 33;
const NONCE_LEN: usize = 12;
const KDF_GENERATION_LEN: usize = 32;
const PLAINTEXT_LEN: usize = 64;
const TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = PLAINTEXT_LEN + TAG_LEN;
const HEADER_LEN: usize = 10;
const ENVELOPE_LEN: usize =
    HEADER_LEN + EPHEMERAL_KEY_LEN + NONCE_LEN + KDF_GENERATION_LEN + CIPHERTEXT_LEN;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QuickUnlockError {
    #[error("invalid quick-unlock envelope binding")]
    InvalidBinding,
    #[error("quick-unlock envelope exceeds the size limit")]
    EnvelopeTooLong,
    #[error("malformed quick-unlock envelope")]
    MalformedEnvelope,
    #[error("unsupported quick-unlock envelope version")]
    UnsupportedVersion,
    #[error("invalid P-256 public key")]
    InvalidPublicKey,
    #[error("quick-unlock key derivation failed")]
    KeyDerivationFailed,
    #[error("quick-unlock envelope authentication failed")]
    AuthenticationFailed,
    #[error("quick-unlock envelope KDF generation does not match the current vault")]
    KdfGenerationMismatch,
}

pub type Result<T> = std::result::Result<T, QuickUnlockError>;

/// Post-KDF key material. The value is neither cloneable nor serializable.
pub struct TransformedKey(Zeroizing<[u8; 32]>);

impl TransformedKey {
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TransformedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransformedKey([REDACTED])")
    }
}

/// Hash identifying the exact KDF parameters that produced a transformed key.
pub struct KdfGeneration(Zeroizing<[u8; 32]>);

impl KdfGeneration {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for KdfGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KdfGeneration([REDACTED])")
    }
}

/// P-256 ECDH output returned by a platform private-key operation.
pub struct EcdhSharedSecret(Zeroizing<[u8; 32]>);

impl EcdhSharedSecret {
    /// Constructs a shared secret from a big-endian P-256 affine x-coordinate.
    pub fn from_be_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Constructs a shared secret from CNG's little-endian `BCRYPT_KDF_RAW_SECRET` output.
    pub fn from_cng_le_bytes(mut bytes: Zeroizing<[u8; 32]>) -> Self {
        bytes.reverse();
        Self(bytes)
    }
}

impl fmt::Debug for EcdhSharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EcdhSharedSecret([REDACTED])")
    }
}

pub struct OpenedQuickUnlock {
    transformed_key: TransformedKey,
    kdf_generation: KdfGeneration,
}

impl OpenedQuickUnlock {
    pub fn transformed_key(&self) -> &TransformedKey {
        &self.transformed_key
    }

    pub fn kdf_generation(&self) -> &KdfGeneration {
        &self.kdf_generation
    }

    pub fn into_transformed_key(self) -> TransformedKey {
        self.transformed_key
    }
}

impl fmt::Debug for OpenedQuickUnlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedQuickUnlock([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct QuickUnlockEnvelope {
    ephemeral_public_key: [u8; EPHEMERAL_KEY_LEN],
    nonce: [u8; NONCE_LEN],
    kdf_generation: [u8; KDF_GENERATION_LEN],
    ciphertext_and_tag: [u8; CIPHERTEXT_LEN],
}

impl fmt::Debug for QuickUnlockEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuickUnlockEnvelope")
            .field("format_version", &FORMAT_VERSION)
            .finish_non_exhaustive()
    }
}

impl QuickUnlockEnvelope {
    /// Parses the canonical v1 `VKQE` encoding without accepting extensions.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_LEN {
            return Err(QuickUnlockError::EnvelopeTooLong);
        }
        if bytes.len() < HEADER_LEN || &bytes[..4] != ENVELOPE_MAGIC {
            return Err(QuickUnlockError::MalformedEnvelope);
        }
        if bytes[4] != FORMAT_VERSION {
            return Err(QuickUnlockError::UnsupportedVersion);
        }

        let ephemeral_len = usize::from(bytes[5]);
        let nonce_len = usize::from(bytes[6]);
        let kdf_generation_len = usize::from(bytes[7]);
        let ciphertext_len = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
        if ephemeral_len != EPHEMERAL_KEY_LEN
            || nonce_len != NONCE_LEN
            || kdf_generation_len != KDF_GENERATION_LEN
            || ciphertext_len != CIPHERTEXT_LEN
            || bytes.len()
                != HEADER_LEN + ephemeral_len + nonce_len + kdf_generation_len + ciphertext_len
        {
            return Err(QuickUnlockError::MalformedEnvelope);
        }

        let ephemeral_end = HEADER_LEN + EPHEMERAL_KEY_LEN;
        let nonce_end = ephemeral_end + NONCE_LEN;
        let kdf_generation_end = nonce_end + KDF_GENERATION_LEN;
        let ephemeral_public_key: [u8; EPHEMERAL_KEY_LEN] = bytes[HEADER_LEN..ephemeral_end]
            .try_into()
            .map_err(|_| QuickUnlockError::MalformedEnvelope)?;
        PublicKey::from_sec1_bytes(&ephemeral_public_key)
            .map_err(|_| QuickUnlockError::InvalidPublicKey)?;

        Ok(Self {
            ephemeral_public_key,
            nonce: bytes[ephemeral_end..nonce_end]
                .try_into()
                .map_err(|_| QuickUnlockError::MalformedEnvelope)?,
            kdf_generation: bytes[nonce_end..kdf_generation_end]
                .try_into()
                .map_err(|_| QuickUnlockError::MalformedEnvelope)?,
            ciphertext_and_tag: bytes[kdf_generation_end..]
                .try_into()
                .map_err(|_| QuickUnlockError::MalformedEnvelope)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(ENVELOPE_LEN);
        encoded.extend_from_slice(ENVELOPE_MAGIC);
        encoded.push(FORMAT_VERSION);
        encoded.push(EPHEMERAL_KEY_LEN as u8);
        encoded.push(NONCE_LEN as u8);
        encoded.push(KDF_GENERATION_LEN as u8);
        encoded.extend_from_slice(&(CIPHERTEXT_LEN as u16).to_be_bytes());
        encoded.extend_from_slice(&self.ephemeral_public_key);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.kdf_generation);
        encoded.extend_from_slice(&self.ciphertext_and_tag);
        encoded
    }

    pub fn ephemeral_public_key_sec1(&self) -> &[u8; EPHEMERAL_KEY_LEN] {
        &self.ephemeral_public_key
    }
}

pub struct EnvelopeBinding<'a> {
    identifier_scope: &'a str,
    vault_ref_id: &'a str,
    record_generation: u64,
    kdf_generation: &'a KdfGeneration,
}

impl<'a> EnvelopeBinding<'a> {
    pub fn new(
        identifier_scope: &'a str,
        vault_ref_id: &'a str,
        record_generation: u64,
        kdf_generation: &'a KdfGeneration,
    ) -> Result<Self> {
        if identifier_scope.is_empty()
            || vault_ref_id.is_empty()
            || identifier_scope.len() > MAX_BINDING_COMPONENT_LEN
            || vault_ref_id.len() > MAX_BINDING_COMPONENT_LEN
        {
            return Err(QuickUnlockError::InvalidBinding);
        }

        Ok(Self {
            identifier_scope,
            vault_ref_id,
            record_generation,
            kdf_generation,
        })
    }
}

fn encode_aad(
    format_version: u8,
    binding: &EnvelopeBinding<'_>,
    kdf_generation: &[u8; KDF_GENERATION_LEN],
    ephemeral_public_key: &[u8; EPHEMERAL_KEY_LEN],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        AAD_DOMAIN.len()
            + binding.identifier_scope.len()
            + binding.vault_ref_id.len()
            + kdf_generation.len()
            + ephemeral_public_key.len()
            + 64,
    );
    append_aad_field(&mut aad, 0, AAD_DOMAIN);
    append_aad_field(&mut aad, 1, &[format_version]);
    append_aad_field(&mut aad, 2, binding.identifier_scope.as_bytes());
    append_aad_field(&mut aad, 3, binding.vault_ref_id.as_bytes());
    append_aad_field(&mut aad, 4, &binding.record_generation.to_be_bytes());
    append_aad_field(&mut aad, 5, kdf_generation);
    append_aad_field(&mut aad, 6, ephemeral_public_key);
    aad
}

fn append_aad_field(target: &mut Vec<u8>, tag: u8, value: &[u8]) {
    target.push(tag);
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value);
}

pub fn seal(
    recipient_public_key: &PublicKey,
    binding: &EnvelopeBinding<'_>,
    transformed_key: TransformedKey,
) -> Result<QuickUnlockEnvelope> {
    let ephemeral_secret = SecretKey::random(&mut OsRng);
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    seal_with_material(
        recipient_public_key,
        binding,
        transformed_key,
        &ephemeral_secret,
        nonce,
    )
}

pub fn open_with_shared_secret(
    envelope: &QuickUnlockEnvelope,
    binding: &EnvelopeBinding<'_>,
    shared_secret: EcdhSharedSecret,
) -> Result<OpenedQuickUnlock> {
    let key = derive_kek(&shared_secret)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| QuickUnlockError::KeyDerivationFailed)?;
    let aad = encode_aad(
        FORMAT_VERSION,
        binding,
        &envelope.kdf_generation,
        &envelope.ephemeral_public_key,
    );
    let mut plaintext = Zeroizing::new([0_u8; PLAINTEXT_LEN]);
    plaintext.copy_from_slice(&envelope.ciphertext_and_tag[..PLAINTEXT_LEN]);
    let tag = Tag::from_slice(&envelope.ciphertext_and_tag[PLAINTEXT_LEN..]);

    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&envelope.nonce),
            &aad,
            plaintext.as_mut_slice(),
            tag,
        )
        .map_err(|_| QuickUnlockError::AuthenticationFailed)?;

    let mut transformed_bytes = Zeroizing::new([0_u8; 32]);
    transformed_bytes.copy_from_slice(&plaintext[..32]);
    let mut generation_bytes = Zeroizing::new([0_u8; 32]);
    generation_bytes.copy_from_slice(&plaintext[32..]);
    if generation_bytes.as_ref() != envelope.kdf_generation {
        return Err(QuickUnlockError::AuthenticationFailed);
    }
    if envelope.kdf_generation.as_slice() != binding.kdf_generation.as_bytes() {
        return Err(QuickUnlockError::KdfGenerationMismatch);
    }

    Ok(OpenedQuickUnlock {
        transformed_key: TransformedKey(transformed_bytes),
        kdf_generation: KdfGeneration(generation_bytes),
    })
}

fn seal_with_material(
    recipient_public_key: &PublicKey,
    binding: &EnvelopeBinding<'_>,
    transformed_key: TransformedKey,
    ephemeral_secret: &SecretKey,
    nonce: [u8; NONCE_LEN],
) -> Result<QuickUnlockEnvelope> {
    let ephemeral_public_key = ephemeral_secret.public_key();
    let encoded_public_key = ephemeral_public_key.to_encoded_point(true);
    let ephemeral_public_key: [u8; EPHEMERAL_KEY_LEN] = encoded_public_key
        .as_bytes()
        .try_into()
        .map_err(|_| QuickUnlockError::InvalidPublicKey)?;
    let raw_shared_secret = diffie_hellman(
        ephemeral_secret.to_nonzero_scalar(),
        recipient_public_key.as_affine(),
    );
    let mut shared_secret = Zeroizing::new([0_u8; 32]);
    shared_secret.copy_from_slice(raw_shared_secret.raw_secret_bytes());
    let shared_secret = EcdhSharedSecret::from_be_bytes(shared_secret);
    seal_from_shared_secret(
        ephemeral_public_key,
        nonce,
        binding,
        transformed_key,
        shared_secret,
    )
}

fn seal_from_shared_secret(
    ephemeral_public_key: [u8; EPHEMERAL_KEY_LEN],
    nonce: [u8; NONCE_LEN],
    binding: &EnvelopeBinding<'_>,
    transformed_key: TransformedKey,
    shared_secret: EcdhSharedSecret,
) -> Result<QuickUnlockEnvelope> {
    let key = derive_kek(&shared_secret)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| QuickUnlockError::KeyDerivationFailed)?;
    let kdf_generation = *binding.kdf_generation.as_bytes();
    let aad = encode_aad(
        FORMAT_VERSION,
        binding,
        &kdf_generation,
        &ephemeral_public_key,
    );
    let mut plaintext = Zeroizing::new([0_u8; PLAINTEXT_LEN]);
    plaintext[..32].copy_from_slice(transformed_key.expose_secret());
    plaintext[32..].copy_from_slice(binding.kdf_generation.as_bytes());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, plaintext.as_mut_slice())
        .map_err(|_| QuickUnlockError::AuthenticationFailed)?;
    let mut ciphertext_and_tag = [0_u8; CIPHERTEXT_LEN];
    ciphertext_and_tag[..PLAINTEXT_LEN].copy_from_slice(plaintext.as_slice());
    ciphertext_and_tag[PLAINTEXT_LEN..].copy_from_slice(tag.as_slice());

    Ok(QuickUnlockEnvelope {
        ephemeral_public_key,
        nonce,
        kdf_generation,
        ciphertext_and_tag,
    })
}

fn derive_kek(shared_secret: &EcdhSharedSecret) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.0.as_ref());
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(HKDF_INFO, key.as_mut_slice())
        .map_err(|_| QuickUnlockError::KeyDerivationFailed)?;
    Ok(key)
}

#[cfg(test)]
fn seal_with_test_material(
    recipient_public_key: &PublicKey,
    binding: &EnvelopeBinding<'_>,
    transformed_key: TransformedKey,
    ephemeral_secret: &SecretKey,
    nonce: [u8; NONCE_LEN],
) -> Result<QuickUnlockEnvelope> {
    seal_with_material(
        recipient_public_key,
        binding,
        transformed_key,
        ephemeral_secret,
        nonce,
    )
}

#[cfg(test)]
fn derive_test_shared_secret(
    recipient_secret: &SecretKey,
    envelope: &QuickUnlockEnvelope,
) -> Result<EcdhSharedSecret> {
    let ephemeral_public_key = PublicKey::from_sec1_bytes(envelope.ephemeral_public_key_sec1())
        .map_err(|_| QuickUnlockError::InvalidPublicKey)?;
    let raw_shared_secret = diffie_hellman(
        recipient_secret.to_nonzero_scalar(),
        ephemeral_public_key.as_affine(),
    );
    let mut shared_secret = Zeroizing::new([0_u8; 32]);
    shared_secret.copy_from_slice(raw_shared_secret.raw_secret_bytes());
    Ok(EcdhSharedSecret::from_be_bytes(shared_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(TransformedKey: Clone, serde::Serialize);
    assert_not_impl_any!(KdfGeneration: Clone, serde::Serialize);
    assert_not_impl_any!(EcdhSharedSecret: Clone, serde::Serialize);
    assert_not_impl_any!(OpenedQuickUnlock: Clone, serde::Serialize);

    fn secret(bytes: [u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(bytes)
    }

    #[test]
    fn secret_carriers_have_fixed_lengths_and_redacted_debug() {
        let transformed = TransformedKey::new(secret([0xa5; 32]));
        let generation = KdfGeneration::new([0x5a; 32]);
        let shared_secret = EcdhSharedSecret::from_be_bytes(secret([0xc3; 32]));

        assert_eq!(transformed.expose_secret().len(), 32);
        assert_eq!(generation.as_bytes().len(), 32);
        assert_eq!(format!("{transformed:?}"), "TransformedKey([REDACTED])");
        assert_eq!(format!("{generation:?}"), "KdfGeneration([REDACTED])");
        assert_eq!(format!("{shared_secret:?}"), "EcdhSharedSecret([REDACTED])");
        assert!(!format!("{transformed:?}").contains("165"));
        assert!(!format!("{generation:?}").contains("90"));
        assert!(std::mem::needs_drop::<TransformedKey>());
        assert!(std::mem::needs_drop::<KdfGeneration>());
        assert!(std::mem::needs_drop::<EcdhSharedSecret>());
    }

    #[test]
    fn public_crypto_api_accepts_only_derived_key_material() {
        let _transformed_constructor: fn(Zeroizing<[u8; 32]>) -> TransformedKey =
            TransformedKey::new;
        let _big_endian_shared_secret_constructor: fn(Zeroizing<[u8; 32]>) -> EcdhSharedSecret =
            EcdhSharedSecret::from_be_bytes;
        let _cng_shared_secret_constructor: fn(Zeroizing<[u8; 32]>) -> EcdhSharedSecret =
            EcdhSharedSecret::from_cng_le_bytes;
        let _seal_signature: for<'a> fn(
            &PublicKey,
            &EnvelopeBinding<'a>,
            TransformedKey,
        ) -> Result<QuickUnlockEnvelope> = seal;
        let _open_signature: for<'a> fn(
            &QuickUnlockEnvelope,
            &EnvelopeBinding<'a>,
            EcdhSharedSecret,
        ) -> Result<OpenedQuickUnlock> = open_with_shared_secret;
    }

    #[test]
    fn authentication_errors_do_not_include_secret_material() {
        let recipient_secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let ephemeral_secret = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let generation = KdfGeneration::new([0x33; 32]);
        let binding = EnvelopeBinding::new("app-group", "vault-123", 42, &generation).unwrap();
        let envelope = seal_with_test_material(
            &recipient_secret.public_key(),
            &binding,
            TransformedKey::new(secret([0xa5; 32])),
            &ephemeral_secret,
            [0x55; 12],
        )
        .unwrap();

        let error = open_with_shared_secret(
            &envelope,
            &binding,
            EcdhSharedSecret::from_be_bytes(secret([0xa5; 32])),
        )
        .unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert_eq!(error, QuickUnlockError::AuthenticationFailed);
        assert!(!rendered.contains("a5a5"));
        assert!(!rendered.contains("165"));
        assert!(!format!("{envelope:?}").contains("a5a5"));
    }

    #[test]
    fn aad_length_prefixes_distinguish_adjacent_strings() {
        let generation = KdfGeneration::new([0x11; 32]);
        let other_generation = KdfGeneration::new([0x12; 32]);
        let left = EnvelopeBinding::new("ab", "c", 7, &generation).unwrap();
        let right = EnvelopeBinding::new("a", "bc", 7, &generation).unwrap();
        let ephemeral_public_key = [0x02; EPHEMERAL_KEY_LEN];
        let mut other_ephemeral_public_key = ephemeral_public_key;
        other_ephemeral_public_key[0] = 0x03;

        assert_ne!(
            encode_aad(
                FORMAT_VERSION,
                &left,
                generation.as_bytes(),
                &ephemeral_public_key
            ),
            encode_aad(
                FORMAT_VERSION,
                &right,
                generation.as_bytes(),
                &ephemeral_public_key
            )
        );
        assert_ne!(
            encode_aad(
                FORMAT_VERSION,
                &left,
                generation.as_bytes(),
                &ephemeral_public_key
            ),
            encode_aad(2, &left, generation.as_bytes(), &ephemeral_public_key)
        );
        assert_ne!(
            encode_aad(
                FORMAT_VERSION,
                &left,
                generation.as_bytes(),
                &ephemeral_public_key
            ),
            encode_aad(
                FORMAT_VERSION,
                &left,
                generation.as_bytes(),
                &other_ephemeral_public_key
            )
        );
        assert_ne!(
            encode_aad(
                FORMAT_VERSION,
                &left,
                generation.as_bytes(),
                &ephemeral_public_key
            ),
            encode_aad(
                FORMAT_VERSION,
                &left,
                other_generation.as_bytes(),
                &ephemeral_public_key
            )
        );
    }

    #[test]
    fn binding_rejects_empty_or_oversized_identifiers() {
        let generation = KdfGeneration::new([0x11; 32]);
        let oversized = "x".repeat(MAX_BINDING_COMPONENT_LEN + 1);

        assert!(EnvelopeBinding::new("", "vault", 1, &generation).is_err());
        assert!(EnvelopeBinding::new("scope", "", 1, &generation).is_err());
        assert!(EnvelopeBinding::new(&oversized, "vault", 1, &generation).is_err());
        assert!(EnvelopeBinding::new("scope", &oversized, 1, &generation).is_err());
    }

    #[test]
    fn deterministic_seal_and_platform_shared_secret_open_round_trip() {
        let recipient_secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let ephemeral_secret = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let generation = KdfGeneration::new([0x33; 32]);
        let binding = EnvelopeBinding::new("app-group", "vault-123", 42, &generation).unwrap();
        let transformed_bytes = [0x44; 32];

        let envelope = seal_with_test_material(
            &recipient_secret.public_key(),
            &binding,
            TransformedKey::new(secret(transformed_bytes)),
            &ephemeral_secret,
            [0x55; 12],
        )
        .unwrap();
        let shared_secret = derive_test_shared_secret(&recipient_secret, &envelope).unwrap();
        let opened = open_with_shared_secret(&envelope, &binding, shared_secret).unwrap();

        assert_eq!(opened.transformed_key().expose_secret(), &transformed_bytes);
        assert_eq!(opened.kdf_generation().as_bytes(), generation.as_bytes());
    }

    #[test]
    fn cng_little_endian_shared_secret_opens_envelope() {
        let recipient_secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let ephemeral_secret = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let generation = KdfGeneration::new([0x33; 32]);
        let binding = EnvelopeBinding::new("app-group", "vault-123", 42, &generation).unwrap();
        let transformed_bytes = [0x44; 32];
        let envelope = seal_with_test_material(
            &recipient_secret.public_key(),
            &binding,
            TransformedKey::new(secret(transformed_bytes)),
            &ephemeral_secret,
            [0x55; 12],
        )
        .unwrap();
        let cng_raw_secret: [u8; 32] = HEXLOWER
            .decode(b"f69aa72c62086944908043484dbc29eef0c6ba3ba5d44aca983c19581f26fccc")
            .unwrap()
            .try_into()
            .unwrap();

        let opened = open_with_shared_secret(
            &envelope,
            &binding,
            EcdhSharedSecret::from_cng_le_bytes(secret(cng_raw_secret)),
        )
        .unwrap();

        assert_eq!(opened.transformed_key().expose_secret(), &transformed_bytes);
    }

    #[test]
    fn stale_kdf_generation_is_reported_for_reenrollment() {
        let recipient_secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let ephemeral_secret = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let enrolled_generation = KdfGeneration::new([0x33; 32]);
        let enrolled_binding =
            EnvelopeBinding::new("app-group", "vault-123", 42, &enrolled_generation).unwrap();
        let envelope = seal_with_test_material(
            &recipient_secret.public_key(),
            &enrolled_binding,
            TransformedKey::new(secret([0x44; 32])),
            &ephemeral_secret,
            [0x55; 12],
        )
        .unwrap();

        let current_generation = KdfGeneration::new([0x34; 32]);
        let current_binding =
            EnvelopeBinding::new("app-group", "vault-123", 42, &current_generation).unwrap();
        let shared_secret = derive_test_shared_secret(&recipient_secret, &envelope).unwrap();

        assert_eq!(
            open_with_shared_secret(&envelope, &current_binding, shared_secret).unwrap_err(),
            QuickUnlockError::KdfGenerationMismatch
        );
    }

    #[test]
    fn deterministic_envelope_encoding_matches_pinned_vector() {
        let recipient_secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let ephemeral_secret = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let generation = KdfGeneration::new([0x33; 32]);
        let binding = EnvelopeBinding::new("app-group", "vault-123", 42, &generation).unwrap();
        let envelope = seal_with_test_material(
            &recipient_secret.public_key(),
            &binding,
            TransformedKey::new(secret([0x44; 32])),
            &ephemeral_secret,
            [0x55; 12],
        )
        .unwrap();
        let expected = HEXLOWER
            .decode(
                concat!(
                    "564b514501210c20005003d65a93977caa3d1b081852ff57a79e465f16605773",
                    "04baead505dd3a48589cf3555555555555555555555555333333333333333333",
                    "333333333333333333333333333333333333333333333329baf0fe3a483a8a1e",
                    "936d88d479cad872144b981cd8b1337bf085809ddd32deaa481807d3e2778564",
                    "a9d037dcf0fa0551f2cae25778be792996bdcd6869c0d963a26686db89c8c73b",
                    "3bdf64b4c23344",
                )
                .as_bytes(),
            )
            .unwrap();

        assert_eq!(envelope.to_bytes(), expected);
        assert_eq!(
            QuickUnlockEnvelope::from_bytes(&expected).unwrap(),
            envelope
        );
    }

    #[test]
    fn inverse_point_encoding_tampering_is_rejected() {
        let recipient_secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let ephemeral_secret = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let generation = KdfGeneration::new([0x33; 32]);
        let binding = EnvelopeBinding::new("app-group", "vault-123", 42, &generation).unwrap();
        let envelope = seal_with_test_material(
            &recipient_secret.public_key(),
            &binding,
            TransformedKey::new(secret([0x44; 32])),
            &ephemeral_secret,
            [0x55; 12],
        )
        .unwrap();

        let mut inverse_point = envelope.to_bytes();
        inverse_point[HEADER_LEN] ^= 1;
        let inverse_point = QuickUnlockEnvelope::from_bytes(&inverse_point).unwrap();
        let shared = derive_test_shared_secret(&recipient_secret, &inverse_point).unwrap();

        assert_eq!(
            open_with_shared_secret(&inverse_point, &binding, shared).unwrap_err(),
            QuickUnlockError::AuthenticationFailed
        );
    }

    #[test]
    fn binding_and_envelope_tampering_is_rejected() {
        let recipient_secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let ephemeral_secret = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let generation = KdfGeneration::new([0x33; 32]);
        let binding = EnvelopeBinding::new("app-group", "vault-123", 42, &generation).unwrap();
        let envelope = seal_with_test_material(
            &recipient_secret.public_key(),
            &binding,
            TransformedKey::new(secret([0x44; 32])),
            &ephemeral_secret,
            [0x55; 12],
        )
        .unwrap();

        for altered_binding in [
            EnvelopeBinding::new("other-scope", "vault-123", 42, &generation).unwrap(),
            EnvelopeBinding::new("app-group", "other-vault", 42, &generation).unwrap(),
            EnvelopeBinding::new("app-group", "vault-123", 43, &generation).unwrap(),
        ] {
            let shared = derive_test_shared_secret(&recipient_secret, &envelope).unwrap();
            assert_eq!(
                open_with_shared_secret(&envelope, &altered_binding, shared).unwrap_err(),
                QuickUnlockError::AuthenticationFailed
            );
        }

        let altered_generation = KdfGeneration::new([0x34; 32]);
        let altered_binding =
            EnvelopeBinding::new("app-group", "vault-123", 42, &altered_generation).unwrap();
        let shared = derive_test_shared_secret(&recipient_secret, &envelope).unwrap();
        assert_eq!(
            open_with_shared_secret(&envelope, &altered_binding, shared).unwrap_err(),
            QuickUnlockError::KdfGenerationMismatch
        );

        let mut version = envelope.to_bytes();
        version[4] = FORMAT_VERSION + 1;
        assert_eq!(
            QuickUnlockEnvelope::from_bytes(&version).unwrap_err(),
            QuickUnlockError::UnsupportedVersion
        );

        let replacement_ephemeral = p256::SecretKey::from_slice(&[0x23; 32])
            .unwrap()
            .public_key()
            .to_encoded_point(true);
        let mut ephemeral = envelope.to_bytes();
        ephemeral[HEADER_LEN..HEADER_LEN + EPHEMERAL_KEY_LEN]
            .copy_from_slice(replacement_ephemeral.as_bytes());
        let ephemeral = QuickUnlockEnvelope::from_bytes(&ephemeral).unwrap();
        let shared = derive_test_shared_secret(&recipient_secret, &ephemeral).unwrap();
        assert_eq!(
            open_with_shared_secret(&ephemeral, &binding, shared).unwrap_err(),
            QuickUnlockError::AuthenticationFailed
        );

        for offset in [
            HEADER_LEN + EPHEMERAL_KEY_LEN,
            HEADER_LEN + EPHEMERAL_KEY_LEN + NONCE_LEN,
            ENVELOPE_LEN - 1,
        ] {
            let mut tampered = envelope.to_bytes();
            tampered[offset] ^= 1;
            let tampered = QuickUnlockEnvelope::from_bytes(&tampered).unwrap();
            let shared = derive_test_shared_secret(&recipient_secret, &tampered).unwrap();
            assert_eq!(
                open_with_shared_secret(&tampered, &binding, shared).unwrap_err(),
                QuickUnlockError::AuthenticationFailed
            );
        }
    }

    #[test]
    fn production_seal_uses_fresh_ephemeral_key_and_nonce() {
        let recipient_secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let generation = KdfGeneration::new([0x33; 32]);
        let binding = EnvelopeBinding::new("app-group", "vault-123", 42, &generation).unwrap();

        let first = seal(
            &recipient_secret.public_key(),
            &binding,
            TransformedKey::new(secret([0x44; 32])),
        )
        .unwrap();
        let second = seal(
            &recipient_secret.public_key(),
            &binding,
            TransformedKey::new(secret([0x44; 32])),
        )
        .unwrap();

        assert_ne!(first.ephemeral_public_key, second.ephemeral_public_key);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first, second);
    }

    #[test]
    fn parser_fails_closed_for_noncanonical_or_malformed_inputs() {
        let recipient_secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let ephemeral_secret = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let generation = KdfGeneration::new([0x33; 32]);
        let binding = EnvelopeBinding::new("app-group", "vault-123", 42, &generation).unwrap();
        let valid = seal_with_test_material(
            &recipient_secret.public_key(),
            &binding,
            TransformedKey::new(secret([0x44; 32])),
            &ephemeral_secret,
            [0x55; 12],
        )
        .unwrap()
        .to_bytes();

        for truncated_len in 0..valid.len() {
            assert!(QuickUnlockEnvelope::from_bytes(&valid[..truncated_len]).is_err());
        }

        let mut overlong = valid.clone();
        overlong.resize(MAX_ENVELOPE_LEN + 1, 0);
        assert_eq!(
            QuickUnlockEnvelope::from_bytes(&overlong).unwrap_err(),
            QuickUnlockError::EnvelopeTooLong
        );

        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            QuickUnlockEnvelope::from_bytes(&trailing).unwrap_err(),
            QuickUnlockError::MalformedEnvelope
        );

        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            QuickUnlockEnvelope::from_bytes(&bad_magic).unwrap_err(),
            QuickUnlockError::MalformedEnvelope
        );

        let mut short_tag = valid[..valid.len() - 1].to_vec();
        short_tag[9] = (CIPHERTEXT_LEN - 1) as u8;
        assert_eq!(
            QuickUnlockEnvelope::from_bytes(&short_tag).unwrap_err(),
            QuickUnlockError::MalformedEnvelope
        );

        for (offset, replacement) in [(5, 65_u8), (6, 13_u8), (7, 31_u8), (8, 1_u8), (9, 79_u8)] {
            let mut noncanonical = valid.clone();
            noncanonical[offset] = replacement;
            assert_eq!(
                QuickUnlockEnvelope::from_bytes(&noncanonical).unwrap_err(),
                QuickUnlockError::MalformedEnvelope
            );
        }

        let mut invalid_key = valid.clone();
        invalid_key[HEADER_LEN..HEADER_LEN + EPHEMERAL_KEY_LEN].fill(0);
        assert_eq!(
            QuickUnlockEnvelope::from_bytes(&invalid_key).unwrap_err(),
            QuickUnlockError::InvalidPublicKey
        );
    }
}
