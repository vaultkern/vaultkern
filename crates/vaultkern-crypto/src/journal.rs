use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use hkdf::Hkdf;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::quick_unlock::TransformedKey;

const HKDF_INFO: &[u8] = b"vaultkern.journal.v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JournalCryptoError {
    #[error("journal payload key derivation failed")]
    KeyDerivationFailed,
    #[error("journal nonce generation failed")]
    EntropyUnavailable,
    #[error("journal payload encryption failed")]
    EncryptionFailed,
    #[error("journal payload authentication failed")]
    AuthenticationFailed,
}

pub type Result<T> = std::result::Result<T, JournalCryptoError>;

struct JournalKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for JournalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalKey([REDACTED])")
    }
}

/// AES-256-GCM journal payload primitive rooted in post-KDF key material.
pub struct JournalCipher {
    key: JournalKey,
}

impl fmt::Debug for JournalCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalCipher([REDACTED])")
    }
}

impl JournalCipher {
    /// Derives the journal key with HKDF-SHA256 and no salt.
    pub fn new(transformed_key: &TransformedKey) -> Result<Self> {
        Ok(Self {
            key: derive_journal_key(transformed_key)?,
        })
    }

    /// Seals opaque bytes with a fresh 12-byte CSPRNG nonce.
    pub fn seal(
        &self,
        plaintext: &[u8],
        op_id: Uuid,
        vault_ref_id: &str,
    ) -> Result<SealedJournalPayload> {
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| JournalCryptoError::EntropyUnavailable)?;
        self.seal_with_nonce(plaintext, op_id, vault_ref_id, nonce)
    }

    /// Authenticates and opens `ciphertext || tag` for the supplied record binding.
    pub fn open(
        &self,
        op_id: Uuid,
        vault_ref_id: &str,
        nonce: &[u8; NONCE_LEN],
        ciphertext_and_tag: &[u8],
    ) -> Result<OpenedJournalPayload> {
        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(JournalCryptoError::AuthenticationFailed);
        }

        let cipher = Aes256Gcm::new_from_slice(self.key.0.as_ref())
            .map_err(|_| JournalCryptoError::KeyDerivationFailed)?;
        let aad = encode_aad(op_id, vault_ref_id);
        let (ciphertext, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_LEN);
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                &aad,
                plaintext.as_mut_slice(),
                Tag::from_slice(tag),
            )
            .map_err(|_| JournalCryptoError::AuthenticationFailed)?;

        Ok(OpenedJournalPayload(plaintext))
    }

    fn seal_with_nonce(
        &self,
        plaintext: &[u8],
        op_id: Uuid,
        vault_ref_id: &str,
        nonce: [u8; NONCE_LEN],
    ) -> Result<SealedJournalPayload> {
        let cipher = Aes256Gcm::new_from_slice(self.key.0.as_ref())
            .map_err(|_| JournalCryptoError::KeyDerivationFailed)?;
        let aad = encode_aad(op_id, vault_ref_id);
        let mut encrypted = Zeroizing::new(plaintext.to_vec());
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, encrypted.as_mut_slice())
            .map_err(|_| JournalCryptoError::EncryptionFailed)?;
        let output_len = encrypted
            .len()
            .checked_add(tag.len())
            .ok_or(JournalCryptoError::EncryptionFailed)?;
        let mut ciphertext_and_tag = Vec::with_capacity(output_len);
        ciphertext_and_tag.extend_from_slice(encrypted.as_slice());
        ciphertext_and_tag.extend_from_slice(tag.as_slice());

        Ok(SealedJournalPayload {
            nonce,
            ciphertext_and_tag,
        })
    }

    #[cfg(test)]
    fn seal_with_nonce_for_test(
        &self,
        plaintext: &[u8],
        op_id: Uuid,
        vault_ref_id: &str,
        nonce: [u8; NONCE_LEN],
    ) -> Result<SealedJournalPayload> {
        self.seal_with_nonce(plaintext, op_id, vault_ref_id, nonce)
    }
}

/// Authenticated plaintext that zeroizes its allocation on drop.
pub struct OpenedJournalPayload(Zeroizing<Vec<u8>>);

impl fmt::Debug for OpenedJournalPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedJournalPayload([REDACTED])")
    }
}

impl OpenedJournalPayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Journal ciphertext and the nonce that must be stored beside it.
pub struct SealedJournalPayload {
    nonce: [u8; NONCE_LEN],
    ciphertext_and_tag: Vec<u8>,
}

impl fmt::Debug for SealedJournalPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedJournalPayload([REDACTED])")
    }
}

impl SealedJournalPayload {
    /// Returns the standalone GCM nonce.
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Returns the ciphertext followed by its 16-byte GCM tag.
    pub fn ciphertext_and_tag(&self) -> &[u8] {
        &self.ciphertext_and_tag
    }

    /// Consumes the sealed payload into its record-storage components.
    pub fn into_parts(self) -> ([u8; NONCE_LEN], Vec<u8>) {
        (self.nonce, self.ciphertext_and_tag)
    }
}

#[cfg(test)]
impl JournalKey {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn derive_journal_key(transformed_key: &TransformedKey) -> Result<JournalKey> {
    let hkdf = Hkdf::<Sha256>::new(None, transformed_key.expose_secret());
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(HKDF_INFO, key.as_mut_slice())
        .map_err(|_| JournalCryptoError::KeyDerivationFailed)?;
    Ok(JournalKey(key))
}

fn encode_aad(op_id: Uuid, vault_ref_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16_usize.saturating_add(vault_ref_id.len()));
    aad.extend_from_slice(op_id.as_bytes());
    aad.extend_from_slice(vault_ref_id.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quick_unlock::TransformedKey;
    use data_encoding::HEXLOWER;
    use static_assertions::assert_not_impl_any;
    use zeroize::Zeroize;
    use zeroize::Zeroizing;

    assert_not_impl_any!(JournalKey: Clone, serde::Serialize);
    assert_not_impl_any!(JournalCipher: Clone, serde::Serialize);
    assert_not_impl_any!(OpenedJournalPayload: Clone, serde::Serialize);
    assert_not_impl_any!(SealedJournalPayload: serde::Serialize);

    #[test]
    fn derives_pinned_journal_key_without_salt() {
        let transformed_bytes = std::array::from_fn(|index| index as u8);
        let transformed = TransformedKey::new(Zeroizing::new(transformed_bytes));
        let expected: [u8; 32] = HEXLOWER
            .decode(b"c2994cc090d3e04c62dc4cf77f5197704b0c08fda740ac4e10f4328ba1af03a7")
            .unwrap()
            .try_into()
            .unwrap();

        let key = derive_journal_key(&transformed).unwrap();

        assert_eq!(key.as_bytes(), &expected);
    }

    #[test]
    fn aad_is_exact_uuid_bytes_followed_by_vault_ref_utf8() {
        let op_id = uuid::Uuid::parse_str("0190a8f0-5b6c-7d8e-9fab-0123456789ab").unwrap();
        let expected = HEXLOWER
            .decode(b"0190a8f05b6c7d8e9fab0123456789ab7661756c742d7265662dceb1")
            .unwrap();

        assert_eq!(encode_aad(op_id, "vault-ref-\u{03b1}"), expected);
    }

    #[test]
    fn fixed_nonce_seal_matches_pinned_ciphertext_vector() {
        let transformed_bytes = std::array::from_fn(|index| index as u8);
        let transformed = TransformedKey::new(Zeroizing::new(transformed_bytes));
        let cipher = JournalCipher::new(&transformed).unwrap();
        let op_id = uuid::Uuid::parse_str("0190a8f0-5b6c-7d8e-9fab-0123456789ab").unwrap();
        let nonce: [u8; 12] = HEXLOWER
            .decode(b"a0a1a2a3a4a5a6a7a8a9aaab")
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = HEXLOWER
            .decode(b"00ff106f70617175652d7061796c6f61640080")
            .unwrap();
        let expected = HEXLOWER
            .decode(b"21005527952b4d3f848ee860681f25e0087a121aafbea23405510258f65914ad70ad8c")
            .unwrap();

        let sealed = cipher
            .seal_with_nonce_for_test(&plaintext, op_id, "vault-ref-\u{03b1}", nonce)
            .unwrap();

        assert_eq!(sealed.nonce(), &nonce);
        assert_eq!(sealed.ciphertext_and_tag(), expected);
    }

    #[test]
    fn fixed_nonce_seal_and_open_round_trip_opaque_bytes() {
        let transformed = TransformedKey::new(Zeroizing::new([0x42; 32]));
        let cipher = JournalCipher::new(&transformed).unwrap();
        let op_id = uuid::Uuid::parse_str("0190a8f0-5b6c-7d8e-9fab-0123456789ab").unwrap();
        let vault_ref_id = "journal-vault";
        let nonce = [0x24; NONCE_LEN];
        let plaintext = [0x00, 0xff, 0x80, 0x7f, 0x01, 0xfe];
        let sealed = cipher
            .seal_with_nonce_for_test(&plaintext, op_id, vault_ref_id, nonce)
            .unwrap();

        let opened = cipher
            .open(
                op_id,
                vault_ref_id,
                sealed.nonce(),
                sealed.ciphertext_and_tag(),
            )
            .unwrap();

        assert_eq!(opened.as_bytes(), plaintext);
    }

    #[test]
    fn production_seal_uses_fresh_nonce_and_ciphertext() {
        let transformed = TransformedKey::new(Zeroizing::new([0x5a; 32]));
        let cipher = JournalCipher::new(&transformed).unwrap();
        let op_id = uuid::Uuid::parse_str("0190a8f0-5b6c-7d8e-9fab-0123456789ab").unwrap();

        let first = cipher.seal(b"same payload", op_id, "same-vault").unwrap();
        let second = cipher.seal(b"same payload", op_id, "same-vault").unwrap();

        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.ciphertext_and_tag(), second.ciphertext_and_tag());
    }

    #[test]
    fn every_binding_nonce_ciphertext_and_tag_change_fails_authentication() {
        let transformed = TransformedKey::new(Zeroizing::new([0x6b; 32]));
        let cipher = JournalCipher::new(&transformed).unwrap();
        let op_id = uuid::Uuid::parse_str("0190a8f0-5b6c-7d8e-9fab-0123456789ab").unwrap();
        let vault_ref_id = "bound-vault";
        let sealed = cipher
            .seal_with_nonce_for_test(b"bound secret", op_id, vault_ref_id, [0x39; NONCE_LEN])
            .unwrap();

        let mut changed_op_id = *op_id.as_bytes();
        changed_op_id[0] ^= 1;
        assert_eq!(
            cipher
                .open(
                    Uuid::from_bytes(changed_op_id),
                    vault_ref_id,
                    sealed.nonce(),
                    sealed.ciphertext_and_tag(),
                )
                .err(),
            Some(JournalCryptoError::AuthenticationFailed)
        );
        assert_eq!(
            cipher
                .open(
                    op_id,
                    "bound-vaule",
                    sealed.nonce(),
                    sealed.ciphertext_and_tag(),
                )
                .err(),
            Some(JournalCryptoError::AuthenticationFailed)
        );

        let mut changed_nonce = *sealed.nonce();
        changed_nonce[0] ^= 1;
        assert_eq!(
            cipher
                .open(
                    op_id,
                    vault_ref_id,
                    &changed_nonce,
                    sealed.ciphertext_and_tag(),
                )
                .err(),
            Some(JournalCryptoError::AuthenticationFailed)
        );

        let mut changed_ciphertext = sealed.ciphertext_and_tag().to_vec();
        changed_ciphertext[0] ^= 1;
        assert_eq!(
            cipher
                .open(op_id, vault_ref_id, sealed.nonce(), &changed_ciphertext)
                .err(),
            Some(JournalCryptoError::AuthenticationFailed)
        );

        let mut changed_tag = sealed.ciphertext_and_tag().to_vec();
        let last = changed_tag.len() - 1;
        changed_tag[last] ^= 1;
        assert_eq!(
            cipher
                .open(op_id, vault_ref_id, sealed.nonce(), &changed_tag)
                .err(),
            Some(JournalCryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn malformed_and_truncated_ciphertext_fails_closed() {
        let transformed = TransformedKey::new(Zeroizing::new([0x7c; 32]));
        let cipher = JournalCipher::new(&transformed).unwrap();
        let op_id = uuid::Uuid::parse_str("0190a8f0-5b6c-7d8e-9fab-0123456789ab").unwrap();
        let nonce = [0x4a; NONCE_LEN];
        let sealed = cipher
            .seal_with_nonce_for_test(b"payload", op_id, "vault", nonce)
            .unwrap();

        for malformed in [
            &[][..],
            &[0_u8; TAG_LEN - 1][..],
            &sealed.ciphertext_and_tag()[..sealed.ciphertext_and_tag().len() - 1],
        ] {
            assert_eq!(
                cipher.open(op_id, "vault", &nonce, malformed).err(),
                Some(JournalCryptoError::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn secret_carriers_zeroize_and_all_debug_output_is_redacted() {
        let transformed = TransformedKey::new(Zeroizing::new([0x8d; 32]));
        let mut derived_key = derive_journal_key(&transformed).unwrap();
        let cipher = JournalCipher::new(&transformed).unwrap();
        let op_id = uuid::Uuid::parse_str("0190a8f0-5b6c-7d8e-9fab-0123456789ab").unwrap();
        let sealed = cipher
            .seal_with_nonce_for_test(
                b"journal-test-secret",
                op_id,
                "secret-vault-ref",
                [0x5b; NONCE_LEN],
            )
            .unwrap();
        let mut opened = cipher
            .open(
                op_id,
                "secret-vault-ref",
                sealed.nonce(),
                sealed.ciphertext_and_tag(),
            )
            .unwrap();
        let ciphertext_hex = HEXLOWER.encode(sealed.ciphertext_and_tag());
        let rendered = format!("{derived_key:?} {cipher:?} {sealed:?} {opened:?}");

        assert!(!rendered.contains("journal-test-secret"));
        assert!(!rendered.contains("secret-vault-ref"));
        assert!(!rendered.contains(&ciphertext_hex));
        assert!(rendered.matches("[REDACTED]").count() >= 4);
        assert!(std::mem::needs_drop::<JournalKey>());
        assert!(std::mem::needs_drop::<JournalCipher>());
        assert!(std::mem::needs_drop::<OpenedJournalPayload>());

        derived_key.0.zeroize();
        opened.0.zeroize();
        assert_eq!(derived_key.as_bytes(), &[0_u8; 32]);
        assert!(opened.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn sealed_payload_consumes_into_separate_nonce_and_ciphertext() {
        let transformed = TransformedKey::new(Zeroizing::new([0x9e; 32]));
        let cipher = JournalCipher::new(&transformed).unwrap();
        let op_id = uuid::Uuid::parse_str("0190a8f0-5b6c-7d8e-9fab-0123456789ab").unwrap();
        let nonce = [0x6c; NONCE_LEN];
        let sealed = cipher
            .seal_with_nonce_for_test(b"opaque", op_id, "vault", nonce)
            .unwrap();
        let expected_ciphertext = sealed.ciphertext_and_tag().to_vec();

        let (actual_nonce, actual_ciphertext) = sealed.into_parts();

        assert_eq!(actual_nonce, nonce);
        assert_eq!(actual_ciphertext, expected_ciphertext);
    }

    #[test]
    fn authentication_errors_do_not_include_payload_or_ciphertext() {
        let transformed = TransformedKey::new(Zeroizing::new([0xaf; 32]));
        let cipher = JournalCipher::new(&transformed).unwrap();
        let op_id = uuid::Uuid::parse_str("0190a8f0-5b6c-7d8e-9fab-0123456789ab").unwrap();
        let secret = b"error-leak-marker";
        let sealed = cipher
            .seal_with_nonce_for_test(secret, op_id, "vault", [0x7d; NONCE_LEN])
            .unwrap();
        let ciphertext_hex = HEXLOWER.encode(sealed.ciphertext_and_tag());
        let error = cipher
            .open(
                op_id,
                "wrong-vault",
                sealed.nonce(),
                sealed.ciphertext_and_tag(),
            )
            .err()
            .unwrap();
        let rendered = format!("{error:?} {error}");

        assert_eq!(error, JournalCryptoError::AuthenticationFailed);
        assert!(!rendered.contains("error-leak-marker"));
        assert!(!rendered.contains(&ciphertext_hex));
        assert!(!rendered.contains("wrong-vault"));
    }

    #[test]
    fn public_api_accepts_only_transformed_key_and_opaque_payload_material() {
        type OpenFn =
            fn(&JournalCipher, Uuid, &str, &[u8; NONCE_LEN], &[u8]) -> Result<OpenedJournalPayload>;

        let _derive: fn(&TransformedKey) -> Result<JournalCipher> = JournalCipher::new;
        let _seal: fn(&JournalCipher, &[u8], Uuid, &str) -> Result<SealedJournalPayload> =
            JournalCipher::seal;
        let _open: OpenFn = JournalCipher::open;
    }

    #[test]
    fn crypto_boundary_does_not_interpret_uuid_version_or_empty_payload() {
        let transformed = TransformedKey::new(Zeroizing::new([0xb0; 32]));
        let cipher = JournalCipher::new(&transformed).unwrap();
        let non_v7_op_id = Uuid::nil();
        let sealed = cipher.seal(b"", non_v7_op_id, "vault").unwrap();

        assert_eq!(sealed.ciphertext_and_tag().len(), TAG_LEN);
        assert_eq!(
            cipher
                .open(
                    non_v7_op_id,
                    "vault",
                    sealed.nonce(),
                    sealed.ciphertext_and_tag(),
                )
                .unwrap()
                .as_bytes(),
            b""
        );
    }
}
