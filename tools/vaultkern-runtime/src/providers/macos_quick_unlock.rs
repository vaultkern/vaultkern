use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use p256::PublicKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::macos_local_authentication::{MacLocalAuthentication, MacLocalAuthenticationApi};
use super::quick_unlock::QuickUnlockProvider;
use crate::macos_secure_enclave::{
    self, BridgeError, BridgeErrorKind, CreatedKeyMaterial, Secret32, SensitiveBytes,
    WrappingKeyMaterial,
};

const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_SCHEME: &str =
    "macos-secure-enclave-p256-ecdh-hkdf-sha256-aes-256-gcm-keychain-acl-v1";
const AAD_MAGIC: &[u8] = b"VaultKern Quick Unlock\0";
const KDF_SALT_LENGTH: usize = 32;
const AES_KEY_LENGTH: usize = 32;
const AES_NONCE_LENGTH: usize = 12;
const AES_TAG_LENGTH: usize = 16;
const CRYPTOKIT_P256_RAW_PUBLIC_KEY_LENGTH: usize = 64;

#[derive(Clone, Copy)]
#[repr(u8)]
enum AadPurpose {
    KdfSharedInfo = 1,
    WrappedDek = 2,
    Credentials = 3,
}

#[derive(Deserialize)]
struct EnvelopeHeader {
    version: u8,
    scheme: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEnvelopeV1 {
    version: u8,
    scheme: String,
    secure_enclave_key: String,
    peer_public_key: String,
    kdf_salt: String,
    wrapped_dek_nonce: String,
    wrapped_dek: String,
    credentials_nonce: String,
    credentials_ciphertext: String,
}

impl Drop for StoredEnvelopeV1 {
    fn drop(&mut self) {
        self.secure_enclave_key.zeroize();
        self.peer_public_key.zeroize();
        self.kdf_salt.zeroize();
        self.wrapped_dek_nonce.zeroize();
        self.wrapped_dek.zeroize();
        self.credentials_nonce.zeroize();
        self.credentials_ciphertext.zeroize();
    }
}

struct DecodedEnvelopeV1 {
    secure_enclave_key: SensitiveBytes,
    peer_public_key: Vec<u8>,
    kdf_salt: [u8; KDF_SALT_LENGTH],
    wrapped_dek_nonce: [u8; AES_NONCE_LENGTH],
    wrapped_dek: Vec<u8>,
    credentials_nonce: [u8; AES_NONCE_LENGTH],
    credentials_ciphertext: Vec<u8>,
}

#[derive(Debug)]
enum EnvelopeDecodeError {
    Unsupported,
    Corrupt(String),
}

trait MacSecureEnclaveApi {
    fn is_available(&self) -> bool;

    fn create(
        &self,
        salt: &[u8],
        shared_info: &[u8],
        reason: &str,
    ) -> std::result::Result<CreatedKeyMaterial, BridgeError>;

    fn derive_for_refresh(
        &self,
        private_key: &[u8],
        salt: &[u8],
        shared_info: &[u8],
    ) -> std::result::Result<WrappingKeyMaterial, BridgeError>;

    fn restore_and_derive(
        &self,
        private_key: &[u8],
        peer_public_key: &[u8],
        salt: &[u8],
        shared_info: &[u8],
        reason: &str,
    ) -> std::result::Result<Secret32, BridgeError>;
}

struct SystemSecureEnclave;

impl MacSecureEnclaveApi for SystemSecureEnclave {
    fn is_available(&self) -> bool {
        macos_secure_enclave::is_secure_enclave_available()
    }

    fn create(
        &self,
        salt: &[u8],
        shared_info: &[u8],
        reason: &str,
    ) -> std::result::Result<CreatedKeyMaterial, BridgeError> {
        macos_secure_enclave::create_key_material(salt, shared_info, reason)
    }

    fn derive_for_refresh(
        &self,
        private_key: &[u8],
        salt: &[u8],
        shared_info: &[u8],
    ) -> std::result::Result<WrappingKeyMaterial, BridgeError> {
        macos_secure_enclave::derive_key_material_for_refresh(private_key, salt, shared_info)
    }

    fn restore_and_derive(
        &self,
        private_key: &[u8],
        peer_public_key: &[u8],
        salt: &[u8],
        shared_info: &[u8],
        reason: &str,
    ) -> std::result::Result<Secret32, BridgeError> {
        macos_secure_enclave::restore_and_derive_kek(
            private_key,
            peer_public_key,
            salt,
            shared_info,
            reason,
        )
    }
}

trait MacQuickUnlockRecordStore {
    fn contains(&self, record_id: &str) -> std::result::Result<bool, BridgeError>;
    fn load(&self, record_id: &str) -> std::result::Result<SensitiveBytes, BridgeError>;
    fn store(&self, record_id: &str, bytes: &[u8]) -> std::result::Result<(), BridgeError>;
    fn delete(&self, record_id: &str) -> std::result::Result<(), BridgeError>;
}

struct SystemQuickUnlockRecordStore;

impl MacQuickUnlockRecordStore for SystemQuickUnlockRecordStore {
    fn contains(&self, record_id: &str) -> std::result::Result<bool, BridgeError> {
        macos_secure_enclave::quick_unlock_record_exists(record_id)
    }

    fn load(&self, record_id: &str) -> std::result::Result<SensitiveBytes, BridgeError> {
        macos_secure_enclave::load_quick_unlock_record(record_id)
    }

    fn store(&self, record_id: &str, bytes: &[u8]) -> std::result::Result<(), BridgeError> {
        macos_secure_enclave::store_quick_unlock_record(record_id, bytes)
    }

    fn delete(&self, record_id: &str) -> std::result::Result<(), BridgeError> {
        macos_secure_enclave::delete_quick_unlock_record(record_id)
    }
}

trait EntropySource {
    fn fill(&self, output: &mut [u8]) -> Result<()>;
}

struct SystemEntropy;

impl EntropySource for SystemEntropy {
    fn fill(&self, output: &mut [u8]) -> Result<()> {
        OsRng
            .try_fill_bytes(output)
            .map_err(|error| anyhow::anyhow!("failed to generate Quick Unlock randomness: {error}"))
    }
}

pub(crate) struct MacOsQuickUnlockProvider {
    local_authentication: Box<dyn MacLocalAuthenticationApi>,
    secure_enclave: Box<dyn MacSecureEnclaveApi>,
    records: Box<dyn MacQuickUnlockRecordStore>,
    entropy: Box<dyn EntropySource>,
    identifier_scope: String,
}

impl MacOsQuickUnlockProvider {
    pub(crate) fn new_default() -> Self {
        Self::new(
            Box::new(MacLocalAuthentication),
            Box::new(SystemSecureEnclave),
            Box::new(SystemQuickUnlockRecordStore),
            Box::new(SystemEntropy),
            None,
        )
    }

    pub(crate) fn new_for_extension_id(extension_id: &str) -> Self {
        Self::new(
            Box::new(MacLocalAuthentication),
            Box::new(SystemSecureEnclave),
            Box::new(SystemQuickUnlockRecordStore),
            Box::new(SystemEntropy),
            Some(extension_id),
        )
    }

    fn new(
        local_authentication: Box<dyn MacLocalAuthenticationApi>,
        secure_enclave: Box<dyn MacSecureEnclaveApi>,
        records: Box<dyn MacQuickUnlockRecordStore>,
        entropy: Box<dyn EntropySource>,
        extension_id: Option<&str>,
    ) -> Self {
        Self {
            local_authentication,
            secure_enclave,
            records,
            entropy,
            identifier_scope: identifier_scope(extension_id),
        }
    }

    fn backend_identifier(&self, key: &str) -> String {
        format!(
            "com.vaultkern.quick-unlock.v1:{}:{key}",
            self.identifier_scope
        )
    }

    fn context_bytes(&self, key: &str, purpose: AadPurpose) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(
            AAD_MAGIC.len() + ENVELOPE_SCHEME.len() + self.identifier_scope.len() + key.len() + 16,
        );
        output.extend_from_slice(AAD_MAGIC);
        output.push(ENVELOPE_VERSION);
        output.push(purpose as u8);
        for field in [
            ENVELOPE_SCHEME.as_bytes(),
            self.identifier_scope.as_bytes(),
            key.as_bytes(),
        ] {
            output.extend_from_slice(
                &u32::try_from(field.len())
                    .context("Quick Unlock context field is too large")?
                    .to_be_bytes(),
            );
            output.extend_from_slice(field);
        }
        Ok(output)
    }

    fn random_array<const N: usize>(&self) -> Result<[u8; N]> {
        let mut output = [0_u8; N];
        self.entropy.fill(&mut output)?;
        Ok(output)
    }

    fn seal_record(
        &self,
        key: &str,
        value: &[u8],
        private_key: &[u8],
        peer_public_key: &[u8],
        salt: &[u8; KDF_SALT_LENGTH],
        kek: &Secret32,
    ) -> Result<Zeroizing<Vec<u8>>> {
        validate_cryptokit_public_key(peer_public_key)
            .map_err(|error| anyhow::anyhow!("Secure Enclave returned {error}"))?;
        let data_key = Zeroizing::new(self.random_array::<AES_KEY_LENGTH>()?);
        let wrapped_dek_nonce = self.random_array::<AES_NONCE_LENGTH>()?;
        let credentials_nonce = self.random_array::<AES_NONCE_LENGTH>()?;
        let wrapped_dek = aes_encrypt(
            kek.expose(),
            &wrapped_dek_nonce,
            data_key.as_ref(),
            &self.context_bytes(key, AadPurpose::WrappedDek)?,
        )
        .context("failed to wrap the macOS Quick Unlock data key")?;
        let credentials_ciphertext = aes_encrypt(
            &data_key,
            &credentials_nonce,
            value,
            &self.context_bytes(key, AadPurpose::Credentials)?,
        )
        .context("failed to encrypt macOS Quick Unlock credentials")?;
        let envelope = StoredEnvelopeV1 {
            version: ENVELOPE_VERSION,
            scheme: ENVELOPE_SCHEME.into(),
            secure_enclave_key: BASE64_STANDARD.encode(private_key),
            peer_public_key: BASE64_STANDARD.encode(peer_public_key),
            kdf_salt: BASE64_STANDARD.encode(salt),
            wrapped_dek_nonce: BASE64_STANDARD.encode(wrapped_dek_nonce),
            wrapped_dek: BASE64_STANDARD.encode(wrapped_dek),
            credentials_nonce: BASE64_STANDARD.encode(credentials_nonce),
            credentials_ciphertext: BASE64_STANDARD.encode(credentials_ciphertext),
        };
        Ok(Zeroizing::new(serde_json::to_vec(&envelope).context(
            "failed to encode the macOS Quick Unlock envelope",
        )?))
    }

    fn delete_if_present(&self, identifier: &str) -> Result<()> {
        match self.records.delete(identifier) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == BridgeErrorKind::MissingItem => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn unusable_record_error(&self, identifier: &str, primary: anyhow::Error) -> anyhow::Error {
        match self.delete_if_present(identifier) {
            Ok(()) => primary,
            Err(cleanup) => primary.context(format!(
                "additionally failed to delete the unusable Quick Unlock record: {cleanup:#}"
            )),
        }
    }

    fn parse_record(&self, identifier: &str, bytes: &[u8]) -> Result<DecodedEnvelopeV1> {
        match decode_envelope(bytes) {
            Ok(envelope) => Ok(envelope),
            Err(EnvelopeDecodeError::Unsupported) => {
                anyhow::bail!("macOS Quick Unlock credentials use an unsupported envelope")
            }
            Err(EnvelopeDecodeError::Corrupt(detail)) => {
                Err(self.unusable_record_error(identifier, anyhow::anyhow!(detail)))
            }
        }
    }

    fn load_record(&self, identifier: &str) -> Result<Option<DecodedEnvelopeV1>> {
        let record = match self.records.load(identifier) {
            Ok(record) => record,
            Err(error) if error.kind() == BridgeErrorKind::MissingItem => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        self.parse_record(identifier, record.expose()).map(Some)
    }

    fn map_key_operation_error(&self, identifier: &str, error: BridgeError) -> anyhow::Error {
        if error.kind() == BridgeErrorKind::KeyInvalidated {
            self.unusable_record_error(identifier, error.into())
        } else {
            error.into()
        }
    }

    fn open_record(
        &self,
        identifier: &str,
        key: &str,
        envelope: &DecodedEnvelopeV1,
        kek: &Secret32,
    ) -> Result<Vec<u8>> {
        let wrapped_data_key = match aes_decrypt(
            kek.expose(),
            &envelope.wrapped_dek_nonce,
            &envelope.wrapped_dek,
            &self.context_bytes(key, AadPurpose::WrappedDek)?,
        ) {
            Ok(value) => Zeroizing::new(value),
            Err(()) => {
                return Err(self.unusable_record_error(
                    identifier,
                    anyhow::anyhow!(
                        "macOS Quick Unlock envelope failed wrapped-key authentication"
                    ),
                ));
            }
        };
        if wrapped_data_key.len() != AES_KEY_LENGTH {
            return Err(self.unusable_record_error(
                identifier,
                anyhow::anyhow!("macOS Quick Unlock envelope contains an invalid data key"),
            ));
        }
        let mut data_key = Zeroizing::new([0_u8; AES_KEY_LENGTH]);
        data_key.copy_from_slice(&wrapped_data_key);
        aes_decrypt(
            &data_key,
            &envelope.credentials_nonce,
            &envelope.credentials_ciphertext,
            &self.context_bytes(key, AadPurpose::Credentials)?,
        )
        .map_err(|()| {
            self.unusable_record_error(
                identifier,
                anyhow::anyhow!("macOS Quick Unlock envelope failed credential authentication"),
            )
        })
    }
}

fn identifier_scope(extension_id: Option<&str>) -> String {
    let Some(extension_id) = extension_id else {
        return "default".into();
    };
    let digest = Sha256::digest(extension_id.as_bytes());
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("extension-{digest}")
}

fn aes_encrypt(
    key: &[u8; AES_KEY_LENGTH],
    nonce: &[u8; AES_NONCE_LENGTH],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("failed to initialize AES-256-GCM"))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("AES-256-GCM encryption failed"))
}

fn aes_decrypt(
    key: &[u8; AES_KEY_LENGTH],
    nonce: &[u8; AES_NONCE_LENGTH],
    ciphertext: &[u8],
    aad: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ())
}

fn decode_base64(field: &str, label: &str) -> std::result::Result<Vec<u8>, EnvelopeDecodeError> {
    BASE64_STANDARD.decode(field).map_err(|_| {
        EnvelopeDecodeError::Corrupt(format!(
            "macOS Quick Unlock envelope contains invalid Base64 for {label}"
        ))
    })
}

fn decode_fixed<const N: usize>(
    field: &str,
    label: &str,
) -> std::result::Result<[u8; N], EnvelopeDecodeError> {
    let bytes = decode_base64(field, label)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        EnvelopeDecodeError::Corrupt(format!(
            "macOS Quick Unlock envelope has {} bytes for {label}; expected {N}",
            bytes.len()
        ))
    })
}

fn validate_cryptokit_public_key(raw_public_key: &[u8]) -> std::result::Result<(), &'static str> {
    let raw: [u8; CRYPTOKIT_P256_RAW_PUBLIC_KEY_LENGTH] = raw_public_key
        .try_into()
        .map_err(|_| "an invalid 64-byte P-256 peer public key")?;
    let mut sec1 = [0_u8; CRYPTOKIT_P256_RAW_PUBLIC_KEY_LENGTH + 1];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(&raw);
    PublicKey::from_sec1_bytes(&sec1)
        .map(|_| ())
        .map_err(|_| "an invalid P-256 peer public key")
}

fn decode_envelope(bytes: &[u8]) -> std::result::Result<DecodedEnvelopeV1, EnvelopeDecodeError> {
    let header: EnvelopeHeader = serde_json::from_slice(bytes).map_err(|error| {
        EnvelopeDecodeError::Corrupt(format!(
            "failed to decode the macOS Quick Unlock envelope header: {error}"
        ))
    })?;
    if header.version != ENVELOPE_VERSION || header.scheme != ENVELOPE_SCHEME {
        return Err(EnvelopeDecodeError::Unsupported);
    }
    let envelope: StoredEnvelopeV1 = serde_json::from_slice(bytes).map_err(|error| {
        EnvelopeDecodeError::Corrupt(format!(
            "failed to decode the macOS Quick Unlock V1 envelope: {error}"
        ))
    })?;
    let private_key = decode_base64(&envelope.secure_enclave_key, "Secure Enclave key")?;
    if private_key.is_empty() {
        return Err(EnvelopeDecodeError::Corrupt(
            "macOS Quick Unlock envelope has an empty Secure Enclave key".into(),
        ));
    }
    let private_key = SensitiveBytes::new(private_key);
    let peer_public_key = decode_base64(&envelope.peer_public_key, "peer public key")?;
    validate_cryptokit_public_key(&peer_public_key).map_err(|error| {
        EnvelopeDecodeError::Corrupt(format!("macOS Quick Unlock envelope has {error}"))
    })?;
    let kdf_salt = decode_fixed(&envelope.kdf_salt, "KDF salt")?;
    let wrapped_dek_nonce = decode_fixed(&envelope.wrapped_dek_nonce, "wrapped-key nonce")?;
    let wrapped_dek = decode_base64(&envelope.wrapped_dek, "wrapped data key")?;
    if wrapped_dek.len() != AES_KEY_LENGTH + AES_TAG_LENGTH {
        return Err(EnvelopeDecodeError::Corrupt(format!(
            "macOS Quick Unlock envelope has {} wrapped-key bytes; expected {}",
            wrapped_dek.len(),
            AES_KEY_LENGTH + AES_TAG_LENGTH
        )));
    }
    let credentials_nonce = decode_fixed(&envelope.credentials_nonce, "credential nonce")?;
    let credentials_ciphertext =
        decode_base64(&envelope.credentials_ciphertext, "credential ciphertext")?;
    if credentials_ciphertext.len() < AES_TAG_LENGTH {
        return Err(EnvelopeDecodeError::Corrupt(
            "macOS Quick Unlock credential ciphertext is shorter than its authentication tag"
                .into(),
        ));
    }
    Ok(DecodedEnvelopeV1 {
        secure_enclave_key: private_key,
        peer_public_key,
        kdf_salt,
        wrapped_dek_nonce,
        wrapped_dek,
        credentials_nonce,
        credentials_ciphertext,
    })
}

impl QuickUnlockProvider for MacOsQuickUnlockProvider {
    fn is_supported(&self) -> bool {
        self.local_authentication.is_touch_id_available() && self.secure_enclave.is_available()
    }

    fn contains(&self, key: &str) -> Result<bool> {
        self.records
            .contains(&self.backend_identifier(key))
            .map_err(Into::into)
    }

    fn enable(&self, key: &str, value: &[u8], reason: &str) -> Result<()> {
        let identifier = self.backend_identifier(key);
        let salt = self.random_array::<KDF_SALT_LENGTH>()?;
        let shared_info = self.context_bytes(key, AadPurpose::KdfSharedInfo)?;
        let material = self
            .secure_enclave
            .create(&salt, &shared_info, reason)
            .map_err(anyhow::Error::from)?;
        let record = self.seal_record(
            key,
            value,
            material.private_key(),
            material.peer_public_key(),
            &salt,
            material.kek(),
        )?;
        self.records.store(&identifier, &record).map_err(Into::into)
    }

    fn unlock(&self, key: &str, reason: &str) -> Result<Option<Vec<u8>>> {
        let identifier = self.backend_identifier(key);
        let Some(envelope) = self.load_record(&identifier)? else {
            return Ok(None);
        };
        let shared_info = self.context_bytes(key, AadPurpose::KdfSharedInfo)?;
        let kek = self
            .secure_enclave
            .restore_and_derive(
                envelope.secure_enclave_key.expose(),
                &envelope.peer_public_key,
                &envelope.kdf_salt,
                &shared_info,
                reason,
            )
            .map_err(|error| self.map_key_operation_error(&identifier, error))?;
        self.open_record(&identifier, key, &envelope, &kek)
            .map(Some)
    }

    fn refresh(&self, key: &str, value: &[u8]) -> Result<()> {
        let identifier = self.backend_identifier(key);
        let Some(envelope) = self.load_record(&identifier)? else {
            return Ok(());
        };
        let salt = self.random_array::<KDF_SALT_LENGTH>()?;
        let shared_info = self.context_bytes(key, AadPurpose::KdfSharedInfo)?;
        let material = self
            .secure_enclave
            .derive_for_refresh(envelope.secure_enclave_key.expose(), &salt, &shared_info)
            .map_err(|error| self.map_key_operation_error(&identifier, error))?;
        let record = self.seal_record(
            key,
            value,
            envelope.secure_enclave_key.expose(),
            material.peer_public_key(),
            &salt,
            material.kek(),
        )?;
        self.records.store(&identifier, &record).map_err(Into::into)
    }

    fn verify_user(&self, reason: &str) -> Result<()> {
        self.local_authentication.authorize(reason)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.delete_if_present(&self.backend_identifier(key))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use anyhow::Result;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    use super::{
        AadPurpose, ENVELOPE_SCHEME, EntropySource, MacOsQuickUnlockProvider,
        MacQuickUnlockRecordStore, MacSecureEnclaveApi,
    };
    use crate::macos_secure_enclave::{
        BridgeError, BridgeErrorKind, CreatedKeyMaterial, Secret32, SensitiveBytes,
        WrappingKeyMaterial,
    };
    use crate::providers::macos_local_authentication::MacLocalAuthenticationApi;
    use crate::providers::quick_unlock::QuickUnlockProvider;

    #[derive(Default)]
    struct FakeState {
        available: bool,
        secure_enclave_available: bool,
        operations: Vec<String>,
        records: BTreeMap<String, Vec<u8>>,
        create_error: Option<BridgeErrorKind>,
        refresh_error: Option<BridgeErrorKind>,
        restore_error: Option<BridgeErrorKind>,
        store_error: bool,
        delete_error: bool,
        peer_counter: u8,
        entropy_counter: u8,
    }

    struct FakeLocalAuthentication {
        state: Rc<RefCell<FakeState>>,
    }

    impl MacLocalAuthenticationApi for FakeLocalAuthentication {
        fn is_touch_id_available(&self) -> bool {
            let mut state = self.state.borrow_mut();
            state.operations.push("touch_id_available".into());
            state.available
        }

        fn authorize(&self, reason: &str) -> Result<()> {
            self.state
                .borrow_mut()
                .operations
                .push(format!("authorize:{reason}"));
            Ok(())
        }
    }

    struct FakeSecureEnclave {
        state: Rc<RefCell<FakeState>>,
    }

    fn fake_kek(
        private_key: &[u8],
        peer_public_key: &[u8],
        salt: &[u8],
        shared_info: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for field in [private_key, peer_public_key, salt, shared_info] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        hasher.finalize().into()
    }

    fn valid_raw_public_key(counter: u8) -> Vec<u8> {
        let mut scalar = [0_u8; 32];
        scalar[31] = counter.max(1);
        let secret = p256::SecretKey::from_slice(&scalar).unwrap();
        secret.public_key().to_encoded_point(false).as_bytes()[1..].to_vec()
    }

    impl FakeSecureEnclave {
        fn next_peer(&self) -> Vec<u8> {
            let mut state = self.state.borrow_mut();
            state.peer_counter = state.peer_counter.wrapping_add(1).max(1);
            valid_raw_public_key(state.peer_counter)
        }

        fn configured_error(
            kind: Option<BridgeErrorKind>,
            operation: &str,
        ) -> std::result::Result<(), BridgeError> {
            match kind {
                Some(kind) => Err(BridgeError::for_test(kind, format!("injected {operation}"))),
                None => Ok(()),
            }
        }
    }

    impl MacSecureEnclaveApi for FakeSecureEnclave {
        fn is_available(&self) -> bool {
            let mut state = self.state.borrow_mut();
            state.operations.push("secure_enclave_available".into());
            state.secure_enclave_available
        }

        fn create(
            &self,
            salt: &[u8],
            shared_info: &[u8],
            reason: &str,
        ) -> std::result::Result<CreatedKeyMaterial, BridgeError> {
            let error = {
                let mut state = self.state.borrow_mut();
                state.operations.push(format!("create:{reason}"));
                state.create_error
            };
            Self::configured_error(error, "create")?;
            let private_key = b"opaque-secure-enclave-key".to_vec();
            let peer_public_key = self.next_peer();
            let kek = fake_kek(&private_key, &peer_public_key, salt, shared_info);
            Ok(CreatedKeyMaterial::for_test(
                private_key,
                peer_public_key,
                kek,
            ))
        }

        fn derive_for_refresh(
            &self,
            private_key: &[u8],
            salt: &[u8],
            shared_info: &[u8],
        ) -> std::result::Result<WrappingKeyMaterial, BridgeError> {
            let error = {
                let mut state = self.state.borrow_mut();
                state.operations.push("derive_for_refresh".into());
                state.refresh_error
            };
            Self::configured_error(error, "refresh")?;
            let peer_public_key = self.next_peer();
            let kek = fake_kek(private_key, &peer_public_key, salt, shared_info);
            Ok(WrappingKeyMaterial::for_test(peer_public_key, kek))
        }

        fn restore_and_derive(
            &self,
            private_key: &[u8],
            peer_public_key: &[u8],
            salt: &[u8],
            shared_info: &[u8],
            reason: &str,
        ) -> std::result::Result<Secret32, BridgeError> {
            let error = {
                let mut state = self.state.borrow_mut();
                state.operations.push(format!("restore:{reason}"));
                state.restore_error
            };
            Self::configured_error(error, "restore")?;
            Ok(Secret32::for_test(fake_kek(
                private_key,
                peer_public_key,
                salt,
                shared_info,
            )))
        }
    }

    struct FakeRecordStore {
        state: Rc<RefCell<FakeState>>,
    }

    impl MacQuickUnlockRecordStore for FakeRecordStore {
        fn contains(&self, record_id: &str) -> std::result::Result<bool, BridgeError> {
            let mut state = self.state.borrow_mut();
            state.operations.push(format!("contains:{record_id}"));
            Ok(state.records.contains_key(record_id))
        }

        fn load(&self, record_id: &str) -> std::result::Result<SensitiveBytes, BridgeError> {
            let mut state = self.state.borrow_mut();
            state.operations.push(format!("load:{record_id}"));
            state
                .records
                .get(record_id)
                .cloned()
                .map(SensitiveBytes::new)
                .ok_or_else(|| {
                    BridgeError::for_test(BridgeErrorKind::MissingItem, "record missing")
                })
        }

        fn store(&self, record_id: &str, bytes: &[u8]) -> std::result::Result<(), BridgeError> {
            let mut state = self.state.borrow_mut();
            state.operations.push(format!("store:{record_id}"));
            if state.store_error {
                return Err(BridgeError::for_test(
                    BridgeErrorKind::PlatformFailure,
                    "injected store failure",
                ));
            }
            state.records.insert(record_id.into(), bytes.to_vec());
            Ok(())
        }

        fn delete(&self, record_id: &str) -> std::result::Result<(), BridgeError> {
            let mut state = self.state.borrow_mut();
            state.operations.push(format!("delete:{record_id}"));
            if state.delete_error {
                return Err(BridgeError::for_test(
                    BridgeErrorKind::PlatformFailure,
                    "injected delete failure",
                ));
            }
            if state.records.remove(record_id).is_some() {
                Ok(())
            } else {
                Err(BridgeError::for_test(
                    BridgeErrorKind::MissingItem,
                    "record missing",
                ))
            }
        }
    }

    struct FakeEntropy {
        state: Rc<RefCell<FakeState>>,
    }

    impl EntropySource for FakeEntropy {
        fn fill(&self, output: &mut [u8]) -> Result<()> {
            let mut state = self.state.borrow_mut();
            state.entropy_counter = state.entropy_counter.wrapping_add(1);
            let seed = state.entropy_counter;
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = seed.wrapping_add(index as u8);
            }
            Ok(())
        }
    }

    fn provider_for_extension(
        state: Rc<RefCell<FakeState>>,
        extension_id: Option<&str>,
    ) -> MacOsQuickUnlockProvider {
        MacOsQuickUnlockProvider::new(
            Box::new(FakeLocalAuthentication {
                state: state.clone(),
            }),
            Box::new(FakeSecureEnclave {
                state: state.clone(),
            }),
            Box::new(FakeRecordStore {
                state: state.clone(),
            }),
            Box::new(FakeEntropy { state }),
            extension_id,
        )
    }

    fn provider() -> (MacOsQuickUnlockProvider, Rc<RefCell<FakeState>>) {
        let state = Rc::new(RefCell::new(FakeState {
            available: true,
            secure_enclave_available: true,
            ..FakeState::default()
        }));
        (provider_for_extension(state.clone(), None), state)
    }

    fn record_bytes(
        provider: &MacOsQuickUnlockProvider,
        state: &Rc<RefCell<FakeState>>,
        key: &str,
    ) -> Vec<u8> {
        state
            .borrow()
            .records
            .get(&provider.backend_identifier(key))
            .unwrap()
            .clone()
    }

    #[test]
    fn enable_stores_v1_envelope_without_plaintext_and_unlock_roundtrips() {
        let (provider, state) = provider();

        provider
            .enable("vault", b"plain-secret", "Enable quick unlock")
            .unwrap();

        let record = record_bytes(&provider, &state, "vault");
        assert!(
            !record
                .windows(b"plain-secret".len())
                .any(|bytes| bytes == b"plain-secret")
        );
        let value: Value = serde_json::from_slice(&record).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["scheme"], ENVELOPE_SCHEME);
        assert_eq!(
            BASE64_STANDARD
                .decode(value["peer_public_key"].as_str().unwrap())
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            provider.unlock("vault", "Unlock this vault").unwrap(),
            Some(b"plain-secret".to_vec())
        );
    }

    #[test]
    fn support_requires_both_strict_touch_id_and_secure_enclave() {
        let (provider, state) = provider();
        assert!(provider.is_supported());

        state.borrow_mut().available = false;
        assert!(!provider.is_supported());
        state.borrow_mut().available = true;
        state.borrow_mut().secure_enclave_available = false;
        assert!(!provider.is_supported());
    }

    #[test]
    fn contains_checks_only_the_keychain_presence_marker() {
        let (provider, state) = provider();
        provider.enable("vault", b"secret", "Enable").unwrap();
        state.borrow_mut().operations.clear();

        assert!(provider.contains("vault").unwrap());
        assert_eq!(state.borrow().operations.len(), 1);
        assert!(state.borrow().operations[0].starts_with("contains:"));
    }

    #[test]
    fn cancelled_enable_and_failed_store_preserve_the_old_record() {
        for fail_store in [false, true] {
            let (provider, state) = provider();
            provider.enable("vault", b"old", "Enable").unwrap();
            let old = record_bytes(&provider, &state, "vault");
            if fail_store {
                state.borrow_mut().store_error = true;
            } else {
                state.borrow_mut().create_error = Some(BridgeErrorKind::AuthenticationFailed);
            }

            assert!(provider.enable("vault", b"new", "Enable").is_err());
            assert_eq!(record_bytes(&provider, &state, "vault"), old);
            assert!(
                !state
                    .borrow()
                    .operations
                    .iter()
                    .any(|op| op.starts_with("delete:"))
            );
        }
    }

    #[test]
    fn refresh_uses_only_public_side_derivation_and_replaces_credentials() {
        let (provider, state) = provider();
        provider.enable("vault", b"old", "Enable").unwrap();
        let old: Value = serde_json::from_slice(&record_bytes(&provider, &state, "vault")).unwrap();
        state.borrow_mut().operations.clear();

        provider.refresh("vault", b"new").unwrap();

        let operations = state.borrow().operations.clone();
        assert!(operations.iter().any(|op| op == "derive_for_refresh"));
        assert!(!operations.iter().any(|op| op.starts_with("restore:")));
        assert!(!operations.iter().any(|op| op.starts_with("authorize:")));
        let new: Value = serde_json::from_slice(&record_bytes(&provider, &state, "vault")).unwrap();
        for field in [
            "peer_public_key",
            "kdf_salt",
            "wrapped_dek_nonce",
            "credentials_nonce",
        ] {
            assert_ne!(old[field], new[field], "{field} must be fresh");
        }
        assert_eq!(
            provider.unlock("vault", "Unlock").unwrap(),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn missing_unlock_and_refresh_are_noninteractive_noops() {
        let (provider, state) = provider();

        assert_eq!(provider.unlock("vault", "Unlock").unwrap(), None);
        provider.refresh("vault", b"new").unwrap();

        assert!(state.borrow().operations.iter().all(|operation| {
            operation.starts_with("load:")
                && !operation.starts_with("restore:")
                && operation != "derive_for_refresh"
        }));
    }

    #[test]
    fn malformed_v1_is_deleted_but_future_envelopes_are_retained() {
        for (record, should_delete) in [
            (br#"{"version":1,"scheme":"macos-secure-enclave-p256-ecdh-hkdf-sha256-aes-256-gcm-keychain-acl-v1"}"#.to_vec(), true),
            (br#"{"version":2,"scheme":"future"}"#.to_vec(), false),
            (br#"{"version":1,"scheme":"future"}"#.to_vec(), false),
        ] {
            let (provider, state) = provider();
            let identifier = provider.backend_identifier("vault");
            state.borrow_mut().records.insert(identifier.clone(), record);

            assert!(provider.unlock("vault", "Unlock").is_err());
            assert_eq!(state.borrow().records.contains_key(&identifier), !should_delete);
        }
    }

    #[test]
    fn invalid_cryptokit_raw_public_key_is_rejected_before_touch_id() {
        let (provider, state) = provider();
        provider.enable("vault", b"secret", "Enable").unwrap();
        let identifier = provider.backend_identifier("vault");
        let mut value: Value =
            serde_json::from_slice(&record_bytes(&provider, &state, "vault")).unwrap();
        value["peer_public_key"] = Value::String(BASE64_STANDARD.encode([0_u8; 64]));
        state
            .borrow_mut()
            .records
            .insert(identifier.clone(), serde_json::to_vec(&value).unwrap());
        state.borrow_mut().operations.clear();

        assert!(provider.unlock("vault", "Unlock").is_err());
        assert!(!state.borrow().records.contains_key(&identifier));
        assert!(
            !state
                .borrow()
                .operations
                .iter()
                .any(|op| op.starts_with("restore:"))
        );
    }

    #[test]
    fn authentication_and_platform_failures_retain_the_record() {
        for kind in [
            BridgeErrorKind::AuthenticationFailed,
            BridgeErrorKind::InteractionUnavailable,
            BridgeErrorKind::PlatformFailure,
        ] {
            let (provider, state) = provider();
            provider.enable("vault", b"secret", "Enable").unwrap();
            let identifier = provider.backend_identifier("vault");
            state.borrow_mut().restore_error = Some(kind);

            assert!(provider.unlock("vault", "Unlock").is_err());
            assert!(state.borrow().records.contains_key(&identifier));
        }
    }

    #[test]
    fn confirmed_key_invalidation_deletes_without_masking_the_primary_error() {
        let (provider, state) = provider();
        provider.enable("vault", b"secret", "Enable").unwrap();
        let identifier = provider.backend_identifier("vault");
        {
            let mut state = state.borrow_mut();
            state.restore_error = Some(BridgeErrorKind::KeyInvalidated);
            state.delete_error = true;
        }

        let error = provider.unlock("vault", "Unlock").unwrap_err();

        assert!(format!("{error:#}").contains("injected restore"));
        assert!(format!("{error:#}").contains("failed to delete"));
        assert!(state.borrow().records.contains_key(&identifier));
    }

    #[test]
    fn ciphertext_tampering_is_deleted_after_touch_id() {
        let (provider, state) = provider();
        provider.enable("vault", b"secret", "Enable").unwrap();
        let identifier = provider.backend_identifier("vault");
        let mut value: Value =
            serde_json::from_slice(&record_bytes(&provider, &state, "vault")).unwrap();
        let mut ciphertext = BASE64_STANDARD
            .decode(value["credentials_ciphertext"].as_str().unwrap())
            .unwrap();
        ciphertext[0] ^= 0x80;
        value["credentials_ciphertext"] = Value::String(BASE64_STANDARD.encode(ciphertext));
        state
            .borrow_mut()
            .records
            .insert(identifier.clone(), serde_json::to_vec(&value).unwrap());

        assert!(provider.unlock("vault", "Unlock").is_err());
        assert!(!state.borrow().records.contains_key(&identifier));
    }

    #[test]
    fn every_authenticated_envelope_component_rejects_same_length_tampering() {
        for field in [
            "secure_enclave_key",
            "peer_public_key",
            "kdf_salt",
            "wrapped_dek_nonce",
            "wrapped_dek",
            "credentials_nonce",
            "credentials_ciphertext",
        ] {
            let (provider, state) = provider();
            provider.enable("vault", b"secret", "Enable").unwrap();
            let identifier = provider.backend_identifier("vault");
            let mut value: Value =
                serde_json::from_slice(&record_bytes(&provider, &state, "vault")).unwrap();
            let replacement = if field == "peer_public_key" {
                valid_raw_public_key(99)
            } else {
                let mut bytes = BASE64_STANDARD
                    .decode(value[field].as_str().unwrap())
                    .unwrap();
                bytes[0] ^= 0x40;
                bytes
            };
            value[field] = Value::String(BASE64_STANDARD.encode(replacement));
            state
                .borrow_mut()
                .records
                .insert(identifier.clone(), serde_json::to_vec(&value).unwrap());

            assert!(provider.unlock("vault", "Unlock").is_err(), "{field}");
            assert!(
                !state.borrow().records.contains_key(&identifier),
                "{field} tampering must delete the unusable record"
            );
        }
    }

    #[test]
    fn swapping_an_envelope_across_extension_scopes_fails_aad_authentication() {
        let state = Rc::new(RefCell::new(FakeState {
            available: true,
            secure_enclave_available: true,
            ..FakeState::default()
        }));
        let first = provider_for_extension(state.clone(), Some("extension-a"));
        let second = provider_for_extension(state.clone(), Some("extension-b"));
        first.enable("vault", b"secret", "Enable").unwrap();
        let source = record_bytes(&first, &state, "vault");
        let target_identifier = second.backend_identifier("vault");
        state
            .borrow_mut()
            .records
            .insert(target_identifier.clone(), source);

        assert!(second.unlock("vault", "Unlock").is_err());
        assert!(!state.borrow().records.contains_key(&target_identifier));
        assert!(
            state
                .borrow()
                .records
                .contains_key(&first.backend_identifier("vault"))
        );
    }

    #[test]
    fn refresh_transient_failure_does_not_delete_the_existing_record() {
        let (provider, state) = provider();
        provider.enable("vault", b"old", "Enable").unwrap();
        let identifier = provider.backend_identifier("vault");
        state.borrow_mut().refresh_error = Some(BridgeErrorKind::InteractionUnavailable);

        assert!(provider.refresh("vault", b"new").is_err());
        assert!(state.borrow().records.contains_key(&identifier));
        assert!(
            !state
                .borrow()
                .operations
                .iter()
                .any(|op| op.starts_with("delete:"))
        );
    }

    #[test]
    fn context_is_length_prefixed_and_domain_separated() {
        let (provider, _state) = provider();
        let kdf = provider
            .context_bytes("vault", AadPurpose::KdfSharedInfo)
            .unwrap();
        let wrap = provider
            .context_bytes("vault", AadPurpose::WrappedDek)
            .unwrap();
        let credentials = provider
            .context_bytes("vault", AadPurpose::Credentials)
            .unwrap();
        assert_ne!(kdf, wrap);
        assert_ne!(wrap, credentials);
        assert_ne!(
            kdf,
            provider
                .context_bytes("other-vault", AadPurpose::KdfSharedInfo)
                .unwrap()
        );
        assert!(
            kdf.windows(ENVELOPE_SCHEME.len())
                .any(|bytes| bytes == ENVELOPE_SCHEME.as_bytes())
        );
    }

    #[test]
    fn verify_user_remains_a_single_transient_touch_id_operation() {
        let (provider, state) = provider();

        provider.verify_user("Verify user for passkey").unwrap();

        assert_eq!(
            state.borrow().operations,
            ["authorize:Verify user for passkey"]
        );
    }

    #[test]
    fn delete_is_idempotent_for_a_missing_record() {
        let (provider, _state) = provider();
        provider.delete("vault").unwrap();
        provider.delete("vault").unwrap();
    }
}
