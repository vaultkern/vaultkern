use anyhow::{Context, Result};
use vaultkern_core::{
    CompositeKey, ExternalKdfConfirmation, ExternalKdfPolicy, KdbxError, TransformedKey, Vault,
    derive_transformed_key_with_policy, load_kdbx_with_transformed_key,
};
use zeroize::Zeroizing;

use crate::providers::secure_storage::{SecureStorageProvider, is_secure_storage_cancelled};

const UNLOCK_BLOB_MAGIC: &[u8; 8] = b"VKUBLOB1";
const PASSWORD_PRESENT: u8 = 1;
const KEY_FILE_PRESENT: u8 = 2;
const MAX_PASSWORD_BYTES: usize = 1024 * 1024;

pub(crate) struct MasterCredential {
    password: Option<Zeroizing<Vec<u8>>>,
    key_file_contribution: Option<Zeroizing<[u8; 32]>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MasterCredentialShape {
    pub(crate) has_password: bool,
    pub(crate) has_key_file: bool,
}

impl MasterCredential {
    pub(crate) fn new(
        password: Option<&[u8]>,
        key_file_contribution: Option<[u8; 32]>,
    ) -> Result<Self> {
        if password.is_none() && key_file_contribution.is_none() {
            anyhow::bail!("master credential has no components");
        }
        if password.is_some_and(|password| password.len() > MAX_PASSWORD_BYTES) {
            anyhow::bail!("master credential password is too large");
        }
        Ok(Self {
            password: password.map(|password| Zeroizing::new(password.to_vec())),
            key_file_contribution: key_file_contribution.map(Zeroizing::new),
        })
    }

    pub(crate) fn to_composite_key(&self) -> CompositeKey {
        let mut key = CompositeKey::default();
        if let Some(password) = &self.password {
            key.add_password_bytes(password.as_slice());
        }
        if let Some(key_file_contribution) = &self.key_file_contribution {
            key.add_key_file(**key_file_contribution);
        }
        key
    }

    pub(crate) fn shape(&self) -> MasterCredentialShape {
        MasterCredentialShape {
            has_password: self.password.is_some(),
            has_key_file: self.key_file_contribution.is_some(),
        }
    }
}

pub(crate) struct UnlockBlob {
    master_credential: MasterCredential,
    cached_transformed_key: TransformedKey,
}

impl UnlockBlob {
    pub(crate) fn new(
        master_credential: MasterCredential,
        cached_transformed_key: TransformedKey,
    ) -> Self {
        Self {
            master_credential,
            cached_transformed_key,
        }
    }

    pub(crate) fn master_credential(&self) -> &MasterCredential {
        &self.master_credential
    }

    pub(crate) fn cached_transformed_key(&self) -> &TransformedKey {
        &self.cached_transformed_key
    }

    fn into_parts(self) -> (MasterCredential, TransformedKey) {
        (self.master_credential, self.cached_transformed_key)
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        Self::encode_parts(&self.master_credential, &self.cached_transformed_key)
    }

    fn encode_parts(
        master_credential: &MasterCredential,
        cached_transformed_key: &TransformedKey,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut flags = 0;
        if master_credential.password.is_some() {
            flags |= PASSWORD_PRESENT;
        }
        if master_credential.key_file_contribution.is_some() {
            flags |= KEY_FILE_PRESENT;
        }
        let password = master_credential
            .password
            .as_ref()
            .map_or(&[][..], |password| password.as_slice());
        let password_len = u32::try_from(password.len()).context("password is too large")?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            UNLOCK_BLOB_MAGIC.len() + 1 + 4 + password.len() + 32 + 32,
        ));
        bytes.extend_from_slice(UNLOCK_BLOB_MAGIC);
        bytes.push(flags);
        bytes.extend_from_slice(&password_len.to_le_bytes());
        bytes.extend_from_slice(password);
        if let Some(contribution) = &master_credential.key_file_contribution {
            bytes.extend_from_slice(contribution.as_ref());
        }
        bytes.extend_from_slice(cached_transformed_key.as_bytes());
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PASSWORD_BYTES + 8 + 1 + 4 + 32 + 32 {
            anyhow::bail!("unlock blob is too large");
        }
        let mut cursor = 0;
        let magic = take(bytes, &mut cursor, UNLOCK_BLOB_MAGIC.len())?;
        if magic != UNLOCK_BLOB_MAGIC {
            anyhow::bail!("unlock blob has an unsupported format");
        }
        let flags = *take(bytes, &mut cursor, 1)?
            .first()
            .context("unlock blob is truncated")?;
        if flags & !(PASSWORD_PRESENT | KEY_FILE_PRESENT) != 0 {
            anyhow::bail!("unlock blob has unsupported flags");
        }
        let password_len = u32::from_le_bytes(
            take(bytes, &mut cursor, 4)?
                .try_into()
                .context("unlock blob password length is truncated")?,
        ) as usize;
        if flags & PASSWORD_PRESENT == 0 && password_len != 0 {
            anyhow::bail!("unlock blob password flag is inconsistent");
        }
        let password = take(bytes, &mut cursor, password_len)?;
        let key_file_contribution = if flags & KEY_FILE_PRESENT != 0 {
            Some(
                take(bytes, &mut cursor, 32)?
                    .try_into()
                    .context("unlock blob key-file contribution is truncated")?,
            )
        } else {
            None
        };
        let transformed = take(bytes, &mut cursor, 32)?
            .try_into()
            .context("unlock blob transformed key is truncated")?;
        if cursor != bytes.len() {
            anyhow::bail!("unlock blob has trailing bytes");
        }
        let password = (flags & PASSWORD_PRESENT != 0).then_some(password);
        Ok(Self::new(
            MasterCredential::new(password, key_file_contribution)?,
            TransformedKey::from_bytes(transformed),
        ))
    }
}

pub(crate) struct UnlockedVault {
    pub(crate) vault: Vault,
    pub(crate) transformed_key: TransformedKey,
    pub(crate) credential_shape: MasterCredentialShape,
    #[cfg(test)]
    pub(crate) cache_refreshed: bool,
}

pub(crate) enum UnlockAttempt {
    Unlocked(UnlockedVault),
    NotEnrolled,
    Cancelled,
    OpenAppRequired,
    CredentialRequired,
}

pub(crate) fn enroll_unlock_blob(
    storage: &dyn SecureStorageProvider,
    storage_key: &str,
    master_credential: &MasterCredential,
    transformed_key: &TransformedKey,
) -> Result<()> {
    let encoded = UnlockBlob::encode_parts(master_credential, transformed_key)?;
    storage
        .store(storage_key, &encoded)
        .context("failed to store unlock blob atomically")
}

pub(crate) fn unlock_from_blob(
    storage: &dyn SecureStorageProvider,
    storage_key: &str,
    file_bytes: &[u8],
    allow_kdf: bool,
) -> Result<UnlockAttempt> {
    let encoded = match storage.load(storage_key) {
        Ok(Some(encoded)) => encoded,
        Ok(None) => return Ok(UnlockAttempt::NotEnrolled),
        Err(error) if is_secure_storage_cancelled(&error) => {
            return Ok(UnlockAttempt::Cancelled);
        }
        Err(_) => {
            storage
                .delete(storage_key)
                .context("failed to delete invalidated unlock blob")?;
            return Ok(UnlockAttempt::NotEnrolled);
        }
    };
    if encoded.is_empty() {
        storage
            .delete(storage_key)
            .context("failed to delete malformed unlock blob")?;
        return Ok(UnlockAttempt::NotEnrolled);
    }
    let encoded = Zeroizing::new(encoded);
    let blob = match UnlockBlob::decode(&encoded) {
        Ok(blob) => blob,
        Err(_) => {
            storage
                .delete(storage_key)
                .context("failed to delete malformed unlock blob")?;
            return Ok(UnlockAttempt::NotEnrolled);
        }
    };

    match load_kdbx_with_transformed_key(file_bytes, blob.cached_transformed_key()) {
        Ok(vault) => {
            let credential_shape = blob.master_credential().shape();
            let (_, transformed_key) = blob.into_parts();
            return Ok(UnlockAttempt::Unlocked(UnlockedVault {
                vault,
                transformed_key,
                credential_shape,
                #[cfg(test)]
                cache_refreshed: false,
            }));
        }
        Err(KdbxError::HeaderHmacMismatch) => {}
        Err(error) => return Err(error.into()),
    }

    if !allow_kdf {
        return Ok(UnlockAttempt::OpenAppRequired);
    }

    let refreshed = derive_transformed_key_with_policy(
        file_bytes,
        &blob.master_credential().to_composite_key(),
        &ExternalKdfPolicy::Desktop,
        ExternalKdfConfirmation::Unconfirmed,
    )?;
    let vault = match load_kdbx_with_transformed_key(file_bytes, &refreshed) {
        Ok(vault) => vault,
        Err(KdbxError::HeaderHmacMismatch) => {
            storage
                .delete(storage_key)
                .context("failed to delete stale unlock blob")?;
            return Ok(UnlockAttempt::CredentialRequired);
        }
        Err(error) => return Err(error.into()),
    };

    let (master_credential, _) = blob.into_parts();
    let credential_shape = master_credential.shape();
    let refreshed_blob = UnlockBlob::new(master_credential, refreshed);
    let encoded = refreshed_blob.encode()?;
    storage
        .store(storage_key, &encoded)
        .context("failed to refresh unlock blob atomically")?;
    let (_, transformed_key) = refreshed_blob.into_parts();
    Ok(UnlockAttempt::Unlocked(UnlockedVault {
        vault,
        transformed_key,
        credential_shape,
        #[cfg(test)]
        cache_refreshed: true,
    }))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .context("unlock blob length overflow")?;
    let value = bytes
        .get(*cursor..end)
        .context("unlock blob is truncated")?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        MasterCredential, UnlockAttempt, UnlockBlob, enroll_unlock_blob, unlock_from_blob,
    };
    use crate::providers::secure_storage::{SecureStorageError, SecureStorageProvider};
    use std::cell::{Cell, RefCell};
    use vaultkern_core::{
        CompositeKey, Compression, KdbxCipher, KdbxVersion, SaveKdf, SaveProfile, TransformedKey,
        Vault, derive_transformed_key, save_kdbx_bytes,
    };

    #[derive(Default)]
    struct CountingStore {
        value: RefCell<Option<Vec<u8>>>,
        stores: Cell<usize>,
    }

    #[derive(Clone, Copy)]
    enum LoadFailure {
        None,
        Cancelled,
        Invalidated,
    }

    struct FailingLoadStore {
        value: RefCell<Option<Vec<u8>>>,
        failure: Cell<LoadFailure>,
        deletes: Cell<usize>,
    }

    impl FailingLoadStore {
        fn with_blob(value: Vec<u8>) -> Self {
            Self {
                value: RefCell::new(Some(value)),
                failure: Cell::new(LoadFailure::None),
                deletes: Cell::new(0),
            }
        }
    }

    impl SecureStorageProvider for FailingLoadStore {
        fn store(&self, _key: &str, value: &[u8]) -> anyhow::Result<()> {
            self.value.replace(Some(value.to_vec()));
            Ok(())
        }

        fn load(&self, _key: &str) -> anyhow::Result<Option<Vec<u8>>> {
            match self.failure.get() {
                LoadFailure::None => Ok(self.value.borrow().clone()),
                LoadFailure::Cancelled => {
                    Err(SecureStorageError::cancelled("user cancelled").into())
                }
                LoadFailure::Invalidated => anyhow::bail!("Hello key was invalidated"),
            }
        }

        fn contains(&self, _key: &str) -> anyhow::Result<bool> {
            Ok(self.value.borrow().is_some())
        }

        fn delete(&self, _key: &str) -> anyhow::Result<()> {
            self.deletes.set(self.deletes.get() + 1);
            self.value.replace(None);
            Ok(())
        }
    }

    impl SecureStorageProvider for CountingStore {
        fn store(&self, _key: &str, value: &[u8]) -> anyhow::Result<()> {
            self.stores.set(self.stores.get() + 1);
            self.value.replace(Some(value.to_vec()));
            Ok(())
        }

        fn load(&self, _key: &str) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.value.borrow().clone())
        }

        fn contains(&self, _key: &str) -> anyhow::Result<bool> {
            Ok(self.value.borrow().is_some())
        }

        fn delete(&self, _key: &str) -> anyhow::Result<()> {
            self.value.replace(None);
            Ok(())
        }
    }

    fn fast_profile() -> SaveProfile {
        SaveProfile {
            version: KdbxVersion::V4_1,
            cipher: KdbxCipher::Aes256,
            compression: Compression::None,
            kdf: Some(SaveKdf::AesKdbx4 { rounds: 16 }),
        }
    }

    fn file(name: &str, password: &[u8]) -> Vec<u8> {
        let mut key = CompositeKey::default();
        key.add_password_bytes(password);
        save_kdbx_bytes(&Vault::empty(name), &key, &fast_profile()).unwrap()
    }

    #[test]
    fn one_blob_roundtrips_master_credential_and_cached_transformed_key() {
        let key_file_contribution = [0x5a; 32];
        let master =
            MasterCredential::new(Some("pāssword".as_bytes()), Some(key_file_contribution))
                .unwrap();
        let transformed = TransformedKey::from_bytes([0xa5; 32]);
        let encoded = UnlockBlob::new(master, transformed).encode().unwrap();

        let decoded = UnlockBlob::decode(&encoded).unwrap();
        assert_eq!(decoded.cached_transformed_key().as_bytes(), &[0xa5; 32]);

        let mut expected = CompositeKey::default();
        expected.add_password_bytes("pāssword".as_bytes());
        expected.add_key_file(key_file_contribution);
        assert_eq!(
            decoded
                .master_credential()
                .to_composite_key()
                .raw_key()
                .unwrap(),
            expected.raw_key().unwrap()
        );
    }

    #[test]
    fn app_unlock_hits_cache_then_refreshes_once_after_a_salt_change() {
        let password = b"refresh password";
        let first = file("first", password);
        let second = file("second", password);
        let master = MasterCredential::new(Some(password), None).unwrap();
        let transformed = derive_transformed_key(&first, &master.to_composite_key()).unwrap();
        let store = CountingStore::default();

        enroll_unlock_blob(&store, "vault-a", &master, &transformed).unwrap();
        assert_eq!(store.stores.get(), 1);

        let UnlockAttempt::Unlocked(hit) =
            unlock_from_blob(&store, "vault-a", &first, true).unwrap()
        else {
            panic!("expected cached unlock");
        };
        assert_eq!(hit.vault.name, "first");
        assert!(!hit.cache_refreshed);
        assert_eq!(store.stores.get(), 1);

        let UnlockAttempt::Unlocked(refreshed) =
            unlock_from_blob(&store, "vault-a", &second, true).unwrap()
        else {
            panic!("expected refreshed unlock");
        };
        assert_eq!(refreshed.vault.name, "second");
        assert!(refreshed.cache_refreshed);
        assert_eq!(store.stores.get(), 2);

        let UnlockAttempt::Unlocked(warm) =
            unlock_from_blob(&store, "vault-a", &second, true).unwrap()
        else {
            panic!("expected warm refreshed unlock");
        };
        assert!(!warm.cache_refreshed);
        assert_eq!(store.stores.get(), 2);
    }

    #[test]
    fn extension_cache_miss_never_runs_kdf_or_rewrites_the_blob() {
        let password = b"extension password";
        let first = file("first", password);
        let second = file("second", password);
        let master = MasterCredential::new(Some(password), None).unwrap();
        let transformed = derive_transformed_key(&first, &master.to_composite_key()).unwrap();
        let store = CountingStore::default();
        enroll_unlock_blob(&store, "vault-a", &master, &transformed).unwrap();

        assert!(matches!(
            unlock_from_blob(&store, "vault-a", &second, false).unwrap(),
            UnlockAttempt::OpenAppRequired
        ));
        assert_eq!(store.stores.get(), 1);

        assert!(matches!(
            unlock_from_blob(&store, "vault-a", &first, false).unwrap(),
            UnlockAttempt::Unlocked(_)
        ));
        assert_eq!(store.stores.get(), 1);
    }

    #[test]
    fn stale_master_credential_deletes_the_blob_for_reenrollment() {
        let original_password = b"original password";
        let original = file("original", original_password);
        let replacement = file("replacement", b"replacement password");
        let master = MasterCredential::new(Some(original_password), None).unwrap();
        let transformed = derive_transformed_key(&original, &master.to_composite_key()).unwrap();
        let store = CountingStore::default();
        enroll_unlock_blob(&store, "vault-a", &master, &transformed).unwrap();

        assert!(matches!(
            unlock_from_blob(&store, "vault-a", &replacement, true).unwrap(),
            UnlockAttempt::CredentialRequired
        ));
        assert!(store.value.borrow().is_none());
    }

    #[test]
    fn cancellation_preserves_the_blob_but_invalidation_deletes_it() {
        let password = b"state password";
        let bytes = file("state", password);
        let master = MasterCredential::new(Some(password), None).unwrap();
        let transformed = derive_transformed_key(&bytes, &master.to_composite_key()).unwrap();
        let encoded = UnlockBlob::new(master, transformed).encode().unwrap();
        let store = FailingLoadStore::with_blob(encoded.to_vec());

        store.failure.set(LoadFailure::Cancelled);
        assert!(matches!(
            unlock_from_blob(&store, "vault-a", &bytes, true).unwrap(),
            UnlockAttempt::Cancelled
        ));
        assert_eq!(store.deletes.get(), 0);
        assert!(store.value.borrow().is_some());

        store.failure.set(LoadFailure::Invalidated);
        assert!(matches!(
            unlock_from_blob(&store, "vault-a", &bytes, true).unwrap(),
            UnlockAttempt::NotEnrolled
        ));
        assert_eq!(store.deletes.get(), 1);
        assert!(store.value.borrow().is_none());
    }
}
