//! Resident selection of the vault format implementation.
//!
//! This is the only runtime module that knows which on-disk format is resident.
//! Callers work with format-neutral keys, encoding profiles, and errors. Provider
//! identity, revisions, retries, and publication state never cross this seam.

use std::fmt;

use vaultkern_core::{
    CompositeKey, EncodedVault, ExternalKdfAlgorithm, ExternalKdfConfirmation, ExternalKdfDecision,
    KdbxCipher, KdbxError, KdbxLoadDiagnostic, KdbxVaultCodec, KdbxVersion, KdfPolicyEvaluator,
    KeepassCore, SaveKdf, SaveProfile, TransformedKey, VAULTKERN_KDBX_GENERATOR, Vault, VaultCodec,
    retained_or_recommended_save_kdf,
};
use zeroize::Zeroizing;

pub(crate) const VAULT_WRITER_ID: &str = VAULTKERN_KDBX_GENERATOR;

/// A format-owned session key. The runtime can persist it in protected memory,
/// but cannot depend on the concrete key representation used by the resident
/// codec.
pub(crate) struct VaultKey(TransformedKey);

impl VaultKey {
    pub(crate) fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(TransformedKey::from_zeroizing(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Format-neutral settings the runtime may expose to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultEncryptionSettings {
    pub(crate) compression: VaultCompression,
    pub(crate) cipher: VaultCipher,
    pub(crate) kdf: VaultKdf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultCompression {
    None,
    Gzip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultCipher {
    Aes256,
    ChaCha20,
    Twofish,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VaultKdf {
    Aes {
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

/// Opaque encoding choices retained from an opened vault.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VaultEncodingProfile(SaveProfile);

impl fmt::Debug for VaultEncodingProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultEncodingProfile")
    }
}

impl VaultEncodingProfile {
    pub(crate) fn recommended() -> Self {
        Self(SaveProfile::recommended())
    }

    pub(crate) fn inspect(bytes: &[u8]) -> Result<Self, VaultCodecError> {
        let inspection = KeepassCore
            .inspect_database(bytes)
            .map_err(VaultCodecError::from_display)?;
        Ok(Self(SaveProfile {
            version: inspection.save_target_version,
            cipher: inspection.header.cipher,
            compression: inspection.header.compression,
            kdf: None,
        }))
    }

    pub(crate) fn merge(
        base: &Self,
        local: &Self,
        remote: &Self,
    ) -> Result<Self, VaultProfileConflict> {
        let local = local.clone().without_explicit_kdf();
        if &local == base {
            return Ok(remote.clone());
        }
        if remote == base || remote == &local {
            return Ok(local);
        }
        Err(VaultProfileConflict)
    }

    pub(crate) fn without_explicit_kdf(mut self) -> Self {
        self.0.kdf = None;
        self
    }

    pub(crate) fn clear_explicit_kdf(&mut self) {
        self.0.kdf = None;
    }

    pub(crate) fn encryption_settings(
        &self,
        vault: &Vault,
    ) -> Result<VaultEncryptionSettings, VaultCodecError> {
        let kdf = self
            .0
            .kdf
            .clone()
            .map(Ok)
            .unwrap_or_else(|| retained_or_recommended_save_kdf(vault))
            .map_err(VaultCodecError::from)?;
        Ok(VaultEncryptionSettings {
            compression: match self.0.compression {
                vaultkern_core::Compression::None => VaultCompression::None,
                vaultkern_core::Compression::Gzip => VaultCompression::Gzip,
            },
            cipher: match self.0.cipher {
                KdbxCipher::Aes256 => VaultCipher::Aes256,
                KdbxCipher::ChaCha20 => VaultCipher::ChaCha20,
                KdbxCipher::Twofish => VaultCipher::Twofish,
            },
            kdf: match kdf {
                SaveKdf::AesKdbx4 { rounds } => VaultKdf::Aes { rounds },
                SaveKdf::Argon2d {
                    iterations,
                    memory_kib,
                    parallelism,
                } => VaultKdf::Argon2d {
                    iterations,
                    memory_kib,
                    parallelism,
                },
                SaveKdf::Argon2id {
                    iterations,
                    memory_kib,
                    parallelism,
                } => VaultKdf::Argon2id {
                    iterations,
                    memory_kib,
                    parallelism,
                },
            },
        })
    }

    pub(crate) fn from_encryption_settings(settings: VaultEncryptionSettings) -> Self {
        Self(SaveProfile {
            version: KdbxVersion::V4_1,
            cipher: match settings.cipher {
                VaultCipher::Aes256 => KdbxCipher::Aes256,
                VaultCipher::ChaCha20 => KdbxCipher::ChaCha20,
                VaultCipher::Twofish => KdbxCipher::Twofish,
            },
            compression: match settings.compression {
                VaultCompression::None => vaultkern_core::Compression::None,
                VaultCompression::Gzip => vaultkern_core::Compression::Gzip,
            },
            kdf: Some(match settings.kdf {
                VaultKdf::Aes { rounds } => SaveKdf::AesKdbx4 { rounds },
                VaultKdf::Argon2d {
                    iterations,
                    memory_kib,
                    parallelism,
                } => SaveKdf::Argon2d {
                    iterations,
                    memory_kib,
                    parallelism,
                },
                VaultKdf::Argon2id {
                    iterations,
                    memory_kib,
                    parallelism,
                } => SaveKdf::Argon2id {
                    iterations,
                    memory_kib,
                    parallelism,
                },
            }),
        })
    }

    pub(crate) fn apply_encryption_settings(
        current: &Self,
        vault: &Vault,
        settings: VaultEncryptionSettings,
    ) -> Result<Self, VaultCodecError> {
        let mut requested = Self::from_encryption_settings(settings);
        let requested_kdf = requested
            .0
            .kdf
            .take()
            .expect("vault encryption settings always include a KDF");
        let retained = retained_or_recommended_save_kdf(vault).map_err(VaultCodecError::from)?;
        requested.0.kdf =
            (!(current.0.kdf.is_none() && requested_kdf == retained)).then_some(requested_kdf);
        Ok(requested)
    }

    pub(crate) fn uses_retained_kdf(&self, vault: &Vault) -> Result<bool, VaultCodecError> {
        let Some(requested) = self.0.kdf.as_ref() else {
            return Ok(true);
        };
        retained_or_recommended_save_kdf(vault)
            .map(|retained| requested == &retained)
            .map_err(Into::into)
    }

    #[cfg(test)]
    pub(crate) fn from_test_profile(profile: SaveProfile) -> Self {
        Self(profile)
    }

    #[cfg(test)]
    pub(crate) fn set_test_compression(&mut self, compression: VaultCompression) {
        self.0.compression = match compression {
            VaultCompression::None => vaultkern_core::Compression::None,
            VaultCompression::Gzip => vaultkern_core::Compression::Gzip,
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VaultProfileConflict;

impl fmt::Display for VaultProfileConflict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("vault encryption profile changed concurrently")
    }
}

impl std::error::Error for VaultProfileConflict {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultKdfAlgorithm {
    AesLegacy,
    Aes,
    Argon2d,
    Argon2id,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultKdfDecision {
    Allow,
    Confirm(u64),
    Refuse(u64),
    Forbid,
}

fn vault_kdf_algorithm(algorithm: ExternalKdfAlgorithm) -> VaultKdfAlgorithm {
    match algorithm {
        ExternalKdfAlgorithm::AesKdbx3 => VaultKdfAlgorithm::AesLegacy,
        ExternalKdfAlgorithm::AesKdbx4 => VaultKdfAlgorithm::Aes,
        ExternalKdfAlgorithm::Argon2d => VaultKdfAlgorithm::Argon2d,
        ExternalKdfAlgorithm::Argon2id => VaultKdfAlgorithm::Argon2id,
    }
}

fn vault_kdf_decision(decision: ExternalKdfDecision) -> VaultKdfDecision {
    match decision {
        ExternalKdfDecision::Allow => VaultKdfDecision::Allow,
        ExternalKdfDecision::Confirm(limit) => VaultKdfDecision::Confirm(limit),
        ExternalKdfDecision::Refuse(limit) => VaultKdfDecision::Refuse(limit),
        ExternalKdfDecision::Forbid => VaultKdfDecision::Forbid,
    }
}

#[derive(Debug)]
pub(crate) enum VaultCodecError {
    KeyMismatch,
    ExternalKdfPolicy {
        algorithm: VaultKdfAlgorithm,
        observed: u64,
        decision: VaultKdfDecision,
    },
    InvalidFormat(String),
}

impl VaultCodecError {
    fn from_display(error: impl fmt::Display) -> Self {
        Self::InvalidFormat(error.to_string())
    }
}

impl From<KdbxError> for VaultCodecError {
    fn from(error: KdbxError) -> Self {
        match error {
            KdbxError::HeaderHmacMismatch => Self::KeyMismatch,
            KdbxError::ExternalKdfPolicy {
                algorithm,
                observed,
                decision,
            } => Self::ExternalKdfPolicy {
                algorithm: vault_kdf_algorithm(algorithm),
                observed,
                decision: vault_kdf_decision(decision),
            },
            error => Self::InvalidFormat(error.to_string()),
        }
    }
}

pub(crate) fn external_kdf_policy_details(
    cause: &(dyn std::error::Error + 'static),
) -> Option<(VaultKdfAlgorithm, u64, VaultKdfDecision)> {
    if let Some(VaultCodecError::ExternalKdfPolicy {
        algorithm,
        observed,
        decision,
    }) = cause.downcast_ref::<VaultCodecError>()
    {
        return Some((*algorithm, *observed, *decision));
    }
    let KdbxError::ExternalKdfPolicy {
        algorithm,
        observed,
        decision,
    } = cause.downcast_ref::<KdbxError>()?
    else {
        return None;
    };
    Some((
        vault_kdf_algorithm(*algorithm),
        *observed,
        vault_kdf_decision(*decision),
    ))
}

impl fmt::Display for VaultCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyMismatch => formatter.write_str("vault key does not match"),
            Self::ExternalKdfPolicy {
                algorithm,
                observed,
                decision,
            } => write!(
                formatter,
                "external KDF policy {decision:?} for algorithm {algorithm:?} with observed value {observed}"
            ),
            Self::InvalidFormat(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for VaultCodecError {}

#[derive(Debug)]
pub(crate) struct VaultLoadDiagnostic {
    stage: String,
    source: VaultCodecError,
}

impl From<KdbxLoadDiagnostic> for VaultLoadDiagnostic {
    fn from(diagnostic: KdbxLoadDiagnostic) -> Self {
        Self {
            stage: diagnostic.stage.to_string(),
            source: diagnostic.source.into(),
        }
    }
}

impl fmt::Display for VaultLoadDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "vault load failed during {}: {}",
            self.stage, self.source
        )
    }
}

impl std::error::Error for VaultLoadDiagnostic {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ResidentVaultCodec;

impl VaultCodec for ResidentVaultCodec {
    type Key = VaultKey;
    type EncodingOptions = VaultEncodingProfile;
    type Error = VaultCodecError;

    fn decode(&self, bytes: &[u8], key: &Self::Key) -> Result<Vault, Self::Error> {
        KdbxVaultCodec.decode(bytes, &key.0).map_err(Into::into)
    }

    fn encode(
        &self,
        vault: Vault,
        key: &Self::Key,
        options: Self::EncodingOptions,
    ) -> Result<EncodedVault, Self::Error> {
        KdbxVaultCodec
            .encode(vault, &key.0, options.0)
            .map_err(Into::into)
    }
}

impl ResidentVaultCodec {
    pub(crate) fn decode_diagnostic(
        &self,
        bytes: &[u8],
        key: &VaultKey,
    ) -> Result<Vault, VaultLoadDiagnostic> {
        KdbxVaultCodec
            .decode_diagnostic(bytes, &key.0)
            .map_err(Into::into)
    }

    pub(crate) fn derive_key_with_policy(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
        policy: &dyn KdfPolicyEvaluator,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<VaultKey, VaultCodecError> {
        KdbxVaultCodec
            .derive_key_with_policy(bytes, composite_key, policy, confirmation)
            .map(VaultKey)
            .map_err(Into::into)
    }

    pub(crate) fn decode_with_policy(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
        policy: &dyn KdfPolicyEvaluator,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<Vault, VaultCodecError> {
        KdbxVaultCodec
            .decode_with_policy(bytes, composite_key, policy, confirmation)
            .map_err(Into::into)
    }

    pub(crate) fn encode_with_composite_key(
        &self,
        vault: Vault,
        composite_key: &CompositeKey,
        profile: VaultEncodingProfile,
    ) -> Result<EncodedVault, VaultCodecError> {
        KdbxVaultCodec
            .encode_with_composite_key(vault, composite_key, profile.0)
            .map_err(Into::into)
    }

    pub(crate) fn legacy_migration_profile(
        bytes: &[u8],
    ) -> Result<Option<VaultEncodingProfile>, VaultCodecError> {
        let inspection = KeepassCore
            .inspect_database(bytes)
            .map_err(VaultCodecError::from_display)?;
        if !matches!(
            inspection.header.version,
            KdbxVersion::V2_0 | KdbxVersion::V3_0 | KdbxVersion::V3_1
        ) {
            return Ok(None);
        }
        Ok(Some(VaultEncodingProfile(SaveProfile {
            version: inspection.save_target_version,
            cipher: inspection.header.cipher,
            compression: inspection.header.compression,
            kdf: Some(SaveKdf::recommended()),
        })))
    }
}
