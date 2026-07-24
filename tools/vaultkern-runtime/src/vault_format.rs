//! Resident selection of the Vault Codec implementation.
//!
//! VaultCore talks to this format-neutral composition seam. KDBX-specific codec
//! selection and delegation stay here, and this module never performs Provider
//! access.

use vaultkern_core::{
    CompositeKey, EncodedVault, ExternalKdfConfirmation, KdbxError, KdbxLoadDiagnostic,
    KdbxVaultCodec, KdfPolicyEvaluator, SaveProfile, TransformedKey, VAULTKERN_KDBX_GENERATOR,
    Vault, VaultCodec,
};

pub(crate) type VaultCodecError = KdbxError;
pub(crate) const VAULT_WRITER_ID: &str = VAULTKERN_KDBX_GENERATOR;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ResidentVaultCodec;

impl VaultCodec for ResidentVaultCodec {
    type Key = TransformedKey;
    type EncodingOptions = SaveProfile;
    type Error = VaultCodecError;

    fn decode(&self, bytes: &[u8], key: &Self::Key) -> Result<Vault, Self::Error> {
        KdbxVaultCodec.decode(bytes, key)
    }

    fn encode(
        &self,
        vault: Vault,
        key: &Self::Key,
        options: Self::EncodingOptions,
    ) -> Result<EncodedVault, Self::Error> {
        KdbxVaultCodec.encode(vault, key, options)
    }
}

impl ResidentVaultCodec {
    pub(crate) fn decode_diagnostic(
        &self,
        bytes: &[u8],
        key: &TransformedKey,
    ) -> Result<Vault, KdbxLoadDiagnostic> {
        KdbxVaultCodec.decode_diagnostic(bytes, key)
    }

    pub(crate) fn derive_key_with_policy(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
        policy: &dyn KdfPolicyEvaluator,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<TransformedKey, VaultCodecError> {
        KdbxVaultCodec.derive_key_with_policy(bytes, composite_key, policy, confirmation)
    }
}
