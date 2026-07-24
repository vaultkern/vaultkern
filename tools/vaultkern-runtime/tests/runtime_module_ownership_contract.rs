//! Architecture contract for the resident persistence boundary.
//!
//! Behavioral contracts live at the Runtime Protocol seam. This small source-level
//! contract prevents the final ownership boundary from silently collapsing back
//! into the public Runtime façade.

const RUNTIME_SOURCE: &str = include_str!("../src/runtime.rs");
const RUNTIME_API_SOURCE: &str = include_str!("../src/runtime_api.rs");
const RUNTIME_DISPATCH_SOURCE: &str = include_str!("../src/runtime_dispatch.rs");
const VAULT_CORE_SOURCE: &str = include_str!("../src/vault_core.rs");
const PROVIDER_SOURCE: &str = include_str!("../src/providers/provider.rs");
const PROVIDER_CATALOG_SOURCE: &str = include_str!("../src/providers/catalog.rs");
const LOCAL_FILE_PROVIDER_SOURCE: &str = include_str!("../src/providers/local_file.rs");
const ONEDRIVE_PROVIDER_SOURCE: &str = include_str!("../src/providers/onedrive.rs");
const VAULT_FORMAT_SOURCE: &str = include_str!("../src/vault_format.rs");
const VAULT_CODEC_SOURCE: &str = include_str!("../../../crates/vaultkern-core/src/vault_codec.rs");
const WEB_CLIENT_SOURCE: &str = include_str!("../../../packages/runtime-web-client/src/index.ts");
const UNIFFI_SOURCE: &str = include_str!("../../../crates/vaultkern-uniffi/src/lib.rs");

#[test]
fn runtime_is_a_protocol_dispatch_and_composition_facade() {
    assert!(
        RUNTIME_SOURCE.lines().count() < 300,
        "Runtime must stay a small façade; vault behavior belongs to VaultCore"
    );
    assert!(RUNTIME_SOURCE.contains("vault_core: VaultCore"));
    assert!(RUNTIME_SOURCE.contains("runtime_dispatch::dispatch(&mut self.vault_core, command)"));
    assert!(RUNTIME_DISPATCH_SOURCE.contains("pub(crate) fn dispatch("));
    assert!(RUNTIME_DISPATCH_SOURCE.contains("match command"));
    assert!(
        RUNTIME_API_SOURCE.contains("impl Runtime"),
        "platform APIs must cross an explicit Runtime port"
    );
    assert!(
        !RUNTIME_SOURCE.contains("impl std::ops::Deref"),
        "Runtime must not expose VaultCore through Deref"
    );

    for leaked_behavior in [
        "fn save_onedrive_vault",
        "fn commit_entry_mutation",
        "fn reconcile",
        "fn preserve_source_refresh_conflict",
        "fn retry_pending_remote_vault_sync",
        "fn completed_conflict_split",
    ] {
        assert!(
            !RUNTIME_SOURCE.contains(leaked_behavior),
            "Runtime owns vault behavior again: {leaked_behavior}"
        );
    }
}

#[test]
fn vault_core_owns_the_working_copy_lifecycle_behind_abstract_seams() {
    for owned_behavior in [
        "pub struct VaultCore",
        "fn commit_entry_mutation",
        "fn save_onedrive_vault",
        "fn completed_conflict_split",
        "fn retry_pending_remote_vault_sync",
    ] {
        assert!(
            VAULT_CORE_SOURCE.contains(owned_behavior),
            "VaultCore is missing lifecycle behavior: {owned_behavior}"
        );
    }

    assert!(
        VAULT_CORE_SOURCE.contains("VaultCodec"),
        "VaultCore must encode and decode through the Vault Codec seam"
    );
    assert!(
        VAULT_CORE_SOURCE.contains("Provider"),
        "VaultCore must publish through the Provider seam"
    );

    let production_core = VAULT_CORE_SOURCE
        .split_once("#[cfg(test)]\nmod tests")
        .map_or(VAULT_CORE_SOURCE, |(production, _)| production);
    for concrete_mechanic in [
        "LocalFileVaultSourceProvider",
        "OneDriveVaultSourceProvider",
        "OneDriveProvider",
        "OneDriveRemoteState",
        "KdbxVaultCodec",
        "KdbxError",
        "SaveProfile",
        "TransformedKey",
    ] {
        assert!(
            !production_core.contains(concrete_mechanic),
            "VaultCore bypasses an abstract seam through {concrete_mechanic}"
        );
    }

    assert!(PROVIDER_CATALOG_SOURCE.contains("impl Provider"));
    assert!(PROVIDER_CATALOG_SOURCE.contains("LocalFileVaultSourceProvider"));
    assert!(PROVIDER_CATALOG_SOURCE.contains("OneDriveVaultSourceProvider"));
    assert!(VAULT_FORMAT_SOURCE.contains("impl VaultCodec"));
    assert!(VAULT_FORMAT_SOURCE.contains("KdbxVaultCodec"));
}

#[test]
fn provider_and_codec_boundaries_cannot_learn_each_others_domain() {
    for (name, source) in [
        ("Provider contract", PROVIDER_SOURCE),
        ("Provider catalog", PROVIDER_CATALOG_SOURCE),
        ("Local File provider", LOCAL_FILE_PROVIDER_SOURCE),
        ("OneDrive provider", ONEDRIVE_PROVIDER_SOURCE),
    ] {
        for forbidden in ["KeepassCore", "VaultCodec", "KdbxVaultCodec", "EntryCreate"] {
            assert!(
                !source.contains(forbidden),
                "{name} interprets Vault Model or format mechanics through {forbidden}"
            );
        }
    }

    for forbidden in ["providers::", "ProviderSnapshot", "ProviderRevision"] {
        assert!(
            !VAULT_CODEC_SOURCE.contains(forbidden),
            "Vault Codec performs Provider access through {forbidden}"
        );
        assert!(
            !VAULT_FORMAT_SOURCE.contains(forbidden),
            "resident Vault Codec selection performs Provider access through {forbidden}"
        );
    }
}

#[test]
fn superseded_direct_save_entry_points_are_gone() {
    assert!(
        !VAULT_CORE_SOURCE.contains("pub fn retry_vault_publication"),
        "VaultCore must expose Commit and Publication, not a legacy direct-save operation"
    );
    assert!(
        !WEB_CLIENT_SOURCE.contains("async saveVault("),
        "web clients must not retain a mutation-plus-save orchestration primitive"
    );
    assert!(
        !UNIFFI_SOURCE.contains(".retry_vault_publication("),
        "platform façades must dispatch the Runtime Protocol instead of bypassing it"
    );
}
