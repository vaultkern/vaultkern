#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, KeepassCore, SaveProfile, Vault, VaultIdentityMetadataUpdate,
    VaultIdentityMetadataView, VaultLifecycleMetadataUpdate, VaultLifecycleMetadataView,
};

const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");
const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseLifecycleIdentityMutationDigest {
    lifecycle: VaultLifecycleMetadataView,
    identity: VaultIdentityMetadataView,
}

#[test]
fn external_fixtures_support_database_lifecycle_identity_mutation_oracle() {
    let core = KeepassCore::new();

    let mut new_database = load_fixture(&core, FIXTURE_NEW_DATABASE, "a");
    apply_lifecycle_identity_mutation(&core, &mut new_database);
    assert_eq!(
        collect_lifecycle_identity_mutation_digest(&core, &new_database),
        DatabaseLifecycleIdentityMutationDigest {
            lifecycle: VaultLifecycleMetadataView {
                settings_changed: Some(1_700_200_001),
                maintenance_history_days: Some(42),
                master_key_changed: Some(1_700_200_002),
                master_key_change_rec: Some(90),
                master_key_change_force: Some(120),
                master_key_change_force_once: Some(true),
            },
            identity: VaultIdentityMetadataView {
                name: "External Database Identity".into(),
                generator: Some("keepass-rust-external".into()),
                database_name_changed: Some(1_700_200_003),
                description_changed: Some(1_700_200_004),
                default_username_changed: Some(1_700_200_005),
            },
        }
    );

    let mut format300 = load_fixture(&core, FIXTURE_FORMAT300, "a");
    apply_lifecycle_identity_mutation(&core, &mut format300);
    assert_eq!(
        collect_lifecycle_identity_mutation_digest(&core, &format300),
        DatabaseLifecycleIdentityMutationDigest {
            lifecycle: VaultLifecycleMetadataView {
                settings_changed: Some(1_700_200_001),
                maintenance_history_days: Some(42),
                master_key_changed: Some(1_700_200_002),
                master_key_change_rec: Some(90),
                master_key_change_force: Some(120),
                master_key_change_force_once: Some(true),
            },
            identity: VaultIdentityMetadataView {
                name: "External Database Identity".into(),
                generator: Some("keepass-rust-external".into()),
                database_name_changed: Some(1_700_200_003),
                description_changed: Some(1_700_200_004),
                default_username_changed: Some(1_700_200_005),
            },
        }
    );
}

#[test]
fn external_database_lifecycle_identity_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut new_database = load_fixture(&core, FIXTURE_NEW_DATABASE, "a");
    apply_lifecycle_identity_mutation(&core, &mut new_database);
    let new_database_before = collect_lifecycle_identity_mutation_digest(&core, &new_database);
    let new_database_after = collect_lifecycle_identity_mutation_digest(
        &core,
        &save_and_reload(&core, &new_database, "a"),
    );
    assert_eq!(new_database_after, new_database_before);

    let mut format300 = load_fixture(&core, FIXTURE_FORMAT300, "a");
    apply_lifecycle_identity_mutation(&core, &mut format300);
    let format300_before = collect_lifecycle_identity_mutation_digest(&core, &format300);
    let format300_after =
        collect_lifecycle_identity_mutation_digest(&core, &save_and_reload(&core, &format300, "a"));
    assert_eq!(format300_after, format300_before);
}

fn apply_lifecycle_identity_mutation(core: &KeepassCore, vault: &mut Vault) {
    let lifecycle = core
        .update_vault_lifecycle_metadata(
            vault,
            VaultLifecycleMetadataUpdate {
                settings_changed: Some(1_700_200_001),
                maintenance_history_days: Some(42),
                master_key_changed: Some(1_700_200_002),
                master_key_change_rec: Some(90),
                master_key_change_force: Some(120),
                master_key_change_force_once: Some(true),
            },
        )
        .expect("update lifecycle metadata");
    assert_eq!(lifecycle.settings_changed, Some(1_700_200_001));
    assert_eq!(lifecycle.master_key_change_force_once, Some(true));

    let identity = core
        .update_vault_identity_metadata(
            vault,
            VaultIdentityMetadataUpdate {
                name: Some("External Database Identity".into()),
                generator: Some("keepass-rust-external".into()),
                database_name_changed: Some(1_700_200_003),
                description_changed: Some(1_700_200_004),
                default_username_changed: Some(1_700_200_005),
            },
        )
        .expect("update identity metadata");
    assert_eq!(identity.name, "External Database Identity");
    assert_eq!(identity.generator.as_deref(), Some("keepass-rust-external"));
}

fn collect_lifecycle_identity_mutation_digest(
    core: &KeepassCore,
    vault: &Vault,
) -> DatabaseLifecycleIdentityMutationDigest {
    DatabaseLifecycleIdentityMutationDigest {
        lifecycle: core.project_vault_lifecycle_metadata(vault),
        identity: core.project_vault_identity_metadata(vault),
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}

fn save_and_reload(core: &KeepassCore, vault: &Vault, password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let bytes = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("save fixture");
    core.load_kdbx(&bytes, &key).expect("reload fixture")
}
