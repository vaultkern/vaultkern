#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, KdbxVersion, KeepassCore, SaveProfile, Vault, VaultIdentityMetadataView,
    VaultLifecycleMetadataView,
};

const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");
const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");
const FIXTURE_PROTECTED_STRINGS: &[u8] =
    include_bytes!("../../../fixtures/kdbx/ProtectedStrings.kdbx");
const FIXTURE_NON_ASCII: &[u8] = include_bytes!("../../../fixtures/kdbx/NonAscii.kdbx");
const FIXTURE_COMPRESSED: &[u8] = include_bytes!("../../../fixtures/kdbx/Compressed.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseLifecycleIdentityDigest {
    lifecycle: VaultLifecycleMetadataView,
    identity: VaultIdentityMetadataView,
}

#[test]
fn external_fixtures_expose_database_lifecycle_identity_projection_oracle() {
    let core = KeepassCore::new();

    assert_eq!(
        collect_database_lifecycle_identity_digest(
            &core,
            &load_fixture(&core, FIXTURE_NEW_DATABASE, "a"),
        ),
        DatabaseLifecycleIdentityDigest {
            lifecycle: VaultLifecycleMetadataView {
                settings_changed: None,
                maintenance_history_days: Some(365),
                master_key_changed: Some(1_283_804_892),
                master_key_change_rec: Some(-1),
                master_key_change_force: Some(-1),
                master_key_change_force_once: None,
            },
            identity: VaultIdentityMetadataView {
                name: "".into(),
                generator: Some("KeePass".into()),
                database_name_changed: Some(1_283_804_892),
                description_changed: Some(1_283_804_892),
                default_username_changed: Some(1_283_804_892),
            },
        }
    );

    assert_eq!(
        collect_database_lifecycle_identity_digest(
            &core,
            &load_fixture(&core, FIXTURE_FORMAT300, "a"),
        ),
        DatabaseLifecycleIdentityDigest {
            lifecycle: VaultLifecycleMetadataView {
                settings_changed: None,
                maintenance_history_days: Some(365),
                master_key_changed: Some(1_348_590_935),
                master_key_change_rec: Some(-1),
                master_key_change_force: Some(-1),
                master_key_change_force_once: None,
            },
            identity: VaultIdentityMetadataView {
                name: "Test Database Format 0x00030000".into(),
                generator: Some("KeePass".into()),
                database_name_changed: Some(1_348_590_987),
                description_changed: Some(1_348_590_935),
                default_username_changed: Some(1_348_590_935),
            },
        }
    );
}

#[test]
fn external_database_lifecycle_identity_projection_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE, "a"),
        (FIXTURE_FORMAT300, "a"),
        (FIXTURE_PROTECTED_STRINGS, "masterpw"),
        (FIXTURE_NON_ASCII, "Δöض"),
        (FIXTURE_COMPRESSED, ""),
    ] {
        let mut key = CompositeKey::default();
        key.add_password(password);

        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load external lifecycle/identity fixture");
        let before = collect_database_lifecycle_identity_digest(&core, &loaded);

        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite external lifecycle/identity fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten external lifecycle/identity fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload rewritten external lifecycle/identity fixture");
        let after = collect_database_lifecycle_identity_digest(&core, &reloaded);

        assert_eq!(inspection.header.version, KdbxVersion::V4_1);
        assert_eq!(after, before);
    }
}

fn collect_database_lifecycle_identity_digest(
    core: &KeepassCore,
    vault: &Vault,
) -> DatabaseLifecycleIdentityDigest {
    DatabaseLifecycleIdentityDigest {
        lifecycle: core.project_vault_lifecycle_metadata(vault),
        identity: core.project_vault_identity_metadata(vault),
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}
