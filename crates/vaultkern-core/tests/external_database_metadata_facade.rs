#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, KdbxVersion, KeepassCore, MemoryProtection, SaveProfile, Vault,
    VaultMetadataView, VaultSelectionMetadataView,
};

const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");
const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");
const FIXTURE_PROTECTED_STRINGS: &[u8] =
    include_bytes!("../../../fixtures/kdbx/ProtectedStrings.kdbx");
const FIXTURE_NON_ASCII: &[u8] = include_bytes!("../../../fixtures/kdbx/NonAscii.kdbx");
const FIXTURE_COMPRESSED: &[u8] = include_bytes!("../../../fixtures/kdbx/Compressed.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseMetadataDigest {
    metadata: VaultMetadataView,
    selection: VaultSelectionMetadataView,
}

#[test]
fn external_fixtures_expose_database_metadata_projection_oracle() {
    let core = KeepassCore::new();

    let new_database = load_fixture(&core, FIXTURE_NEW_DATABASE, "a");
    let format300 = load_fixture(&core, FIXTURE_FORMAT300, "a");
    let protected_strings = load_fixture(&core, FIXTURE_PROTECTED_STRINGS, "masterpw");
    let non_ascii = load_fixture(&core, FIXTURE_NON_ASCII, "Δöض");
    let compressed = load_fixture(&core, FIXTURE_COMPRESSED, "");

    assert_eq!(
        collect_database_metadata_digest(&core, &new_database),
        DatabaseMetadataDigest {
            metadata: VaultMetadataView {
                description: None,
                default_username: None,
                color: None,
                history_max_items: Some(10),
                history_max_size: Some(6_291_456),
                memory_protection: Some(password_only_memory_protection()),
            },
            selection: VaultSelectionMetadataView {
                last_selected_group_id: Some(new_database.root.id.to_string()),
                last_top_visible_group_id: Some(new_database.root.id.to_string()),
            },
        }
    );

    assert_eq!(
        collect_database_metadata_digest(&core, &format300),
        DatabaseMetadataDigest {
            metadata: VaultMetadataView {
                description: None,
                default_username: None,
                color: None,
                history_max_items: Some(10),
                history_max_size: Some(6_291_456),
                memory_protection: Some(password_only_memory_protection()),
            },
            selection: VaultSelectionMetadataView {
                last_selected_group_id: Some(format300.root.id.to_string()),
                last_top_visible_group_id: Some(format300.root.id.to_string()),
            },
        }
    );

    assert_eq!(
        collect_database_metadata_digest(&core, &protected_strings),
        DatabaseMetadataDigest {
            metadata: VaultMetadataView {
                description: None,
                default_username: None,
                color: None,
                history_max_items: Some(10),
                history_max_size: Some(6_291_456),
                memory_protection: Some(password_only_memory_protection()),
            },
            selection: VaultSelectionMetadataView {
                last_selected_group_id: Some(protected_strings.root.id.to_string()),
                last_top_visible_group_id: Some(protected_strings.root.id.to_string()),
            },
        }
    );

    assert_eq!(
        collect_database_metadata_digest(&core, &non_ascii),
        DatabaseMetadataDigest {
            metadata: VaultMetadataView {
                description: None,
                default_username: None,
                color: None,
                history_max_items: Some(10),
                history_max_size: Some(6_291_456),
                memory_protection: Some(password_only_memory_protection()),
            },
            selection: VaultSelectionMetadataView {
                last_selected_group_id: Some(non_ascii.root.id.to_string()),
                last_top_visible_group_id: Some(non_ascii.root.id.to_string()),
            },
        }
    );

    assert_eq!(
        collect_database_metadata_digest(&core, &compressed),
        DatabaseMetadataDigest {
            metadata: VaultMetadataView {
                description: None,
                default_username: None,
                color: None,
                history_max_items: Some(10),
                history_max_size: Some(6_291_456),
                memory_protection: Some(password_only_memory_protection()),
            },
            selection: VaultSelectionMetadataView {
                last_selected_group_id: Some(compressed.root.id.to_string()),
                last_top_visible_group_id: Some(compressed.root.id.to_string()),
            },
        }
    );
}

#[test]
fn external_database_metadata_projection_preserves_fixture_matrix_on_roundtrip() {
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
            .expect("load external metadata fixture");
        let before = collect_database_metadata_digest(&core, &loaded);

        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite external metadata fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten external metadata fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload rewritten external metadata fixture");
        let after = collect_database_metadata_digest(&core, &reloaded);

        assert_eq!(inspection.header.version, KdbxVersion::V4_1);
        assert_eq!(after, before);
    }
}

fn collect_database_metadata_digest(core: &KeepassCore, vault: &Vault) -> DatabaseMetadataDigest {
    DatabaseMetadataDigest {
        metadata: core.project_vault_metadata(vault),
        selection: core.project_vault_selection_metadata(vault),
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}

fn password_only_memory_protection() -> MemoryProtection {
    MemoryProtection {
        protect_title: false,
        protect_username: false,
        protect_password: true,
        protect_url: false,
        protect_notes: false,
    }
}
