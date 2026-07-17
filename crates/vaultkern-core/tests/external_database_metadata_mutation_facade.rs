#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, KeepassCore, MemoryProtection, SaveProfile, Vault, VaultMetadataUpdate,
    VaultMetadataView, VaultSelectionMetadataUpdate, VaultSelectionMetadataView,
};

const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");
const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseMetadataMutationDigest {
    metadata: VaultMetadataView,
    selection: VaultSelectionMetadataView,
    selected_group_title: Option<String>,
    top_group_title: Option<String>,
}

#[derive(Debug, Clone)]
struct DatabaseMetadataMutationRefs {
    selected_group_id: String,
    top_group_id: String,
}

#[test]
fn external_fixtures_support_database_metadata_mutation_oracle() {
    let core = KeepassCore::new();

    let mut new_database = load_fixture(&core, FIXTURE_NEW_DATABASE, "a");
    let new_database_refs = apply_database_metadata_mutation(&core, &mut new_database);
    assert_eq!(
        collect_database_metadata_mutation_digest(&core, &new_database),
        DatabaseMetadataMutationDigest {
            metadata: VaultMetadataView {
                description: Some("External database description".into()),
                default_username: Some("external-default-user".into()),
                color: Some("#224466".into()),
                history_max_items: Some(24),
                history_max_size: Some(12_345_678),
                memory_protection: Some(external_memory_protection()),
            },
            selection: VaultSelectionMetadataView {
                last_selected_group_id: Some(new_database_refs.selected_group_id.clone()),
                last_top_visible_group_id: Some(new_database_refs.top_group_id.clone()),
            },
            selected_group_title: Some("General".into()),
            top_group_title: Some("Homebanking".into()),
        }
    );

    let mut format300 = load_fixture(&core, FIXTURE_FORMAT300, "a");
    let format300_refs = apply_database_metadata_mutation(&core, &mut format300);
    assert_eq!(
        collect_database_metadata_mutation_digest(&core, &format300),
        DatabaseMetadataMutationDigest {
            metadata: VaultMetadataView {
                description: Some("External database description".into()),
                default_username: Some("external-default-user".into()),
                color: Some("#224466".into()),
                history_max_items: Some(24),
                history_max_size: Some(12_345_678),
                memory_protection: Some(external_memory_protection()),
            },
            selection: VaultSelectionMetadataView {
                last_selected_group_id: Some(format300_refs.selected_group_id.clone()),
                last_top_visible_group_id: Some(format300_refs.top_group_id.clone()),
            },
            selected_group_title: Some("General".into()),
            top_group_title: Some("Homebanking".into()),
        }
    );
}

#[test]
fn external_database_metadata_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut new_database = load_fixture(&core, FIXTURE_NEW_DATABASE, "a");
    apply_database_metadata_mutation(&core, &mut new_database);
    let new_database_before = collect_database_metadata_mutation_digest(&core, &new_database);
    let new_database_after = collect_database_metadata_mutation_digest(
        &core,
        &save_and_reload(&core, &new_database, "a"),
    );
    assert_eq!(new_database_after, new_database_before);

    let mut format300 = load_fixture(&core, FIXTURE_FORMAT300, "a");
    apply_database_metadata_mutation(&core, &mut format300);
    let format300_before = collect_database_metadata_mutation_digest(&core, &format300);
    let format300_after =
        collect_database_metadata_mutation_digest(&core, &save_and_reload(&core, &format300, "a"));
    assert_eq!(format300_after, format300_before);
}

fn apply_database_metadata_mutation(
    core: &KeepassCore,
    vault: &mut Vault,
) -> DatabaseMetadataMutationRefs {
    let general_id = find_group_by_title(&vault.root, "General")
        .expect("general group")
        .id
        .to_string();
    let homebanking_id = find_group_by_title(&vault.root, "Homebanking")
        .expect("homebanking group")
        .id
        .to_string();

    let metadata = core
        .update_vault_metadata(
            vault,
            VaultMetadataUpdate {
                description: Some("External database description".into()),
                default_username: Some("external-default-user".into()),
                color: Some("#224466".into()),
                history_max_items: Some(24),
                history_max_size: Some(12_345_678),
                memory_protection: Some(external_memory_protection()),
            },
        )
        .expect("update external database metadata");
    assert_eq!(
        metadata.description.as_deref(),
        Some("External database description")
    );
    assert_eq!(
        metadata.default_username.as_deref(),
        Some("external-default-user")
    );
    assert_eq!(metadata.color.as_deref(), Some("#224466"));

    let selection = core
        .update_vault_selection_metadata(
            vault,
            VaultSelectionMetadataUpdate {
                last_selected_group_id: Some(Some(general_id.clone())),
                last_top_visible_group_id: Some(Some(homebanking_id.clone())),
            },
        )
        .expect("update vault selection metadata");
    assert_eq!(
        selection.last_selected_group_id.as_deref(),
        Some(general_id.as_str())
    );
    assert_eq!(
        selection.last_top_visible_group_id.as_deref(),
        Some(homebanking_id.as_str())
    );

    DatabaseMetadataMutationRefs {
        selected_group_id: general_id,
        top_group_id: homebanking_id,
    }
}

fn collect_database_metadata_mutation_digest(
    core: &KeepassCore,
    vault: &Vault,
) -> DatabaseMetadataMutationDigest {
    let metadata = core.project_vault_metadata(vault);
    let selection = core.project_vault_selection_metadata(vault);
    let selected_group_title = selection
        .last_selected_group_id
        .as_deref()
        .and_then(|id| find_group_by_id(&vault.root, id))
        .map(|group| group.title.clone());
    let top_group_title = selection
        .last_top_visible_group_id
        .as_deref()
        .and_then(|id| find_group_by_id(&vault.root, id))
        .map(|group| group.title.clone());

    DatabaseMetadataMutationDigest {
        metadata,
        selection,
        selected_group_title,
        top_group_title,
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

fn external_memory_protection() -> MemoryProtection {
    MemoryProtection {
        protect_title: true,
        protect_username: true,
        protect_password: true,
        protect_url: false,
        protect_notes: true,
    }
}

fn find_group_by_title<'a>(
    group: &'a vaultkern_core::Group,
    title: &str,
) -> Option<&'a vaultkern_core::Group> {
    if group.title == title {
        return Some(group);
    }
    for child in &group.children {
        if let Some(found) = find_group_by_title(child, title) {
            return Some(found);
        }
    }
    None
}

fn find_group_by_id<'a>(
    group: &'a vaultkern_core::Group,
    id: &str,
) -> Option<&'a vaultkern_core::Group> {
    if group.id.to_string() == id {
        return Some(group);
    }
    for child in &group.children {
        if let Some(found) = find_group_by_id(child, id) {
            return Some(found);
        }
    }
    None
}
