#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, KeepassCore, SaveProfile, Vault, VaultBinTemplateMetadataUpdate,
    VaultBinTemplateMetadataView,
};

const FIXTURE_RECYCLE_BIN_DISABLED: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinDisabled.kdbx");
const FIXTURE_RECYCLE_BIN_NOT_YET_CREATED: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinNotYetCreated.kdbx");
const FIXTURE_RECYCLE_BIN_EMPTY: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinEmpty.kdbx");
const FIXTURE_RECYCLE_BIN_WITH_DATA: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinWithData.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseBinTemplateMutationDigest {
    metadata: VaultBinTemplateMetadataView,
    recycle_bin_title: Option<String>,
    template_group_title: Option<String>,
}

#[derive(Debug, Clone)]
struct BinTemplateMutationRefs {
    recycle_bin_group_id: String,
    recycle_bin_title: String,
    template_group_id: String,
    template_group_title: String,
}

#[test]
fn external_fixtures_support_database_bin_template_mutation_oracle() {
    let core = KeepassCore::new();

    let mut disabled = load_fixture(&core, FIXTURE_RECYCLE_BIN_DISABLED, "123");
    let disabled_refs = apply_disabled_mutation(&core, &mut disabled);
    assert_eq!(
        collect_mutation_digest(&core, &disabled),
        DatabaseBinTemplateMutationDigest {
            metadata: VaultBinTemplateMetadataView {
                recycle_bin_enabled: Some(true),
                recycle_bin_group_id: Some(disabled_refs.recycle_bin_group_id.clone()),
                recycle_bin_changed: Some(1_700_100_001),
                entry_templates_group_id: Some(disabled_refs.template_group_id.clone()),
                entry_templates_group_changed: Some(1_700_100_002),
            },
            recycle_bin_title: Some(disabled_refs.recycle_bin_title),
            template_group_title: Some(disabled_refs.template_group_title),
        }
    );

    let mut not_yet_created = load_fixture(&core, FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, "123");
    let not_yet_created_refs = apply_not_yet_created_mutation(&core, &mut not_yet_created);
    assert_eq!(
        collect_mutation_digest(&core, &not_yet_created),
        DatabaseBinTemplateMutationDigest {
            metadata: VaultBinTemplateMetadataView {
                recycle_bin_enabled: Some(true),
                recycle_bin_group_id: Some(not_yet_created_refs.recycle_bin_group_id.clone()),
                recycle_bin_changed: Some(1_700_100_101),
                entry_templates_group_id: Some(not_yet_created_refs.template_group_id.clone()),
                entry_templates_group_changed: Some(1_700_100_102),
            },
            recycle_bin_title: Some(not_yet_created_refs.recycle_bin_title),
            template_group_title: Some(not_yet_created_refs.template_group_title),
        }
    );

    let mut empty = load_fixture(&core, FIXTURE_RECYCLE_BIN_EMPTY, "123");
    let empty_existing_recycle_bin_id = empty
        .recycle_bin_group
        .expect("existing recycle bin id")
        .to_string();
    let empty_refs = apply_empty_mutation(&core, &mut empty);
    assert_eq!(
        empty_refs.recycle_bin_group_id,
        empty_existing_recycle_bin_id
    );
    assert_eq!(
        collect_mutation_digest(&core, &empty),
        DatabaseBinTemplateMutationDigest {
            metadata: VaultBinTemplateMetadataView {
                recycle_bin_enabled: Some(true),
                recycle_bin_group_id: Some(empty_refs.recycle_bin_group_id.clone()),
                recycle_bin_changed: Some(1_700_100_201),
                entry_templates_group_id: Some(empty_refs.template_group_id.clone()),
                entry_templates_group_changed: Some(1_700_100_202),
            },
            recycle_bin_title: Some(empty_refs.recycle_bin_title),
            template_group_title: Some(empty_refs.template_group_title),
        }
    );

    let mut with_data = load_fixture(&core, FIXTURE_RECYCLE_BIN_WITH_DATA, "123");
    let with_data_existing_recycle_bin_id = with_data
        .recycle_bin_group
        .expect("existing populated recycle bin id")
        .to_string();
    let with_data_refs = apply_with_data_mutation(&core, &mut with_data);
    assert_eq!(
        with_data_refs.recycle_bin_group_id,
        with_data_existing_recycle_bin_id
    );
    assert_eq!(
        collect_mutation_digest(&core, &with_data),
        DatabaseBinTemplateMutationDigest {
            metadata: VaultBinTemplateMetadataView {
                recycle_bin_enabled: Some(true),
                recycle_bin_group_id: Some(with_data_refs.recycle_bin_group_id.clone()),
                recycle_bin_changed: Some(1_700_100_301),
                entry_templates_group_id: Some(with_data_refs.template_group_id.clone()),
                entry_templates_group_changed: Some(1_700_100_302),
            },
            recycle_bin_title: Some(with_data_refs.recycle_bin_title),
            template_group_title: Some(with_data_refs.template_group_title),
        }
    );
}

#[test]
fn external_database_bin_template_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut disabled = load_fixture(&core, FIXTURE_RECYCLE_BIN_DISABLED, "123");
    apply_disabled_mutation(&core, &mut disabled);
    let disabled_before = collect_mutation_digest(&core, &disabled);
    let disabled_after = collect_mutation_digest(&core, &save_and_reload(&core, &disabled, "123"));
    assert_eq!(disabled_after, disabled_before);

    let mut not_yet_created = load_fixture(&core, FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, "123");
    apply_not_yet_created_mutation(&core, &mut not_yet_created);
    let not_yet_created_before = collect_mutation_digest(&core, &not_yet_created);
    let not_yet_created_after =
        collect_mutation_digest(&core, &save_and_reload(&core, &not_yet_created, "123"));
    assert_eq!(not_yet_created_after, not_yet_created_before);

    let mut empty = load_fixture(&core, FIXTURE_RECYCLE_BIN_EMPTY, "123");
    apply_empty_mutation(&core, &mut empty);
    let empty_before = collect_mutation_digest(&core, &empty);
    let empty_after = collect_mutation_digest(&core, &save_and_reload(&core, &empty, "123"));
    assert_eq!(empty_after, empty_before);

    let mut with_data = load_fixture(&core, FIXTURE_RECYCLE_BIN_WITH_DATA, "123");
    apply_with_data_mutation(&core, &mut with_data);
    let with_data_before = collect_mutation_digest(&core, &with_data);
    let with_data_after =
        collect_mutation_digest(&core, &save_and_reload(&core, &with_data, "123"));
    assert_eq!(with_data_after, with_data_before);
}

fn apply_disabled_mutation(core: &KeepassCore, vault: &mut Vault) -> BinTemplateMutationRefs {
    apply_mutation(core, vault, "Mail", "Network", 1_700_100_001, 1_700_100_002)
}

fn apply_not_yet_created_mutation(
    core: &KeepassCore,
    vault: &mut Vault,
) -> BinTemplateMutationRefs {
    apply_mutation(
        core,
        vault,
        "Computer logins",
        "Mail",
        1_700_100_101,
        1_700_100_102,
    )
}

fn apply_empty_mutation(core: &KeepassCore, vault: &mut Vault) -> BinTemplateMutationRefs {
    let recycle_bin_id = vault
        .recycle_bin_group
        .expect("existing recycle bin id")
        .to_string();
    apply_mutation_with_group_ids(
        core,
        vault,
        recycle_bin_id,
        "Recycle Bin",
        find_group_by_title(&vault.root, "Mail")
            .expect("empty fixture mail group")
            .id
            .to_string(),
        "Mail",
        1_700_100_201,
        1_700_100_202,
    )
}

fn apply_with_data_mutation(core: &KeepassCore, vault: &mut Vault) -> BinTemplateMutationRefs {
    let recycle_bin_id = vault
        .recycle_bin_group
        .expect("existing populated recycle bin id")
        .to_string();
    apply_mutation_with_group_ids(
        core,
        vault,
        recycle_bin_id,
        "Recycle Bin",
        find_group_by_title(&vault.root, "Network")
            .expect("with-data fixture network group")
            .id
            .to_string(),
        "Network",
        1_700_100_301,
        1_700_100_302,
    )
}

fn apply_mutation(
    core: &KeepassCore,
    vault: &mut Vault,
    recycle_bin_title: &str,
    template_group_title: &str,
    recycle_bin_changed: i64,
    entry_templates_group_changed: i64,
) -> BinTemplateMutationRefs {
    let recycle_bin_group = find_group_by_title(&vault.root, recycle_bin_title)
        .expect("recycle-bin target group")
        .id
        .to_string();
    let template_group = find_group_by_title(&vault.root, template_group_title)
        .expect("entry-templates target group")
        .id
        .to_string();
    apply_mutation_with_group_ids(
        core,
        vault,
        recycle_bin_group,
        recycle_bin_title,
        template_group,
        template_group_title,
        recycle_bin_changed,
        entry_templates_group_changed,
    )
}

fn apply_mutation_with_group_ids(
    core: &KeepassCore,
    vault: &mut Vault,
    recycle_bin_group_id: String,
    recycle_bin_title: &str,
    template_group_id: String,
    template_group_title: &str,
    recycle_bin_changed: i64,
    entry_templates_group_changed: i64,
) -> BinTemplateMutationRefs {
    let metadata = core
        .update_vault_bin_template_metadata(
            vault,
            VaultBinTemplateMetadataUpdate {
                recycle_bin_enabled: Some(Some(true)),
                recycle_bin_group_id: Some(Some(recycle_bin_group_id.clone())),
                recycle_bin_changed: Some(Some(recycle_bin_changed)),
                entry_templates_group_id: Some(Some(template_group_id.clone())),
                entry_templates_group_changed: Some(Some(entry_templates_group_changed)),
            },
        )
        .expect("update vault bin/template metadata");

    assert_eq!(
        metadata.recycle_bin_group_id.as_deref(),
        Some(recycle_bin_group_id.as_str())
    );
    assert_eq!(
        metadata.entry_templates_group_id.as_deref(),
        Some(template_group_id.as_str())
    );

    BinTemplateMutationRefs {
        recycle_bin_group_id,
        recycle_bin_title: recycle_bin_title.into(),
        template_group_id,
        template_group_title: template_group_title.into(),
    }
}

fn collect_mutation_digest(core: &KeepassCore, vault: &Vault) -> DatabaseBinTemplateMutationDigest {
    let metadata = core.project_vault_bin_template_metadata(vault);
    let recycle_bin_title = metadata
        .recycle_bin_group_id
        .as_deref()
        .and_then(|id| find_group_by_id(&vault.root, id))
        .map(|group| group.title.clone());
    let template_group_title = metadata
        .entry_templates_group_id
        .as_deref()
        .and_then(|id| find_group_by_id(&vault.root, id))
        .map(|group| group.title.clone());

    DatabaseBinTemplateMutationDigest {
        metadata,
        recycle_bin_title,
        template_group_title,
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
