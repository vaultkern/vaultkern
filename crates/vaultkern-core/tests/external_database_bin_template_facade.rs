#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, KdbxVersion, KeepassCore, SaveProfile, Vault, VaultBinTemplateMetadataView,
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
struct DatabaseBinTemplateDigest {
    metadata: VaultBinTemplateMetadataView,
    recycle_bin_title: Option<String>,
    template_group_title: Option<String>,
}

#[test]
fn external_fixtures_expose_database_bin_template_projection_oracle() {
    let core = KeepassCore::new();

    let disabled = load_fixture(&core, FIXTURE_RECYCLE_BIN_DISABLED, "123");
    let not_yet_created = load_fixture(&core, FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, "123");
    let empty = load_fixture(&core, FIXTURE_RECYCLE_BIN_EMPTY, "123");
    let with_data = load_fixture(&core, FIXTURE_RECYCLE_BIN_WITH_DATA, "123");

    assert_eq!(
        collect_database_bin_template_digest(&core, &disabled),
        DatabaseBinTemplateDigest {
            metadata: VaultBinTemplateMetadataView {
                recycle_bin_enabled: Some(false),
                recycle_bin_group_id: None,
                recycle_bin_changed: Some(1_492_843_388),
                entry_templates_group_id: None,
                entry_templates_group_changed: Some(1_492_843_388),
            },
            recycle_bin_title: None,
            template_group_title: None,
        }
    );

    assert_eq!(
        collect_database_bin_template_digest(&core, &not_yet_created),
        DatabaseBinTemplateDigest {
            metadata: VaultBinTemplateMetadataView {
                recycle_bin_enabled: Some(true),
                recycle_bin_group_id: None,
                recycle_bin_changed: Some(1_492_843_388),
                entry_templates_group_id: None,
                entry_templates_group_changed: Some(1_492_843_388),
            },
            recycle_bin_title: None,
            template_group_title: None,
        }
    );

    assert_eq!(
        collect_database_bin_template_digest(&core, &empty),
        DatabaseBinTemplateDigest {
            metadata: VaultBinTemplateMetadataView {
                recycle_bin_enabled: Some(true),
                recycle_bin_group_id: Some(
                    find_group_by_title(&empty.root, "Recycle Bin")
                        .expect("recycle bin group")
                        .id
                        .to_string(),
                ),
                recycle_bin_changed: Some(1_492_849_706),
                entry_templates_group_id: None,
                entry_templates_group_changed: Some(1_492_843_388),
            },
            recycle_bin_title: Some("Recycle Bin".into()),
            template_group_title: None,
        }
    );

    assert_eq!(
        collect_database_bin_template_digest(&core, &with_data),
        DatabaseBinTemplateDigest {
            metadata: VaultBinTemplateMetadataView {
                recycle_bin_enabled: Some(true),
                recycle_bin_group_id: Some(
                    find_group_by_title(&with_data.root, "Recycle Bin")
                        .expect("recycle bin group")
                        .id
                        .to_string(),
                ),
                recycle_bin_changed: Some(1_492_849_706),
                entry_templates_group_id: None,
                entry_templates_group_changed: Some(1_492_843_388),
            },
            recycle_bin_title: Some("Recycle Bin".into()),
            template_group_title: None,
        }
    );
}

#[test]
fn external_database_bin_template_projection_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for fixture in [
        FIXTURE_RECYCLE_BIN_DISABLED,
        FIXTURE_RECYCLE_BIN_NOT_YET_CREATED,
        FIXTURE_RECYCLE_BIN_EMPTY,
        FIXTURE_RECYCLE_BIN_WITH_DATA,
    ] {
        let mut key = CompositeKey::default();
        key.add_password("123");

        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load external bin/template fixture");
        let before = collect_database_bin_template_digest(&core, &loaded);

        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite external bin/template fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten external bin/template fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload rewritten external bin/template fixture");
        let after = collect_database_bin_template_digest(&core, &reloaded);

        assert_eq!(inspection.header.version, KdbxVersion::V4_1);
        assert_eq!(after, before);
    }
}

fn collect_database_bin_template_digest(
    core: &KeepassCore,
    vault: &Vault,
) -> DatabaseBinTemplateDigest {
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

    DatabaseBinTemplateDigest {
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
