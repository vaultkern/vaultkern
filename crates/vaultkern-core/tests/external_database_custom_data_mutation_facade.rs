#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, CustomDataItemInput, CustomDataItemView, KeepassCore, SaveProfile, Vault,
    VaultCustomDataItemView,
};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseCustomDataMutationDigest {
    items: Vec<CustomDataItemView>,
    detail_items: Vec<VaultCustomDataItemView>,
    last_modified: Option<String>,
    fdo_secrets_exposed_group_id: Option<String>,
    keepassxc_browser_items: Vec<CustomDataItemView>,
}

#[test]
fn external_fixtures_support_database_custom_data_mutation_oracle() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    apply_browser_mutation(&core, &mut browser);
    assert_eq!(
        collect_custom_data_mutation_digest(&core, &browser),
        DatabaseCustomDataMutationDigest {
            items: vec![
                CustomDataItemView {
                    key: "KPXC_BROWSER_stage".into(),
                    value: "stage-browser".into(),
                },
                CustomDataItemView {
                    key: "KPXC_BROWSER_test2".into(),
                    value: "YM1zuHGk5GLctep1gEmms/MuCVFBNWPdUBrmviqj/Q8=".into(),
                },
                CustomDataItemView {
                    key: "_LAST_MODIFIED".into(),
                    value: "Fri Apr 11 12:00:00 2026 GMT".into(),
                },
            ],
            detail_items: vec![
                VaultCustomDataItemView {
                    key: "KPXC_BROWSER_stage".into(),
                    value: "stage-browser".into(),
                    last_modified: None,
                },
                VaultCustomDataItemView {
                    key: "KPXC_BROWSER_test2".into(),
                    value: "YM1zuHGk5GLctep1gEmms/MuCVFBNWPdUBrmviqj/Q8=".into(),
                    last_modified: None,
                },
                VaultCustomDataItemView {
                    key: "_LAST_MODIFIED".into(),
                    value: "Fri Apr 11 12:00:00 2026 GMT".into(),
                    last_modified: None,
                },
            ],
            last_modified: Some("Fri Apr 11 12:00:00 2026 GMT".into()),
            fdo_secrets_exposed_group_id: None,
            keepassxc_browser_items: vec![
                CustomDataItemView {
                    key: "KPXC_BROWSER_stage".into(),
                    value: "stage-browser".into(),
                },
                CustomDataItemView {
                    key: "KPXC_BROWSER_test2".into(),
                    value: "YM1zuHGk5GLctep1gEmms/MuCVFBNWPdUBrmviqj/Q8=".into(),
                },
            ],
        }
    );

    let mut new_database = load_fixture(&core, FIXTURE_NEW_DATABASE, "a");
    apply_new_database_mutation(&core, &mut new_database);
    assert_eq!(
        collect_custom_data_mutation_digest(&core, &new_database),
        DatabaseCustomDataMutationDigest {
            items: vec![
                CustomDataItemView {
                    key: "STAGE_FLAG".into(),
                    value: "enabled".into(),
                },
                CustomDataItemView {
                    key: "_LAST_MODIFIED".into(),
                    value: "Fri Apr 11 13:00:00 2026 GMT".into(),
                },
            ],
            detail_items: vec![
                VaultCustomDataItemView {
                    key: "STAGE_FLAG".into(),
                    value: "enabled".into(),
                    last_modified: None,
                },
                VaultCustomDataItemView {
                    key: "_LAST_MODIFIED".into(),
                    value: "Fri Apr 11 13:00:00 2026 GMT".into(),
                    last_modified: None,
                },
            ],
            last_modified: Some("Fri Apr 11 13:00:00 2026 GMT".into()),
            fdo_secrets_exposed_group_id: None,
            keepassxc_browser_items: Vec::new(),
        }
    );
}

#[test]
fn external_database_custom_data_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    apply_browser_mutation(&core, &mut browser);
    let browser_before = collect_custom_data_mutation_digest(&core, &browser);
    let browser_after =
        collect_custom_data_mutation_digest(&core, &save_and_reload(&core, &browser, "a"));
    assert_eq!(browser_after, browser_before);

    let mut new_database = load_fixture(&core, FIXTURE_NEW_DATABASE, "a");
    apply_new_database_mutation(&core, &mut new_database);
    let new_database_before = collect_custom_data_mutation_digest(&core, &new_database);
    let new_database_after =
        collect_custom_data_mutation_digest(&core, &save_and_reload(&core, &new_database, "a"));
    assert_eq!(new_database_after, new_database_before);
}

fn apply_browser_mutation(core: &KeepassCore, vault: &mut Vault) {
    core.upsert_vault_custom_data(
        vault,
        CustomDataItemInput {
            key: "_LAST_MODIFIED".into(),
            value: "Fri Apr 11 12:00:00 2026 GMT".into(),
        },
    );
    core.upsert_vault_custom_data(
        vault,
        CustomDataItemInput {
            key: "KPXC_BROWSER_stage".into(),
            value: "stage-browser".into(),
        },
    );
    core.delete_vault_custom_data(vault, "KPXC_BROWSER_test")
        .expect("delete browser custom data item");
}

fn apply_new_database_mutation(core: &KeepassCore, vault: &mut Vault) {
    core.upsert_vault_custom_data(
        vault,
        CustomDataItemInput {
            key: "_LAST_MODIFIED".into(),
            value: "Fri Apr 11 13:00:00 2026 GMT".into(),
        },
    );
    core.upsert_vault_custom_data(
        vault,
        CustomDataItemInput {
            key: "STAGE_FLAG".into(),
            value: "enabled".into(),
        },
    );
    core.delete_vault_custom_data(vault, "FDO_SECRETS_EXPOSED_GROUP")
        .expect("delete new-database custom data item");
}

fn collect_custom_data_mutation_digest(
    core: &KeepassCore,
    vault: &Vault,
) -> DatabaseCustomDataMutationDigest {
    let semantic = core.project_vault_custom_data_semantics(vault);
    DatabaseCustomDataMutationDigest {
        items: core.list_vault_custom_data(vault),
        detail_items: core.list_vault_custom_data_detail(vault),
        last_modified: semantic.last_modified,
        fdo_secrets_exposed_group_id: semantic.fdo_secrets_exposed_group_id,
        keepassxc_browser_items: semantic.keepassxc_browser_items,
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
