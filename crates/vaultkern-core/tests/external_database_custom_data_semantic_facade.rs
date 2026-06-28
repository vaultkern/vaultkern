#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, CustomDataItemView, KeepassCore, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseCustomDataSemanticDigest {
    last_modified: Option<String>,
    fdo_secrets_exposed_group_id: Option<String>,
    keepassxc_browser_items: Vec<CustomDataItemView>,
}

#[test]
fn external_fixtures_expose_database_custom_data_semantic_oracle() {
    let core = KeepassCore::new();

    assert_eq!(
        collect_database_custom_data_semantic_digest(
            &core,
            &load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a"),
        ),
        DatabaseCustomDataSemanticDigest {
            last_modified: Some("Wed Apr 29 20:57:45 2020 GMT".into()),
            fdo_secrets_exposed_group_id: None,
            keepassxc_browser_items: vec![
                CustomDataItemView {
                    key: "KPXC_BROWSER_test".into(),
                    value: "9l41TH7Lky0zfXdjKr+xhduR6k33qAPuMppy4bPlJ2M=".into(),
                },
                CustomDataItemView {
                    key: "KPXC_BROWSER_test2".into(),
                    value: "YM1zuHGk5GLctep1gEmms/MuCVFBNWPdUBrmviqj/Q8=".into(),
                },
            ],
        }
    );

    assert_eq!(
        collect_database_custom_data_semantic_digest(
            &core,
            &load_fixture(&core, FIXTURE_NEW_DATABASE, "a"),
        ),
        DatabaseCustomDataSemanticDigest {
            last_modified: Some("Sun Nov 7 21:48:24 2021 GMT".into()),
            fdo_secrets_exposed_group_id: Some("{87f9f6bf-2e09-2344-a972-a1d1de394774}".into(),),
            keepassxc_browser_items: Vec::new(),
        }
    );
}

#[test]
fn external_database_custom_data_semantic_projection_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_NEW_DATABASE, "a"),
    ] {
        let mut key = CompositeKey::default();
        key.add_password(password);

        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load external database custom-data semantic fixture");
        let before = collect_database_custom_data_semantic_digest(&core, &loaded);

        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite external database custom-data semantic fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload external database custom-data semantic fixture");
        let after = collect_database_custom_data_semantic_digest(&core, &reloaded);

        assert_eq!(after, before);
    }
}

fn collect_database_custom_data_semantic_digest(
    core: &KeepassCore,
    vault: &Vault,
) -> DatabaseCustomDataSemanticDigest {
    let semantic = core.project_vault_custom_data_semantics(vault);
    DatabaseCustomDataSemanticDigest {
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
