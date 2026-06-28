#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, KeepassCore, SaveProfile, Vault, VaultCustomDataItemView};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseCustomDataDetailDigest {
    items: Vec<VaultCustomDataItemView>,
}

#[test]
fn external_fixtures_expose_database_custom_data_detail_oracle() {
    let core = KeepassCore::new();

    assert_eq!(
        collect_database_custom_data_detail_digest(
            &core,
            &load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a"),
        ),
        DatabaseCustomDataDetailDigest {
            items: vec![
                VaultCustomDataItemView {
                    key: "KPXC_BROWSER_test".into(),
                    value: "9l41TH7Lky0zfXdjKr+xhduR6k33qAPuMppy4bPlJ2M=".into(),
                    last_modified: None,
                },
                VaultCustomDataItemView {
                    key: "KPXC_BROWSER_test2".into(),
                    value: "YM1zuHGk5GLctep1gEmms/MuCVFBNWPdUBrmviqj/Q8=".into(),
                    last_modified: None,
                },
                VaultCustomDataItemView {
                    key: "_LAST_MODIFIED".into(),
                    value: "Wed Apr 29 20:57:45 2020 GMT".into(),
                    last_modified: None,
                },
            ],
        }
    );

    assert_eq!(
        collect_database_custom_data_detail_digest(
            &core,
            &load_fixture(&core, FIXTURE_NEW_DATABASE, "a"),
        ),
        DatabaseCustomDataDetailDigest {
            items: vec![
                VaultCustomDataItemView {
                    key: "FDO_SECRETS_EXPOSED_GROUP".into(),
                    value: "{87f9f6bf-2e09-2344-a972-a1d1de394774}".into(),
                    last_modified: None,
                },
                VaultCustomDataItemView {
                    key: "_LAST_MODIFIED".into(),
                    value: "Sun Nov 7 21:48:24 2021 GMT".into(),
                    last_modified: None,
                },
            ],
        }
    );
}

#[test]
fn external_database_custom_data_detail_projection_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_NEW_DATABASE, "a"),
    ] {
        let mut key = CompositeKey::default();
        key.add_password(password);

        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load external database custom-data detail fixture");
        let before = collect_database_custom_data_detail_digest(&core, &loaded);

        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite external database custom-data detail fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload external database custom-data detail fixture");
        let after = collect_database_custom_data_detail_digest(&core, &reloaded);

        assert_eq!(after, before);
    }
}

fn collect_database_custom_data_detail_digest(
    core: &KeepassCore,
    vault: &Vault,
) -> DatabaseCustomDataDetailDigest {
    DatabaseCustomDataDetailDigest {
        items: core.list_vault_custom_data_detail(vault),
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}
