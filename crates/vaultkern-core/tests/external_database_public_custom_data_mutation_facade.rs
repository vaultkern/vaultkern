#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, KeepassCore, PublicCustomDataItemView, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");
const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicCustomDataMutationDigest {
    items: Vec<PublicCustomDataItemView>,
    inspected_items: Vec<(String, Vec<u8>)>,
}

#[test]
fn external_fixtures_support_public_custom_data_mutation_oracle() {
    let core = KeepassCore::new();

    let mut new_database = load_fixture(&core, FIXTURE_NEW_DATABASE, "a");
    apply_public_custom_data_mutation(&core, &mut new_database, "client", b"desktop", "channel");
    let new_database_digest = save_reload_and_collect(&core, &new_database, "a");
    assert_eq!(
        new_database_digest,
        PublicCustomDataMutationDigest {
            items: vec![PublicCustomDataItemView {
                key: "channel".into(),
                value: b"stable".to_vec(),
            }],
            inspected_items: vec![("channel".into(), b"stable".to_vec())],
        }
    );

    let mut format300 = load_fixture(&core, FIXTURE_FORMAT300, "a");
    apply_public_custom_data_mutation(&core, &mut format300, "client", b"legacy", "channel");
    let format300_digest = save_reload_and_collect(&core, &format300, "a");
    assert_eq!(
        format300_digest,
        PublicCustomDataMutationDigest {
            items: vec![PublicCustomDataItemView {
                key: "channel".into(),
                value: b"stable".to_vec(),
            }],
            inspected_items: vec![("channel".into(), b"stable".to_vec())],
        }
    );
}

#[test]
fn external_public_custom_data_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut new_database = load_fixture(&core, FIXTURE_NEW_DATABASE, "a");
    apply_public_custom_data_mutation(&core, &mut new_database, "client", b"desktop", "channel");
    let new_database_before = save_reload_and_collect(&core, &new_database, "a");
    let new_database_after =
        save_reload_and_collect(&core, &save_and_reload(&core, &new_database, "a"), "a");
    assert_eq!(new_database_after, new_database_before);

    let mut format300 = load_fixture(&core, FIXTURE_FORMAT300, "a");
    apply_public_custom_data_mutation(&core, &mut format300, "client", b"legacy", "channel");
    let format300_before = save_reload_and_collect(&core, &format300, "a");
    let format300_after =
        save_reload_and_collect(&core, &save_and_reload(&core, &format300, "a"), "a");
    assert_eq!(format300_after, format300_before);
}

fn apply_public_custom_data_mutation(
    core: &KeepassCore,
    vault: &mut Vault,
    transient_key: &str,
    transient_value: &[u8],
    retained_key: &str,
) {
    assert!(core.list_vault_public_custom_data(vault).is_empty());

    let items = core
        .upsert_vault_public_custom_data(
            vault,
            vaultkern_core::PublicCustomDataItemInput {
                key: transient_key.into(),
                value: transient_value.to_vec(),
            },
        )
        .expect("insert transient public custom data");
    assert_eq!(items.len(), 1);

    let items = core
        .upsert_vault_public_custom_data(
            vault,
            vaultkern_core::PublicCustomDataItemInput {
                key: retained_key.into(),
                value: b"stable".to_vec(),
            },
        )
        .expect("insert retained public custom data");
    assert_eq!(items.len(), 2);

    let items = core
        .delete_vault_public_custom_data(vault, transient_key)
        .expect("delete transient public custom data");
    assert_eq!(
        items,
        vec![PublicCustomDataItemView {
            key: retained_key.into(),
            value: b"stable".to_vec(),
        }]
    );
}

fn save_reload_and_collect(
    core: &KeepassCore,
    vault: &Vault,
    password: &str,
) -> PublicCustomDataMutationDigest {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let bytes = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("save fixture");
    let loaded = core.load_kdbx(&bytes, &key).expect("reload fixture");
    let inspected = core.inspect_kdbx_header(&bytes).expect("inspect fixture");

    PublicCustomDataMutationDigest {
        items: core.list_vault_public_custom_data(&loaded),
        inspected_items: inspected.public_custom_data.into_iter().collect(),
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
