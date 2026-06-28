#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    AttachmentView, CompositeKey, KdbxVersion, KeepassCore, MutationError, SaveProfile, Vault,
};

const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD: &[u8] =
    include_bytes!("../../../fixtures/kdbx/SyncDatabaseDifferentPassword.kdbx");
const FIXTURE_USER_TEST: &[u8] = include_bytes!("../../../fixtures/kdbx/test.kdbx");
const FIXTURE_USER_TEST4: &[u8] = include_bytes!("../../../fixtures/kdbx/test4.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachmentDigest {
    name: &'static str,
    data: &'static [u8],
    protect_in_memory: bool,
}

#[test]
fn loads_external_attachment_fixtures_with_breadth_oracle() {
    let core = KeepassCore::new();

    assert_sync_fixture_attachment_oracle(&core, FIXTURE_SYNC_DATABASE, "a");
    assert_sync_fixture_attachment_oracle(&core, FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD, "b");
    assert_user_fixture_attachment_oracle(&core, FIXTURE_USER_TEST, "123456", false);
    assert_user_fixture_attachment_oracle(&core, FIXTURE_USER_TEST4, "123456", true);
}

#[test]
fn external_attachment_fixtures_preserve_breadth_oracle_on_roundtrip() {
    let core = KeepassCore::new();

    for (bytes, password, assert_loaded) in [
        (
            FIXTURE_SYNC_DATABASE,
            "a",
            assert_sync_fixture_attachment_oracle as fn(&KeepassCore, &[u8], &str),
        ),
        (
            FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD,
            "b",
            assert_sync_fixture_attachment_oracle as fn(&KeepassCore, &[u8], &str),
        ),
        (FIXTURE_USER_TEST, "123456", |core, bytes, password| {
            assert_user_fixture_attachment_oracle(core, bytes, password, false)
        }),
        (FIXTURE_USER_TEST4, "123456", |core, bytes, password| {
            assert_user_fixture_attachment_oracle(core, bytes, password, true)
        }),
    ] {
        let mut key = CompositeKey::default();
        key.add_password(password);

        let loaded = core
            .load_kdbx(bytes, &key)
            .expect("load external attachment fixture");
        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite external attachment fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten external attachment fixture");

        assert_eq!(inspection.header.version, KdbxVersion::V4_1);
        assert_loaded(&core, &rewritten, password);
    }
}

fn assert_sync_fixture_attachment_oracle(core: &KeepassCore, bytes: &[u8], password: &str) {
    let vault = load_fixture(core, bytes, password);
    let root_entry = vault.root.entries.first().expect("root entry");
    let root_entry_id = root_entry.id.to_string();

    assert_attachment_views(
        &core
            .list_entry_attachments(&vault, &root_entry_id)
            .expect("list sync root attachments"),
        &[AttachmentDigest {
            name: "Sample attachment.txt",
            data: b"Sample content\n",
            protect_in_memory: false,
        }],
    );
    assert_attachment_content(
        core,
        &vault,
        &root_entry_id,
        "Sample attachment.txt",
        b"Sample content\n",
    );

    let history_items = core
        .list_entry_history(&vault, &root_entry_id)
        .expect("list sync root history");
    assert_eq!(history_items.len(), 10);
    for history_index in 0..9 {
        assert!(
            core.list_entry_history_attachments(&vault, &root_entry_id, history_index)
                .expect("list sync history attachments")
                .is_empty()
        );
    }
    assert_attachment_views(
        &core
            .list_entry_history_attachments(&vault, &root_entry_id, 9)
            .expect("list latest sync history attachments"),
        &[AttachmentDigest {
            name: "Sample attachment.txt",
            data: b"Sample content \n",
            protect_in_memory: false,
        }],
    );
    assert_attachment_content(
        core,
        &vault,
        &root_entry_id,
        "Sample attachment.txt",
        b"Sample content\n",
    );
    let history_content = core
        .project_entry_history_attachment_content(
            &vault,
            &root_entry_id,
            9,
            "Sample attachment.txt",
        )
        .expect("project latest sync history attachment content");
    assert_eq!(history_content.name, "Sample attachment.txt");
    assert_eq!(history_content.data, b"Sample content \n".to_vec());

    let subgroup_entry = find_group_by_title(&vault.root, "Homebanking")
        .and_then(|group| find_group_by_title(group, "Subgroup"))
        .and_then(|group| group.entries.first())
        .expect("subgroup entry");
    let subgroup_entry_id = subgroup_entry.id.to_string();
    assert!(
        core.list_entry_attachments(&vault, &subgroup_entry_id)
            .expect("list subgroup attachments")
            .is_empty()
    );
    assert_eq!(
        core.list_entry_history(&vault, &subgroup_entry_id)
            .expect("list subgroup history")
            .len(),
        2
    );
    assert!(
        core.list_entry_history_attachments(&vault, &subgroup_entry_id, 0)
            .expect("list subgroup history attachments")
            .is_empty()
    );
    assert!(
        core.list_entry_history_attachments(&vault, &subgroup_entry_id, 1)
            .expect("list subgroup history attachments")
            .is_empty()
    );
}

fn assert_user_fixture_attachment_oracle(
    core: &KeepassCore,
    bytes: &[u8],
    password: &str,
    expected_protection: bool,
) {
    let vault = load_fixture(core, bytes, password);
    let entry = vault.root.entries.first().expect("user fixture entry");
    let entry_id = entry.id.to_string();

    assert_attachment_views(
        &core
            .list_entry_attachments(&vault, &entry_id)
            .expect("list user fixture attachments"),
        &[AttachmentDigest {
            name: "test",
            data: b"test",
            protect_in_memory: expected_protection,
        }],
    );
    assert_attachment_content(core, &vault, &entry_id, "test", b"test");
    let history = core
        .list_entry_history(&vault, &entry_id)
        .expect("list user fixture history");
    assert_eq!(
        core.project_entry_history_attachment_content(&vault, &entry_id, history.len(), "test")
            .expect_err("history attachment should be absent"),
        MutationError::HistoryIndexOutOfBounds(history.len())
    );
}

fn assert_attachment_views(actual: &[AttachmentView], expected: &[AttachmentDigest]) {
    assert_eq!(
        actual,
        &expected
            .iter()
            .map(|attachment| AttachmentView {
                name: attachment.name.into(),
                size: attachment.data.len(),
                protect_in_memory: attachment.protect_in_memory,
            })
            .collect::<Vec<_>>()
    );
}

fn assert_attachment_content(
    core: &KeepassCore,
    vault: &Vault,
    entry_id: &str,
    name: &str,
    expected_data: &[u8],
) {
    let content = core
        .project_entry_attachment_content(vault, entry_id, name)
        .expect("project live attachment content");
    assert_eq!(content.name, name);
    assert_eq!(content.data, expected_data);
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
