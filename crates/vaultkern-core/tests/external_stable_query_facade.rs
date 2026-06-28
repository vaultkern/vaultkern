#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, EntryView, GroupView, KeepassCore, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");
const FIXTURE_RECYCLE_BIN_WITH_DATA: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinWithData.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryOracleDigest {
    group: GroupLookupDigest,
    entry: EntryLookupDigest,
    search: Vec<SearchMatchDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupLookupDigest {
    id: String,
    title: String,
    entry_count: usize,
    child_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryLookupDigest {
    id: String,
    title: String,
    username: String,
    url: String,
    attachment_count: usize,
    history_count: usize,
    has_totp: bool,
    has_passkey: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SearchMatchDigest {
    entry_id: String,
    title: String,
    username: String,
    group_id: String,
    group_path: Vec<String>,
    attachment_count: usize,
    history_count: usize,
}

#[test]
fn external_fixtures_expose_stable_query_oracle() {
    let core = KeepassCore::new();

    let browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_group =
        find_group_by_path(&browser.root, &["Homebanking", "Subgroup"]).expect("browser subgroup");
    let browser_entry =
        find_entry_in_group(browser_group, "Subgroup Entry").expect("browser subgroup entry");
    assert_eq!(
        collect_query_digest(
            &core,
            &browser,
            &browser_group.id.to_string(),
            &browser_entry.id.to_string(),
            "Important note"
        ),
        QueryOracleDigest {
            group: GroupLookupDigest {
                id: browser_group.id.to_string(),
                title: "Subgroup".into(),
                entry_count: 1,
                child_count: 0,
            },
            entry: EntryLookupDigest {
                id: browser_entry.id.to_string(),
                title: "Subgroup Entry".into(),
                username: "Bank User Name".into(),
                url: "https:/www.bank.com".into(),
                attachment_count: 0,
                history_count: 1,
                has_totp: false,
                has_passkey: false,
            },
            search: vec![SearchMatchDigest {
                entry_id: browser_entry.id.to_string(),
                title: "Subgroup Entry".into(),
                username: "Bank User Name".into(),
                group_id: browser_group.id.to_string(),
                group_path: vec![
                    "NewDatabase".into(),
                    "Homebanking".into(),
                    "Subgroup".into()
                ],
                attachment_count: 0,
                history_count: 1,
            }],
        }
    );

    let sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let sync_group =
        find_group_by_path(&sync.root, &["Homebanking", "Subgroup"]).expect("sync subgroup");
    let sync_entry =
        find_entry_in_group(sync_group, "Subgroup Entry").expect("sync subgroup entry");
    assert_eq!(
        collect_query_digest(
            &core,
            &sync,
            &sync_group.id.to_string(),
            &sync_entry.id.to_string(),
            "Important note"
        ),
        QueryOracleDigest {
            group: GroupLookupDigest {
                id: sync_group.id.to_string(),
                title: "Subgroup".into(),
                entry_count: 1,
                child_count: 0,
            },
            entry: EntryLookupDigest {
                id: sync_entry.id.to_string(),
                title: "Subgroup Entry".into(),
                username: "Bank User Name".into(),
                url: "https://www.bank.com".into(),
                attachment_count: 0,
                history_count: 2,
                has_totp: false,
                has_passkey: false,
            },
            search: vec![SearchMatchDigest {
                entry_id: sync_entry.id.to_string(),
                title: "Subgroup Entry".into(),
                username: "Bank User Name".into(),
                group_id: sync_group.id.to_string(),
                group_path: vec![
                    "NewDatabase".into(),
                    "Homebanking".into(),
                    "Subgroup".into()
                ],
                attachment_count: 0,
                history_count: 2,
            }],
        }
    );

    let merge = load_fixture(&core, FIXTURE_MERGE_DATABASE, "a");
    let merge_group =
        find_group_by_path(&merge.root, &["TestExtraGroup"]).expect("merge extra group");
    let merge_entry = find_entry_in_group(merge_group, "b").expect("merge extra entry");
    assert_eq!(
        collect_query_digest(
            &core,
            &merge,
            &merge_group.id.to_string(),
            &merge_entry.id.to_string(),
            "pc"
        ),
        QueryOracleDigest {
            group: GroupLookupDigest {
                id: merge_group.id.to_string(),
                title: "TestExtraGroup".into(),
                entry_count: 1,
                child_count: 0,
            },
            entry: EntryLookupDigest {
                id: merge_entry.id.to_string(),
                title: "b".into(),
                username: "".into(),
                url: "".into(),
                attachment_count: 0,
                history_count: 0,
                has_totp: false,
                has_passkey: false,
            },
            search: vec![SearchMatchDigest {
                entry_id: find_entry_in_group(
                    find_group_by_path(&merge.root, &["General"]).expect("merge general"),
                    "pc"
                )
                .expect("merge general entry")
                .id
                .to_string(),
                title: "pc".into(),
                username: "".into(),
                group_id: find_group_by_path(&merge.root, &["General"])
                    .expect("merge general")
                    .id
                    .to_string(),
                group_path: vec!["NewDatabase".into(), "General".into()],
                attachment_count: 0,
                history_count: 0,
            }],
        }
    );

    let recycle = load_fixture(&core, FIXTURE_RECYCLE_BIN_WITH_DATA, "123");
    let recycle_group = find_group_by_path(&recycle.root, &["Recycle Bin"]).expect("recycle bin");
    let recycle_entry =
        find_entry_in_group(recycle_group, "Obsolete e-mail").expect("recycle bin entry");
    assert_eq!(
        collect_query_digest(
            &core,
            &recycle,
            &recycle_group.id.to_string(),
            &recycle_entry.id.to_string(),
            "Obsolete e-mail"
        ),
        QueryOracleDigest {
            group: GroupLookupDigest {
                id: recycle_group.id.to_string(),
                title: "Recycle Bin".into(),
                entry_count: 2,
                child_count: 2,
            },
            entry: EntryLookupDigest {
                id: recycle_entry.id.to_string(),
                title: "Obsolete e-mail".into(),
                username: "olduser@mail.ru".into(),
                url: "http://mail.ru".into(),
                attachment_count: 0,
                history_count: 1,
                has_totp: false,
                has_passkey: false,
            },
            search: vec![SearchMatchDigest {
                entry_id: recycle_entry.id.to_string(),
                title: "Obsolete e-mail".into(),
                username: "olduser@mail.ru".into(),
                group_id: recycle_group.id.to_string(),
                group_path: vec!["Root".into(), "Recycle Bin".into()],
                attachment_count: 0,
                history_count: 1,
            }],
        }
    );
}

#[test]
fn external_stable_query_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password, group_path, entry_title, search_term) in [
        (
            FIXTURE_NEW_DATABASE_BROWSER,
            "a",
            vec!["Homebanking", "Subgroup"],
            "Subgroup Entry",
            "Important note",
        ),
        (
            FIXTURE_SYNC_DATABASE,
            "a",
            vec!["Homebanking", "Subgroup"],
            "Subgroup Entry",
            "Important note",
        ),
        (
            FIXTURE_MERGE_DATABASE,
            "a",
            vec!["TestExtraGroup"],
            "b",
            "pc",
        ),
        (
            FIXTURE_RECYCLE_BIN_WITH_DATA,
            "123",
            vec!["Recycle Bin"],
            "Obsolete e-mail",
            "Obsolete e-mail",
        ),
    ] {
        let loaded = load_fixture(&core, fixture, password);
        let group = find_group_by_path(&loaded.root, &group_path).expect("roundtrip group");
        let entry = find_entry_in_group(group, entry_title).expect("roundtrip entry");
        let before = collect_query_digest(
            &core,
            &loaded,
            &group.id.to_string(),
            &entry.id.to_string(),
            search_term,
        );

        let mut key = CompositeKey::default();
        key.add_password(password);
        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite query fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload query fixture");
        let group = find_group_by_path(&reloaded.root, &group_path).expect("reloaded group");
        let entry = find_entry_in_group(group, entry_title).expect("reloaded entry");
        let after = collect_query_digest(
            &core,
            &reloaded,
            &group.id.to_string(),
            &entry.id.to_string(),
            search_term,
        );

        assert_eq!(after, before);
    }
}

fn collect_query_digest(
    core: &KeepassCore,
    vault: &Vault,
    group_id: &str,
    entry_id: &str,
    search_term: &str,
) -> QueryOracleDigest {
    let group = core
        .find_group_view_by_id(vault, group_id)
        .expect("query group view by id");
    let entry = core
        .find_entry_view_by_id(vault, entry_id)
        .expect("query entry view by id");
    let search = core
        .search_entries_view(vault, search_term)
        .into_iter()
        .map(|item| SearchMatchDigest {
            entry_id: item.entry.id,
            title: item.entry.title,
            username: item.entry.username,
            group_id: item.group_id,
            group_path: item.group_path,
            attachment_count: item.entry.attachment_count,
            history_count: item.entry.history_count,
        })
        .collect::<Vec<_>>();

    QueryOracleDigest {
        group: summarize_group(&group),
        entry: summarize_entry(&entry),
        search,
    }
}

fn summarize_group(group: &GroupView) -> GroupLookupDigest {
    GroupLookupDigest {
        id: group.id.clone(),
        title: group.title.clone(),
        entry_count: group.entry_count,
        child_count: group.child_count,
    }
}

fn summarize_entry(entry: &EntryView) -> EntryLookupDigest {
    EntryLookupDigest {
        id: entry.id.clone(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        url: entry.url.clone(),
        attachment_count: entry.attachment_count,
        history_count: entry.history_count,
        has_totp: entry.has_totp,
        has_passkey: entry.has_passkey,
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}

fn find_group_by_path<'a>(
    root: &'a vaultkern_core::Group,
    path: &[&str],
) -> Option<&'a vaultkern_core::Group> {
    let mut current = root;
    for segment in path {
        current = current
            .children
            .iter()
            .find(|group| group.title == *segment)?;
    }
    Some(current)
}

fn find_entry_in_group<'a>(
    group: &'a vaultkern_core::Group,
    title: &str,
) -> Option<&'a vaultkern_core::Entry> {
    group.entries.iter().find(|entry| entry.title == title)
}
