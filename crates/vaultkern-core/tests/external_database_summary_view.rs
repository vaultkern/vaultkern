#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, Compression, KdbxCipher, KdbxVersion, KeepassCore, LoadWarning, SaveProfile,
};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_RECYCLE_BIN_WITH_DATA: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinWithData.kdbx");
const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseSummaryViewDigest {
    summary: (String, String, usize, usize, usize, usize, usize),
    inspection: (
        KdbxVersion,
        KdbxCipher,
        Compression,
        KdbxVersion,
        Vec<LoadWarning>,
    ),
    deleted_objects: usize,
    recycle_bin_enabled: Option<bool>,
    recycle_bin_group_title: Option<String>,
    root_lines: Vec<String>,
}

#[test]
fn external_fixtures_expose_database_summary_view_oracle() {
    let core = KeepassCore::new();

    assert_eq!(
        load_summary_view_digest(&core, FIXTURE_FORMAT300, "a"),
        DatabaseSummaryViewDigest {
            summary: (
                "Test Database Format 0x00030000".into(),
                "Format300".into(),
                7,
                1,
                0,
                2,
                0,
            ),
            inspection: (
                KdbxVersion::V3_0,
                KdbxCipher::Aes256,
                Compression::Gzip,
                KdbxVersion::V4_1,
                vec![
                    LoadWarning::LegacyFormat(KdbxVersion::V3_0),
                    LoadWarning::SaveWillUpgradeToV4_1,
                ],
            ),
            deleted_objects: 2,
            recycle_bin_enabled: Some(true),
            recycle_bin_group_title: None,
            root_lines: vec![
                "G|Format300|entries=1|children=6".into(),
                "E|Format300/Sample Entry|user=User Name|url=http://www.somesite.com/|att=0|custom=0|hist=0|totp=false|passkey=false".into(),
                "G|Format300/General|entries=0|children=0".into(),
                "G|Format300/Windows|entries=0|children=0".into(),
                "G|Format300/Network|entries=0|children=0".into(),
                "G|Format300/Internet|entries=0|children=0".into(),
                "G|Format300/eMail|entries=0|children=0".into(),
                "G|Format300/Homebanking|entries=0|children=0".into(),
            ],
        }
    );

    assert_eq!(
        load_summary_view_digest(&core, FIXTURE_NEW_DATABASE_BROWSER, "a"),
        DatabaseSummaryViewDigest {
            summary: (
                "".into(),
                "NewDatabase".into(),
                9,
                2,
                0,
                2,
                5,
            ),
            inspection: (
                KdbxVersion::V4_0,
                KdbxCipher::Aes256,
                Compression::None,
                KdbxVersion::V4_1,
                vec![LoadWarning::SaveWillUpgradeToV4_1],
            ),
            deleted_objects: 2,
            recycle_bin_enabled: Some(true),
            recycle_bin_group_title: None,
            root_lines: vec![
                "G|NewDatabase|entries=1|children=6".into(),
                "E|NewDatabase/Sample Entry|user=User Name|url=https://github.com/login|att=0|custom=2|hist=3|totp=false|passkey=false".into(),
                "G|NewDatabase/General|entries=0|children=1".into(),
                "G|NewDatabase/General/SubGroup|entries=0|children=0".into(),
                "G|NewDatabase/Windows|entries=0|children=0".into(),
                "G|NewDatabase/Network|entries=0|children=0".into(),
                "G|NewDatabase/Internet|entries=0|children=0".into(),
                "G|NewDatabase/eMail|entries=0|children=0".into(),
                "G|NewDatabase/Homebanking|entries=0|children=1".into(),
                "G|NewDatabase/Homebanking/Subgroup|entries=1|children=0".into(),
                "E|NewDatabase/Homebanking/Subgroup/Subgroup Entry|user=Bank User Name|url=https:/www.bank.com|att=0|custom=0|hist=1|totp=false|passkey=false".into(),
            ],
        }
    );
}

#[test]
fn external_database_summary_view_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_SYNC_DATABASE, "a"),
        (FIXTURE_RECYCLE_BIN_WITH_DATA, "123"),
        (FIXTURE_FORMAT300, "a"),
    ] {
        let before = load_summary_view_digest(&core, fixture, password);

        let mut key = CompositeKey::default();
        key.add_password(password);
        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load summary/view fixture");
        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite summary/view fixture");
        let after = load_summary_view_digest(&core, &rewritten, password);

        assert_eq!(
            summary_view_semantics(&after),
            summary_view_semantics(&before)
        );
        assert_eq!(
            after.inspection,
            (
                KdbxVersion::V4_1,
                KdbxCipher::Aes256,
                Compression::Gzip,
                KdbxVersion::V4_1,
                Vec::new(),
            )
        );
    }
}

fn load_summary_view_digest(
    core: &KeepassCore,
    bytes: &[u8],
    password: &str,
) -> DatabaseSummaryViewDigest {
    let mut key = CompositeKey::default();
    key.add_password(password);

    let loaded = core
        .load_database(bytes, &key)
        .expect("load database summary/inspection");
    let view = core
        .load_database_view(bytes, &key)
        .expect("load database view");

    assert_eq!(view.database.summary, loaded.summary);
    assert_eq!(view.inspection, loaded.inspection);

    let recycle_bin_group_title = view
        .database
        .recycle_bin_group_id
        .as_deref()
        .and_then(|id| find_group_title_by_id(&view.database.root, id));

    DatabaseSummaryViewDigest {
        summary: (
            loaded.summary.name,
            loaded.summary.root_title,
            loaded.summary.groups,
            loaded.summary.entries,
            loaded.summary.attachments,
            loaded.summary.deleted_objects,
            loaded.summary.custom_data_items,
        ),
        inspection: (
            loaded.inspection.header.version,
            loaded.inspection.header.cipher,
            loaded.inspection.header.compression,
            loaded.inspection.save_target_version,
            loaded.inspection.warnings,
        ),
        deleted_objects: view.database.deleted_objects,
        recycle_bin_enabled: view.database.recycle_bin_enabled,
        recycle_bin_group_title,
        root_lines: summarize_group_view(&view.database.root, ""),
    }
}

fn summarize_group_view(group: &vaultkern_core::GroupView, path: &str) -> Vec<String> {
    let current = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };

    let mut rows = vec![format!(
        "G|{current}|entries={}|children={}",
        group.entry_count, group.child_count
    )];

    for entry in &group.entries {
        rows.push(format!(
            "E|{current}/{}|user={}|url={}|att={}|custom={}|hist={}|totp={}|passkey={}",
            entry.title,
            entry.username,
            entry.url,
            entry.attachment_count,
            entry.custom_field_count,
            entry.history_count,
            entry.has_totp,
            entry.has_passkey
        ));
    }

    for child in &group.children {
        rows.extend(summarize_group_view(child, &current));
    }

    rows
}

fn find_group_title_by_id(group: &vaultkern_core::GroupView, id: &str) -> Option<String> {
    if group.id == id {
        return Some(group.title.clone());
    }
    for child in &group.children {
        if let Some(found) = find_group_title_by_id(child, id) {
            return Some(found);
        }
    }
    None
}

fn summary_view_semantics(
    digest: &DatabaseSummaryViewDigest,
) -> (
    (String, String, usize, usize, usize, usize, usize),
    usize,
    Option<bool>,
    Option<String>,
    Vec<String>,
) {
    (
        digest.summary.clone(),
        digest.deleted_objects,
        digest.recycle_bin_enabled,
        digest.recycle_bin_group_title.clone(),
        digest.root_lines.clone(),
    )
}
