#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, KdbxVersion, KeepassCore, SaveProfile};

const FIXTURE_KEY_FILE_PROTECTED_DB: &[u8] =
    include_bytes!("../../../fixtures/kdbx/KeyFileProtected.kdbx");
const FIXTURE_KEY_FILE_PROTECTED: &[u8] =
    include_bytes!("../../../fixtures/kdbx/KeyFileProtected.key");
const FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB: &[u8] =
    include_bytes!("../../../fixtures/kdbx/KeyFileProtectedNoPassword.kdbx");
const FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD: &[u8] =
    include_bytes!("../../../fixtures/kdbx/KeyFileProtectedNoPassword.key");

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyFileProtectedDigest {
    header_version: KdbxVersion,
    entry_rows: Vec<EntryRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryRow {
    title: String,
    username: String,
    password: String,
    created_at: u64,
    expiry_time: Option<i64>,
    icon_id: Option<u32>,
    usage_count: Option<u64>,
    protection: (bool, bool, bool, bool, bool),
    auto_type: (Option<bool>, Option<i32>, usize),
}

#[test]
fn external_key_file_protected_fixtures_expose_oracle() {
    let core = KeepassCore::new();

    assert_eq!(
        load_password_and_key_digest(&core),
        KeyFileProtectedDigest {
            header_version: KdbxVersion::V4_0,
            entry_rows: vec![
                entry_row("entry1", 1_550_181_928),
                entry_row("entry2", 1_550_181_945),
            ],
        }
    );

    assert_eq!(
        load_key_only_digest(&core),
        KeyFileProtectedDigest {
            header_version: KdbxVersion::V4_0,
            entry_rows: vec![
                entry_row("entry1", 1_550_343_234),
                entry_row("entry2", 1_550_343_246),
            ],
        }
    );
}

#[test]
fn external_key_file_protected_fixtures_preserve_semantics_on_roundtrip() {
    let core = KeepassCore::new();

    let password_and_key_before = load_password_and_key_digest(&core);
    let password_and_key_after = rewrite_password_and_key_and_collect(
        &core,
        FIXTURE_KEY_FILE_PROTECTED_DB,
        "a",
        FIXTURE_KEY_FILE_PROTECTED,
    );
    assert_eq!(
        password_and_key_after,
        KeyFileProtectedDigest {
            header_version: KdbxVersion::V4_1,
            entry_rows: password_and_key_before.entry_rows,
        }
    );

    let key_only_before = load_key_only_digest(&core);
    let key_only_after = rewrite_key_only_and_collect(
        &core,
        FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB,
        FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD,
    );
    assert_eq!(
        key_only_after,
        KeyFileProtectedDigest {
            header_version: KdbxVersion::V4_1,
            entry_rows: key_only_before.entry_rows,
        }
    );
}

fn load_password_and_key_digest(core: &KeepassCore) -> KeyFileProtectedDigest {
    let mut key = CompositeKey::default();
    key.add_password("a");
    key.add_key_file_content(FIXTURE_KEY_FILE_PROTECTED)
        .expect("password+key key file");

    load_digest(core, FIXTURE_KEY_FILE_PROTECTED_DB, &key)
}

fn load_key_only_digest(core: &KeepassCore) -> KeyFileProtectedDigest {
    let mut key = CompositeKey::default();
    key.add_key_file_content(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD)
        .expect("key-only key file");

    load_digest(core, FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB, &key)
}

fn rewrite_password_and_key_and_collect(
    core: &KeepassCore,
    bytes: &[u8],
    password: &str,
    key_file: &[u8],
) -> KeyFileProtectedDigest {
    let mut key = CompositeKey::default();
    key.add_password(password);
    key.add_key_file_content(key_file)
        .expect("password+key key file");

    rewrite_and_collect(core, bytes, &key)
}

fn rewrite_key_only_and_collect(
    core: &KeepassCore,
    bytes: &[u8],
    key_file: &[u8],
) -> KeyFileProtectedDigest {
    let mut key = CompositeKey::default();
    key.add_key_file_content(key_file)
        .expect("key-only key file");

    rewrite_and_collect(core, bytes, &key)
}

fn rewrite_and_collect(
    core: &KeepassCore,
    bytes: &[u8],
    key: &CompositeKey,
) -> KeyFileProtectedDigest {
    let loaded = core.load_kdbx(bytes, key).expect("load key-file fixture");
    let rewritten = core
        .save_kdbx(&loaded, key, SaveProfile::recommended())
        .expect("rewrite key-file fixture");
    load_digest(core, &rewritten, key)
}

fn load_digest(core: &KeepassCore, bytes: &[u8], key: &CompositeKey) -> KeyFileProtectedDigest {
    let loaded = core
        .load_database(bytes, key)
        .expect("load key-file protected database");
    let entry_rows = loaded.vault.root.entries.iter().map(entry_to_row).collect();

    KeyFileProtectedDigest {
        header_version: loaded.inspection.header.version,
        entry_rows,
    }
}

fn entry_row(title: &str, created_at: u64) -> EntryRow {
    EntryRow {
        title: title.into(),
        username: "username".into(),
        password: "password".into(),
        created_at,
        expiry_time: Some(created_at as i64),
        icon_id: Some(0),
        usage_count: Some(0),
        protection: (false, false, true, false, false),
        auto_type: (Some(true), Some(0), 0),
    }
}

fn entry_to_row(entry: &vaultkern_core::Entry) -> EntryRow {
    EntryRow {
        title: entry.title.clone(),
        username: entry.username.clone(),
        password: entry.password.clone(),
        created_at: entry.created_at,
        expiry_time: entry.expiry_time,
        icon_id: entry.icon_id,
        usage_count: entry.usage_count,
        protection: (
            entry.field_protection.protect_title,
            entry.field_protection.protect_username,
            entry.field_protection.protect_password,
            entry.field_protection.protect_url,
            entry.field_protection.protect_notes,
        ),
        auto_type: (
            entry.auto_type.as_ref().and_then(|value| value.enabled),
            entry.auto_type.as_ref().and_then(|value| value.obfuscation),
            entry
                .auto_type
                .as_ref()
                .map(|value| value.associations.len())
                .unwrap_or(0),
        ),
    }
}
