#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, Compression, KdbxCipher, KdbxVersion, KeepassCore, LoadWarning, SaveProfile,
};

const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");
const FIXTURE_PROTECTED_STRINGS: &[u8] =
    include_bytes!("../../../fixtures/kdbx/ProtectedStrings.kdbx");
const FIXTURE_NON_ASCII: &[u8] = include_bytes!("../../../fixtures/kdbx/NonAscii.kdbx");
const FIXTURE_COMPRESSED: &[u8] = include_bytes!("../../../fixtures/kdbx/Compressed.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyRichFixtureDigest {
    inspection: (
        KdbxVersion,
        KdbxCipher,
        Compression,
        KdbxVersion,
        Vec<LoadWarning>,
    ),
    database: (
        String,
        Option<String>,
        Option<i64>,
        Option<i32>,
        Option<i64>,
        (bool, bool, bool, bool, bool),
        usize,
        Option<i64>,
        Option<bool>,
        bool,
        Option<i64>,
        Option<i64>,
    ),
    root: (
        String,
        Option<u32>,
        Option<bool>,
        usize,
        Vec<String>,
        Option<bool>,
    ),
    entry: EntryRichDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryRichDigest {
    detail: (
        String,
        String,
        String,
        String,
        String,
        Option<u32>,
        Option<u64>,
        usize,
        bool,
    ),
    protection: (bool, bool, bool, bool, bool),
    auto_type: (Option<bool>, Option<i32>, usize),
    custom_fields: Vec<(String, String, bool)>,
    history: Vec<HistoryRichDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryRichDigest {
    detail: (String, String, String, String, String, Option<u64>),
    protection: (bool, bool, bool, bool, bool),
    auto_type: (Option<bool>, Option<i32>, usize),
    custom_fields: Vec<(String, String, bool)>,
}

#[test]
fn external_legacy_fixtures_expose_rich_oracle() {
    let core = KeepassCore::new();

    assert_eq!(
        load_legacy_digest(&core, FIXTURE_FORMAT300, "a"),
        LegacyRichFixtureDigest {
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
            database: (
                "Test Database Format 0x00030000".into(),
                Some("KeePass".into()),
                Some(1_348_590_987),
                Some(10),
                Some(6_291_456),
                (false, false, true, false, false),
                2,
                Some(1_348_590_997),
                Some(true),
                true,
                Some(1_348_590_935),
                Some(1_348_590_935),
            ),
            root: (
                "Format300".into(),
                Some(49),
                Some(true),
                1,
                vec![
                    "General".into(),
                    "Windows".into(),
                    "Network".into(),
                    "Internet".into(),
                    "eMail".into(),
                    "Homebanking".into(),
                ],
                Some(true),
            ),
            entry: EntryRichDigest {
                detail: (
                    "Sample Entry".into(),
                    "User Name".into(),
                    "Password".into(),
                    "http://www.somesite.com/".into(),
                    "Notes".into(),
                    Some(0),
                    Some(0),
                    0,
                    false,
                ),
                protection: (false, false, true, false, false),
                auto_type: (Some(true), Some(0), 1),
                custom_fields: Vec::new(),
                history: Vec::new(),
            },
        }
    );

    assert_eq!(
        load_legacy_digest(&core, FIXTURE_PROTECTED_STRINGS, "masterpw"),
        LegacyRichFixtureDigest {
            inspection: (
                KdbxVersion::V3_1,
                KdbxCipher::Aes256,
                Compression::Gzip,
                KdbxVersion::V4_1,
                vec![
                    LoadWarning::LegacyFormat(KdbxVersion::V3_1),
                    LoadWarning::SaveWillUpgradeToV4_1,
                ],
            ),
            database: (
                "Protected Strings Test".into(),
                Some("KeePass".into()),
                Some(1_309_365_789),
                Some(10),
                Some(6_291_456),
                (false, false, true, false, false),
                1,
                Some(1_309_365_817),
                Some(true),
                false,
                Some(1_309_366_154),
                Some(1_309_365_718),
            ),
            root: (
                "Protected".into(),
                Some(49),
                Some(true),
                1,
                Vec::new(),
                Some(true),
            ),
            entry: EntryRichDigest {
                detail: (
                    "Sample Entry".into(),
                    "Protected User Name".into(),
                    "ProtectedPassword".into(),
                    "http://www.somesite.com/".into(),
                    "Notes".into(),
                    Some(0),
                    Some(4),
                    1,
                    false,
                ),
                protection: (false, false, true, false, false),
                auto_type: (Some(true), Some(0), 1),
                custom_fields: vec![
                    ("TestProtected".into(), "ABC".into(), true),
                    ("TestUnprotected".into(), "DEF".into(), false),
                ],
                history: vec![HistoryRichDigest {
                    detail: (
                        "Sample Entry".into(),
                        "Protected User Name".into(),
                        "ProtectedPassword".into(),
                        "http://www.somesite.com/".into(),
                        "Notes".into(),
                        Some(2),
                    ),
                    protection: (false, false, true, false, false),
                    auto_type: (Some(true), Some(0), 1),
                    custom_fields: vec![
                        ("TestProtected".into(), "ABC".into(), true),
                        ("TestUnprotected".into(), "DEF".into(), false),
                    ],
                }],
            },
        }
    );

    assert_eq!(
        load_legacy_digest(&core, FIXTURE_NON_ASCII, "Δöض"),
        LegacyRichFixtureDigest {
            inspection: (
                KdbxVersion::V3_1,
                KdbxCipher::Aes256,
                Compression::None,
                KdbxVersion::V4_1,
                vec![
                    LoadWarning::LegacyFormat(KdbxVersion::V3_1),
                    LoadWarning::SaveWillUpgradeToV4_1,
                ],
            ),
            database: (
                "NonAsciiTest".into(),
                Some("KeePass".into()),
                Some(1_284_927_373),
                Some(10),
                Some(6_291_456),
                (false, false, true, false, false),
                1,
                Some(1_284_927_398),
                Some(true),
                false,
                Some(1_284_933_314),
                Some(1_284_927_220),
            ),
            root: (
                "EmptyPassword".into(),
                Some(49),
                Some(true),
                1,
                Vec::new(),
                None,
            ),
            entry: EntryRichDigest {
                detail: (
                    "秘密".into(),
                    "".into(),
                    "🚗🐎🔋📎".into(),
                    "".into(),
                    "".into(),
                    Some(49),
                    Some(0),
                    0,
                    false,
                ),
                protection: (false, false, true, false, false),
                auto_type: (Some(true), Some(0), 0),
                custom_fields: Vec::new(),
                history: Vec::new(),
            },
        }
    );

    assert_eq!(
        load_legacy_digest(&core, FIXTURE_COMPRESSED, ""),
        LegacyRichFixtureDigest {
            inspection: (
                KdbxVersion::V3_1,
                KdbxCipher::Aes256,
                Compression::Gzip,
                KdbxVersion::V4_1,
                vec![
                    LoadWarning::LegacyFormat(KdbxVersion::V3_1),
                    LoadWarning::SaveWillUpgradeToV4_1,
                ],
            ),
            database: (
                "Compressed".into(),
                Some("KeePass".into()),
                Some(1_285_268_778),
                Some(10),
                Some(6_291_456),
                (false, false, true, false, false),
                0,
                None,
                Some(true),
                false,
                Some(1_285_268_774),
                Some(1_285_268_774),
            ),
            root: (
                "Compressed".into(),
                Some(49),
                Some(true),
                1,
                vec![
                    "General".into(),
                    "Windows".into(),
                    "Network".into(),
                    "Internet".into(),
                    "eMail".into(),
                    "Homebanking".into(),
                ],
                Some(true),
            ),
            entry: EntryRichDigest {
                detail: (
                    "Sample Entry".into(),
                    "User Name".into(),
                    "Password".into(),
                    "http://www.somesite.com/".into(),
                    "Notes".into(),
                    Some(0),
                    Some(0),
                    0,
                    false,
                ),
                protection: (false, false, true, false, false),
                auto_type: (Some(true), Some(0), 1),
                custom_fields: Vec::new(),
                history: Vec::new(),
            },
        }
    );
}

#[test]
fn external_legacy_fixtures_preserve_rich_semantics_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_FORMAT300, "a"),
        (FIXTURE_PROTECTED_STRINGS, "masterpw"),
        (FIXTURE_NON_ASCII, "Δöض"),
        (FIXTURE_COMPRESSED, ""),
    ] {
        let before = load_legacy_digest(&core, fixture, password);

        let mut key = CompositeKey::default();
        key.add_password(password);
        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load legacy rich fixture");
        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite legacy rich fixture");
        let after = load_legacy_digest(&core, &rewritten, password);

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
        assert_eq!(after.database, before.database);
        assert_eq!(after.root, before.root);
        assert_eq!(after.entry, before.entry);
    }
}

fn load_legacy_digest(core: &KeepassCore, bytes: &[u8], password: &str) -> LegacyRichFixtureDigest {
    let mut key = CompositeKey::default();
    key.add_password(password);

    let loaded = core
        .load_database(bytes, &key)
        .expect("load legacy rich database");
    let vault = &loaded.vault;
    let entry = vault.root.entries.first().expect("root entry");

    LegacyRichFixtureDigest {
        inspection: (
            loaded.inspection.header.version,
            loaded.inspection.header.cipher,
            loaded.inspection.header.compression,
            loaded.inspection.save_target_version,
            loaded.inspection.warnings,
        ),
        database: (
            vault.name.clone(),
            vault.generator.clone(),
            vault.database_name_changed,
            vault.history_max_items,
            vault.history_max_size,
            protect_tuple(vault.memory_protection.as_ref()),
            vault.deleted_objects.len(),
            vault.deleted_objects.first().map(|item| item.deleted_at),
            vault.recycle_bin_enabled,
            vault.recycle_bin_group.is_some(),
            vault.recycle_bin_changed,
            vault.entry_templates_group_changed,
        ),
        root: (
            vault.root.title.clone(),
            vault.root.icon_id,
            vault.root.flags.is_expanded,
            vault.root.entries.len(),
            vault
                .root
                .children
                .iter()
                .map(|group| group.title.clone())
                .collect(),
            vault
                .root
                .last_top_visible_entry
                .map(|id| id == vault.root.entries[0].id),
        ),
        entry: EntryRichDigest {
            detail: (
                entry.title.clone(),
                entry.username.clone(),
                entry.password.clone(),
                entry.url.clone(),
                entry.notes.clone(),
                entry.icon_id,
                entry.usage_count,
                entry.history.len(),
                entry.expires,
            ),
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
            custom_fields: entry
                .attributes
                .iter()
                .filter(|(key, _)| key.starts_with("Test"))
                .map(|(key, field)| (key.clone(), field.value.clone(), field.protected))
                .collect(),
            history: entry
                .history
                .iter()
                .map(|history| HistoryRichDigest {
                    detail: (
                        history.title.clone(),
                        history.username.clone(),
                        history.password.clone(),
                        history.url.clone(),
                        history.notes.clone(),
                        history.usage_count,
                    ),
                    protection: (
                        history.field_protection.protect_title,
                        history.field_protection.protect_username,
                        history.field_protection.protect_password,
                        history.field_protection.protect_url,
                        history.field_protection.protect_notes,
                    ),
                    auto_type: (
                        history.auto_type.as_ref().and_then(|value| value.enabled),
                        history
                            .auto_type
                            .as_ref()
                            .and_then(|value| value.obfuscation),
                        history
                            .auto_type
                            .as_ref()
                            .map(|value| value.associations.len())
                            .unwrap_or(0),
                    ),
                    custom_fields: history
                        .attributes
                        .iter()
                        .filter(|(key, _)| key.starts_with("Test"))
                        .map(|(key, field)| (key.clone(), field.value.clone(), field.protected))
                        .collect(),
                })
                .collect(),
        },
    }
}

fn protect_tuple(
    value: Option<&vaultkern_core::MemoryProtection>,
) -> (bool, bool, bool, bool, bool) {
    (
        value.map(|item| item.protect_title).unwrap_or(false),
        value.map(|item| item.protect_username).unwrap_or(false),
        value.map(|item| item.protect_password).unwrap_or(false),
        value.map(|item| item.protect_url).unwrap_or(false),
        value.map(|item| item.protect_notes).unwrap_or(false),
    )
}
