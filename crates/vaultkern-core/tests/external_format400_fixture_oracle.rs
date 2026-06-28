#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, KdbxCipher, KdbxVersion, KeepassCore, LoadWarning, SaveProfile,
};

const FIXTURE_FORMAT400: &[u8] = include_bytes!("../../../fixtures/kdbx/Format400.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct Format400Digest {
    inspection: (KdbxVersion, KdbxCipher, KdbxVersion, Vec<LoadWarning>),
    summary: (String, String, usize, usize, usize, usize, usize),
    database: (
        String,
        Option<i64>,
        (bool, bool, bool, bool, bool),
        usize,
        usize,
    ),
    root: (String, Option<u32>, Option<bool>, usize, usize),
    entry: EntryDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryDigest {
    title: String,
    username: String,
    password: String,
    icon_id: Option<u32>,
    usage_count: Option<u64>,
    history_count: usize,
    protection: (bool, bool, bool, bool, bool),
    auto_type: (Option<bool>, Option<i32>),
    protected_field: Option<(String, bool)>,
    attachment: Option<(String, usize, bool)>,
}

#[test]
fn external_format400_fixture_exposes_rich_oracle() {
    let core = KeepassCore::new();

    let digest = load_format400_digest(&core, FIXTURE_FORMAT400, "t");
    assert_eq!(
        digest,
        Format400Digest {
            inspection: (
                KdbxVersion::V4_0,
                KdbxCipher::ChaCha20,
                KdbxVersion::V4_1,
                vec![LoadWarning::SaveWillUpgradeToV4_1],
            ),
            summary: ("Format400".into(), "Format400".into(), 1, 1, 1, 10, 0),
            database: (
                "Format400".into(),
                Some(1_489_501_066),
                (false, false, true, false, false),
                10,
                1,
            ),
            root: ("Format400".into(), Some(49), Some(true), 1, 0),
            entry: EntryDigest {
                title: "Format400".into(),
                username: "Format400".into(),
                password: "Format400".into(),
                icon_id: Some(0),
                usage_count: Some(1),
                history_count: 0,
                protection: (false, false, true, false, false),
                auto_type: (Some(true), Some(0)),
                protected_field: Some(("Format400".into(), true)),
                attachment: Some(("Format400".into(), "Format400\n".len(), false)),
            },
        }
    );
}

#[test]
fn external_format400_fixture_preserves_rich_semantics_on_roundtrip() {
    let core = KeepassCore::new();
    let before = load_format400_digest(&core, FIXTURE_FORMAT400, "t");

    let mut key = CompositeKey::default();
    key.add_password("t");
    let loaded = core
        .load_kdbx(FIXTURE_FORMAT400, &key)
        .expect("load format400 fixture");
    let rewritten = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("rewrite format400 fixture");
    let after = load_format400_digest(&core, &rewritten, "t");

    assert_eq!(
        after.inspection,
        (
            KdbxVersion::V4_1,
            KdbxCipher::Aes256,
            KdbxVersion::V4_1,
            Vec::new()
        )
    );
    assert_eq!(after.summary, before.summary);
    assert_eq!(
        after.database,
        (
            before.database.0,
            before.database.1,
            before.database.2,
            before.database.3,
            2,
        )
    );
    assert_eq!(after.root, before.root);
    assert_eq!(after.entry, before.entry);
}

fn load_format400_digest(core: &KeepassCore, bytes: &[u8], password: &str) -> Format400Digest {
    let mut key = CompositeKey::default();
    key.add_password(password);

    let loaded = core
        .load_database(bytes, &key)
        .expect("load format400 database");
    let vault = &loaded.vault;
    let entry = vault.root.entries.first().expect("format400 root entry");

    Format400Digest {
        inspection: (
            loaded.inspection.header.version,
            loaded.inspection.header.cipher,
            loaded.inspection.save_target_version,
            loaded.inspection.warnings,
        ),
        summary: (
            loaded.summary.name,
            loaded.summary.root_title,
            loaded.summary.groups,
            loaded.summary.entries,
            loaded.summary.attachments,
            loaded.summary.deleted_objects,
            loaded.summary.custom_data_items,
        ),
        database: (
            vault.name.clone(),
            vault.database_name_changed,
            (
                vault
                    .memory_protection
                    .as_ref()
                    .map(|value| value.protect_title)
                    .unwrap_or(false),
                vault
                    .memory_protection
                    .as_ref()
                    .map(|value| value.protect_username)
                    .unwrap_or(false),
                vault
                    .memory_protection
                    .as_ref()
                    .map(|value| value.protect_password)
                    .unwrap_or(false),
                vault
                    .memory_protection
                    .as_ref()
                    .map(|value| value.protect_url)
                    .unwrap_or(false),
                vault
                    .memory_protection
                    .as_ref()
                    .map(|value| value.protect_notes)
                    .unwrap_or(false),
            ),
            vault.deleted_objects.len(),
            vault.meta_opaque_xml.len(),
        ),
        root: (
            vault.root.title.clone(),
            vault.root.icon_id,
            vault.root.flags.is_expanded,
            vault.root.entries.len(),
            vault.root.children.len(),
        ),
        entry: EntryDigest {
            title: entry.title.clone(),
            username: entry.username.clone(),
            password: entry.password.clone(),
            icon_id: entry.icon_id,
            usage_count: entry.usage_count,
            history_count: entry.history.len(),
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
            ),
            protected_field: entry
                .attributes
                .get("Format400")
                .map(|field| (field.value.clone(), field.protected)),
            attachment: entry.attachments.get("Format400").map(|attachment| {
                (
                    "Format400".into(),
                    attachment.data.len(),
                    attachment.protect_in_memory,
                )
            }),
        },
    }
}
