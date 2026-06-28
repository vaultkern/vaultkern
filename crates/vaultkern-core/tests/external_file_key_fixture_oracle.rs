#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, KdbxVersion, KeepassCore, SaveProfile};

const FIXTURE_FILE_KEY_BINARY_DB: &[u8] =
    include_bytes!("../../../fixtures/kdbx/FileKeyBinary.kdbx");
const FIXTURE_FILE_KEY_BINARY: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyBinary.key");
const FIXTURE_FILE_KEY_HEX_DB: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyHex.kdbx");
const FIXTURE_FILE_KEY_HEX: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyHex.key");
const FIXTURE_FILE_KEY_HASHED_DB: &[u8] =
    include_bytes!("../../../fixtures/kdbx/FileKeyHashed.kdbx");
const FIXTURE_FILE_KEY_HASHED: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyHashed.key");
const FIXTURE_FILE_KEY_XML_DB: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyXml.kdbx");
const FIXTURE_FILE_KEY_XML: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyXml.key");
const FIXTURE_FILE_KEY_XML_V2_DB: &[u8] =
    include_bytes!("../../../fixtures/kdbx/FileKeyXmlV2.kdbx");
const FIXTURE_FILE_KEY_XML_V2: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyXmlV2.keyx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileKeyFixtureDigest {
    header_version: KdbxVersion,
    name: String,
    root_title: String,
    child_titles: Vec<String>,
}

#[test]
fn external_file_key_fixtures_expose_oracle() {
    let core = KeepassCore::new();

    assert_eq!(
        load_file_key_digest(&core, FIXTURE_FILE_KEY_BINARY_DB, FIXTURE_FILE_KEY_BINARY),
        FileKeyFixtureDigest {
            header_version: KdbxVersion::V2_0,
            name: "FileKeyBinary Database".into(),
            root_title: "FileKeyBinary".into(),
            child_titles: default_child_titles(),
        }
    );
    assert_eq!(
        load_file_key_digest(&core, FIXTURE_FILE_KEY_HEX_DB, FIXTURE_FILE_KEY_HEX),
        FileKeyFixtureDigest {
            header_version: KdbxVersion::V2_0,
            name: "FileKeyHex Database".into(),
            root_title: "FileKeyHex".into(),
            child_titles: default_child_titles(),
        }
    );
    assert_eq!(
        load_file_key_digest(&core, FIXTURE_FILE_KEY_HASHED_DB, FIXTURE_FILE_KEY_HASHED),
        FileKeyFixtureDigest {
            header_version: KdbxVersion::V2_0,
            name: "FileKeyHashed Database".into(),
            root_title: "FileKeyHashed".into(),
            child_titles: default_child_titles(),
        }
    );
    assert_eq!(
        load_file_key_digest(&core, FIXTURE_FILE_KEY_XML_DB, FIXTURE_FILE_KEY_XML),
        FileKeyFixtureDigest {
            header_version: KdbxVersion::V2_0,
            name: "FileKeyXml Database".into(),
            root_title: "FileKeyXml".into(),
            child_titles: default_child_titles(),
        }
    );
    assert_eq!(
        load_file_key_digest(&core, FIXTURE_FILE_KEY_XML_V2_DB, FIXTURE_FILE_KEY_XML_V2),
        FileKeyFixtureDigest {
            header_version: KdbxVersion::V3_1,
            name: "FileKeyXmlV2 Database".into(),
            root_title: "Database".into(),
            child_titles: default_child_titles(),
        }
    );
}

#[test]
fn external_file_key_fixtures_preserve_semantics_on_roundtrip() {
    let core = KeepassCore::new();

    for (db_bytes, key_file, expected_name, expected_root_title) in [
        (
            FIXTURE_FILE_KEY_BINARY_DB,
            FIXTURE_FILE_KEY_BINARY,
            "FileKeyBinary Database",
            "FileKeyBinary",
        ),
        (
            FIXTURE_FILE_KEY_HEX_DB,
            FIXTURE_FILE_KEY_HEX,
            "FileKeyHex Database",
            "FileKeyHex",
        ),
        (
            FIXTURE_FILE_KEY_HASHED_DB,
            FIXTURE_FILE_KEY_HASHED,
            "FileKeyHashed Database",
            "FileKeyHashed",
        ),
        (
            FIXTURE_FILE_KEY_XML_DB,
            FIXTURE_FILE_KEY_XML,
            "FileKeyXml Database",
            "FileKeyXml",
        ),
        (
            FIXTURE_FILE_KEY_XML_V2_DB,
            FIXTURE_FILE_KEY_XML_V2,
            "FileKeyXmlV2 Database",
            "Database",
        ),
    ] {
        let after = rewrite_and_collect(&core, db_bytes, key_file);
        assert_eq!(
            after,
            FileKeyFixtureDigest {
                header_version: KdbxVersion::V4_1,
                name: expected_name.into(),
                root_title: expected_root_title.into(),
                child_titles: default_child_titles(),
            }
        );
    }
}

fn load_file_key_digest(
    core: &KeepassCore,
    db_bytes: &[u8],
    key_file: &[u8],
) -> FileKeyFixtureDigest {
    let mut key = CompositeKey::default();
    key.add_key_file_content(key_file).expect("key file");

    let loaded = core
        .load_database(db_bytes, &key)
        .expect("load file-key fixture");

    FileKeyFixtureDigest {
        header_version: loaded.inspection.header.version,
        name: loaded.vault.name,
        root_title: loaded.vault.root.title,
        child_titles: loaded
            .vault
            .root
            .children
            .iter()
            .map(|group| group.title.clone())
            .collect(),
    }
}

fn rewrite_and_collect(
    core: &KeepassCore,
    db_bytes: &[u8],
    key_file: &[u8],
) -> FileKeyFixtureDigest {
    let mut key = CompositeKey::default();
    key.add_key_file_content(key_file).expect("key file");
    let loaded = core
        .load_kdbx(db_bytes, &key)
        .expect("load file-key fixture");
    let rewritten = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("rewrite file-key fixture");
    load_file_key_digest(core, &rewritten, key_file)
}

fn default_child_titles() -> Vec<String> {
    vec![
        "General".into(),
        "Windows".into(),
        "Network".into(),
        "Internet".into(),
        "eMail".into(),
        "Homebanking".into(),
    ]
}
