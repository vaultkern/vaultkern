#![cfg(feature = "external-fixtures")]

use vaultkern_crypto::{CompositeKey, sha256_bytes};
use vaultkern_kdbx::{KdbxVersion, inspect_kdbx_header, load_kdbx};

const FIXTURE: &[u8] = include_bytes!("fixtures/keepassxc-2.7.6-kdbx4.1.kdbx");
const FIXTURE_PASSWORD: &str = "vaultkern-external-fixture";
const FIXTURE_SHA256: [u8; 32] = [
    0xef, 0x38, 0xf5, 0x90, 0x82, 0x51, 0xac, 0xa9, 0x54, 0x7e, 0x61, 0xd6, 0xed, 0x45, 0x65, 0x2c,
    0x63, 0x70, 0x31, 0x59, 0x63, 0x72, 0x22, 0xf9, 0x89, 0xc3, 0xe1, 0x2a, 0xfc, 0x33, 0x4c, 0x62,
];

#[test]
fn reads_checked_in_keepassxc_kdbx41_fixture() {
    assert_eq!(sha256_bytes(FIXTURE), FIXTURE_SHA256);
    let header = inspect_kdbx_header(FIXTURE).expect("inspect external KeePassXC fixture");
    assert_eq!(header.version, KdbxVersion::V4_1);

    let mut key = CompositeKey::default();
    key.add_password(FIXTURE_PASSWORD);
    let vault = load_kdbx(FIXTURE, &key).expect("decrypt external KeePassXC fixture");
    assert!(vault.root.tags.contains("external-fixture"));
    let entry = vault
        .root
        .entries
        .iter()
        .find(|entry| entry.title == "KeePassXC 4.1 Fixture")
        .expect("fixture sentinel entry");

    assert_eq!(entry.username, "external-fixture-user");
    assert_eq!(entry.url, "https://fixture.vaultkern.test/kdbx41");
    assert!(entry.exclude_from_reports);
}
