//! Phase 0 contract-freeze snapshot tests (000, Execution discipline #1).
//!
//! Every contract type has at least one golden JSON fixture under
//! `tests/fixtures/`. The tests assert both directions:
//!
//! (a) the fixture deserializes successfully and every field matches the
//!     expected value exactly, and
//! (b) serializing the expected value reproduces the golden **bytes**
//!     exactly.
//!
//! This is the CI snapshot check: any wire change makes (b) fail, so a wire
//! change can only land by explicitly regenerating the goldens
//! (`VAULTKERN_BLESS=1 cargo test -p vaultkern-runtime-protocol`) and
//! reviewing the diff.

use std::path::PathBuf;

use vaultkern_runtime_protocol::EntryPasskeyDto;
use vaultkern_runtime_protocol::contracts::{
    CacheManifest, JournalOpKind, JournalRecord, NeedsReenrollReason, PasskeyRegistrationPayload,
    PlatformRecordKey, QuickUnlockLedgerEntry, QuickUnlockState, UsageCountPayload,
};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Asserts a value against its golden fixture, or regenerates the fixture
/// when `VAULTKERN_BLESS` is set.
fn assert_matches_golden<T>(name: &str, expected: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let path = fixture_path(name);
    let rendered = serde_json::to_string_pretty(expected).expect("serialize contract value");

    if std::env::var_os("VAULTKERN_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &rendered).unwrap();
        return;
    }

    let golden = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing golden fixture {}: {err}", path.display()));

    // (a) The golden deserializes and every field matches exactly.
    let decoded: T = serde_json::from_str(&golden)
        .unwrap_or_else(|err| panic!("golden fixture {} does not deserialize: {err}", name));
    assert_eq!(&decoded, expected, "field mismatch against golden {name}");

    // (b) Serialization reproduces the golden bytes exactly (the snapshot
    // check: any wire change must explicitly update the golden).
    assert_eq!(
        rendered.as_bytes(),
        golden.as_bytes(),
        "wire bytes changed for {name}; if intentional, regenerate the \
         golden with VAULTKERN_BLESS=1 and review the diff"
    );
}

/// The KDBX4-Argon2id generation pinned in vaultkern-kdbx's
/// `kdf_generation` fixtures (002 r9 length-prefixed canonical encoding) —
/// reused here so the manifest fixture carries a real generation value.
const PINNED_ARGON2ID_GENERATION: &str =
    "6c2923f403eb289a70ddd461feeda074ee18a01e7140b8020ad525becfa49398";

fn cache_manifest() -> CacheManifest {
    CacheManifest {
        schema_version: CacheManifest::SCHEMA_VERSION,
        vault_ref_id: "vault-ref-0f6c".into(),
        content_fingerprint: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            .into(),
        kdf_generation: PINNED_ARGON2ID_GENERATION.into(),
        source_etag: Some("\"etag-1234\"".into()),
        published_at: 1_783_900_800,
    }
}

/// Fixed **fake** ciphertext bytes for the sealed-record golden: 48 bytes
/// of 0xA5, standard base64. The contract pins the wire encoding of the
/// sealed frame, not the cryptography — real AES-256-GCM output is
/// nondeterministic by design and cannot be a byte-exact golden.
const FAKE_PAYLOAD_SEALED_B64: &str =
    "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl";
/// Fixed 12-byte nonce 0x00..=0x0b, standard base64.
const FIXTURE_NONCE_B64: &str = "AAECAwQFBgcICQoL";

fn sealed_journal_record() -> JournalRecord {
    JournalRecord {
        seq: 1,
        op_id: "0197f9a0-5c00-7000-8000-3b9e21f04d11".into(),
        vault_ref_id: "vault-ref-0f6c".into(),
        payload_sealed: FAKE_PAYLOAD_SEALED_B64.into(),
        nonce: FIXTURE_NONCE_B64.into(),
        base_fingerprint: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".into(),
        created_at: 1_783_900_801,
    }
}

fn passkey_registration_op() -> JournalOpKind {
    JournalOpKind::PasskeyRegistration(PasskeyRegistrationPayload {
        passkey: EntryPasskeyDto {
            username: "alice@example.com".into(),
            credential_id: "u9ZLeKUO3lVBqPlpX0QU1w".into(),
            generated_user_id: None,
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nMIG…\n-----END PRIVATE KEY-----\n"
                .into(),
            relying_party: "example.com".into(),
            user_handle: Some("bXktdXNlci1oYW5kbGU".into()),
            backup_eligible: true,
            backup_state: false,
        },
    })
}

fn usage_count_op() -> JournalOpKind {
    JournalOpKind::UsageCount(UsageCountPayload {
        entry_id: "31e2f3b4-9a76-4c1d-8e0f-6a5b4c3d2e1f".into(),
        observed_usage_count: 42,
    })
}

fn enrolled_ledger_entry() -> QuickUnlockLedgerEntry {
    QuickUnlockLedgerEntry {
        state: QuickUnlockState::Enrolled,
        generation: 3,
        policy: true,
    }
}

fn needs_reenroll_ledger_entry() -> QuickUnlockLedgerEntry {
    QuickUnlockLedgerEntry {
        state: QuickUnlockState::NeedsReenroll {
            reason: NeedsReenrollReason::KdfRotated,
        },
        generation: 3,
        policy: true,
    }
}

fn platform_record_key() -> PlatformRecordKey {
    PlatformRecordKey {
        identifier_scope: "group.com.vaultkern.extension".into(),
        vault_ref_id: "vault-ref-0f6c".into(),
        record_generation: 3,
    }
}

#[test]
fn cache_manifest_matches_golden() {
    assert_matches_golden("cache_manifest.json", &cache_manifest());
}

#[test]
fn journal_record_sealed_matches_golden() {
    // The on-disk record frame: op vocabulary sealed, plaintext header
    // fields only (003 r9).
    assert_matches_golden("journal_record_sealed.json", &sealed_journal_record());
}

#[test]
fn journal_op_passkey_registration_matches_golden() {
    // The decrypted plaintext of payload_sealed — never on disk in the
    // clear, but its wire shape is contract all the same.
    assert_matches_golden(
        "journal_op_passkey_registration.json",
        &passkey_registration_op(),
    );
}

#[test]
fn journal_op_usage_count_matches_golden() {
    assert_matches_golden("journal_op_usage_count.json", &usage_count_op());
}

#[test]
fn quick_unlock_ledger_entry_enrolled_matches_golden() {
    assert_matches_golden(
        "quick_unlock_ledger_entry_enrolled.json",
        &enrolled_ledger_entry(),
    );
}

#[test]
fn quick_unlock_ledger_entry_needs_reenroll_matches_golden() {
    assert_matches_golden(
        "quick_unlock_ledger_entry_needs_reenroll.json",
        &needs_reenroll_ledger_entry(),
    );
}

#[test]
fn platform_record_key_matches_golden() {
    assert_matches_golden("platform_record_key.json", &platform_record_key());
}

// ---------------------------------------------------------------------
// Evolution guarantees frozen with the formats.
// ---------------------------------------------------------------------

#[test]
fn contracts_tolerate_unknown_fields() {
    // Additive evolution: a newer writer may add fields; this reader must
    // ignore them (no deny_unknown_fields anywhere in the contracts).
    let manifest: CacheManifest = serde_json::from_str(
        r#"{
            "schema_version": 1,
            "vault_ref_id": "v",
            "content_fingerprint": "f",
            "kdf_generation": "g",
            "published_at": 1,
            "field_from_the_future": true
        }"#,
    )
    .expect("unknown field must be tolerated");
    assert_eq!(manifest.source_etag, None, "source_etag defaults to None");

    let entry: QuickUnlockLedgerEntry = serde_json::from_str(
        r#"{
            "state": { "kind": "needs_reenroll", "reason": "biometry_changed", "extra": 1 },
            "generation": 9,
            "policy": false,
            "field_from_the_future": "x"
        }"#,
    )
    .expect("unknown field must be tolerated");
    assert_eq!(
        entry.state,
        QuickUnlockState::NeedsReenroll {
            reason: NeedsReenrollReason::BiometryChanged
        }
    );
}

#[test]
fn schema_version_constants_are_pinned() {
    assert_eq!(CacheManifest::SCHEMA_VERSION, 1);
    assert_eq!(JournalRecord::SCHEMA_VERSION, 1);
    assert_eq!(QuickUnlockLedgerEntry::SCHEMA_VERSION, 1);
    assert_eq!(PlatformRecordKey::SCHEMA_VERSION, 1);
}

#[test]
fn journal_op_wire_shape_is_kind_plus_payload() {
    // 003 r9: the decrypted op document serializes as sibling `kind` +
    // `payload` fields, not as a nested enum object; the target
    // vault_ref_id is NOT duplicated inside the payload (it lives once, in
    // the plaintext record header, bound via the sealing AAD).
    let value = serde_json::to_value(usage_count_op()).unwrap();
    assert_eq!(value["kind"], "usage_count");
    assert_eq!(value["payload"]["observed_usage_count"], 42);
    assert!(value["payload"].get("vault_ref_id").is_none());
}

#[test]
fn journal_record_frame_keeps_the_op_sealed() {
    // 003 r9: the record frame carries only plaintext routing fields plus
    // the sealed payload — no `kind`/`payload` in the clear.
    let value = serde_json::to_value(sealed_journal_record()).unwrap();
    assert_eq!(value["vault_ref_id"], "vault-ref-0f6c");
    assert_eq!(value["payload_sealed"], FAKE_PAYLOAD_SEALED_B64);
    assert_eq!(value["nonce"], FIXTURE_NONCE_B64);
    assert!(value.get("kind").is_none());
    assert!(value.get("payload").is_none());
}

#[test]
fn cache_manifest_source_etag_is_none_for_local_vaults() {
    // 002: source_etag is None for local-file vaults; absence and null both
    // deserialize.
    let mut manifest = cache_manifest();
    manifest.source_etag = None;
    let json = serde_json::to_string(&manifest).unwrap();
    let decoded: CacheManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, manifest);
}
