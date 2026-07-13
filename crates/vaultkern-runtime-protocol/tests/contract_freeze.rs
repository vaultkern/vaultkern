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
//! reviewing the diff. Blessing is refused in CI (guard below): goldens
//! may only be rewritten on a developer machine where the diff is
//! reviewed before it is committed.
//!
//! Scope of the goldens (003 r11): they pin **this Rust implementation's
//! serialization as a regression baseline**, not a cross-language byte
//! spec — journal bodies are any schema-conforming JSON, and no
//! correctness property depends on byte shape. Byte determinism exists
//! only in 005's canonical entry serialization.

use std::path::PathBuf;

use base64::Engine as _;
use vaultkern_runtime_protocol::contracts::{
    CacheManifest, DeadLetterRecord, JournalOpKind, JournalRecord, NeedsReenrollReason,
    PasskeyRegistrationOutcome, PasskeyRegistrationPayload, PlatformRecordKey,
    QuickUnlockLedgerEntry, QuickUnlockState, UsageCountPayload, dead_letter_reason,
};
use vaultkern_runtime_protocol::{EntryPasskeyDto, MergeSummaryDto, framing};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// True when a golden rewrite was requested. Panics if requested in CI —
/// the snapshot check must never be able to silently re-bless itself.
fn blessing() -> bool {
    let requested = std::env::var_os("VAULTKERN_BLESS").is_some();
    if requested && std::env::var_os("CI").is_some() {
        panic!(
            "VAULTKERN_BLESS is set in a CI environment; goldens must only \
             be regenerated on a developer machine and reviewed as a diff"
        );
    }
    requested
}

/// Asserts a value against its golden fixture, or regenerates the fixture
/// when `VAULTKERN_BLESS` is set (never in CI).
fn assert_matches_golden<T>(name: &str, expected: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let path = fixture_path(name);
    let rendered = serde_json::to_string_pretty(expected).expect("serialize contract value");

    if blessing() {
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

/// Decode-only golden: the fixture must deserialize to `expected`, but is
/// not required to be byte-reproducible (used for the legacy MergeSummary
/// document, which by definition lacks the newer fields).
fn assert_decodes_golden<T>(name: &str, golden_body: &str, expected: &T)
where
    T: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let path = fixture_path(name);
    if blessing() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, golden_body).unwrap();
        return;
    }
    let golden = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing golden fixture {}: {err}", path.display()));
    assert_eq!(golden, golden_body, "legacy golden body drifted for {name}");
    let decoded: T = serde_json::from_str(&golden)
        .unwrap_or_else(|err| panic!("golden fixture {} does not deserialize: {err}", name));
    assert_eq!(&decoded, expected, "field mismatch against golden {name}");
}

/// The KDBX4-Argon2id generation pinned in vaultkern-kdbx's
/// `kdf_generation` fixtures (002 r9 length-prefixed canonical encoding) —
/// reused here so the manifest fixture carries a real generation value.
const PINNED_ARGON2ID_GENERATION: &str =
    "6c2923f403eb289a70ddd461feeda074ee18a01e7140b8020ad525becfa49398";

/// Explicitly fake fixture PEM (B3: fixtures must never look like real key
/// material; the redaction test below also greps for this marker).
const FIXTURE_FAKE_PEM: &str =
    "-----BEGIN PRIVATE KEY-----\nTEST-FIXTURE-NOT-A-REAL-KEY\n-----END PRIVATE KEY-----";

/// Fixed **fake** ciphertext bytes for the sealed-record golden: 48 bytes
/// of 0xA5, standard base64. The contract pins the wire encoding of the
/// sealed frame, not the cryptography — real AES-256-GCM output is
/// nondeterministic by design and cannot be a byte-exact golden.
const FAKE_PAYLOAD_SEALED_B64: &str =
    "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl";
/// Fixed 12-byte nonce 0x00..=0x0b, standard base64 (exactly 16 chars).
const FIXTURE_NONCE_B64: &str = "AAECAwQFBgcICQoL";

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

fn dead_letter_record() -> DeadLetterRecord {
    // 003 r11/r12: the dead-letter archives the original frame's raw
    // bytes verbatim, assembled through the frozen archive() rule. The
    // fixture frame wraps the sealed golden record exactly as the binary
    // segment golden does; it is far below the 1 MiB cap, so nothing is
    // truncated and archived_segment stays None.
    let body = serde_json::to_vec(&sealed_journal_record()).unwrap();
    let frame = framing::encode_frame(JournalRecord::SCHEMA_VERSION as u16, &body).unwrap();
    DeadLetterRecord::archive(
        dead_letter_reason::PAYLOAD_CONFLICT,
        1_783_900_803,
        &frame,
        None,
    )
}

fn fixture_passkey() -> EntryPasskeyDto {
    EntryPasskeyDto {
        username: "alice@example.com".into(),
        credential_id: "u9ZLeKUO3lVBqPlpX0QU1w".into(),
        generated_user_id: None,
        private_key_pem: FIXTURE_FAKE_PEM.into(),
        relying_party: "example.com".into(),
        user_handle: Some("bXktdXNlci1oYW5kbGU".into()),
        backup_eligible: true,
        backup_state: false,
    }
}

fn passkey_registration_op() -> JournalOpKind {
    JournalOpKind::PasskeyRegistration(PasskeyRegistrationPayload {
        entry_id: "31e2f3b4-9a76-4c1d-8e0f-6a5b4c3d2e1f".into(),
        passkey: fixture_passkey(),
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
        schema_version: QuickUnlockLedgerEntry::SCHEMA_VERSION,
        state: QuickUnlockState::Enrolled,
        generation: 3,
        policy: true,
    }
}

fn needs_reenroll_ledger_entry() -> QuickUnlockLedgerEntry {
    QuickUnlockLedgerEntry {
        schema_version: QuickUnlockLedgerEntry::SCHEMA_VERSION,
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

fn merge_summary() -> MergeSummaryDto {
    MergeSummaryDto {
        merged_entries: 2,
        history_snapshots_added: 1,
        meta_conflicts_resolved: 1,
        icon_conflicts_resolved: 1,
    }
}

#[test]
fn cache_manifest_matches_golden() {
    assert_matches_golden("cache_manifest.json", &cache_manifest());
}

#[test]
fn journal_record_sealed_matches_golden() {
    // The on-disk record frame body: op vocabulary sealed, plaintext
    // header fields only (003 r9).
    assert_matches_golden("journal_record_sealed.json", &sealed_journal_record());
}

#[test]
fn dead_letter_record_matches_golden() {
    assert_matches_golden("dead_letter_record.json", &dead_letter_record());
}

#[test]
fn dead_letter_frame_bytes_roundtrip_to_the_original_record() {
    // The archived bytes are the frame verbatim: decoding them re-parses
    // to exactly the original record (the retry path).
    let dead_letter = dead_letter_record();
    let frame_bytes = base64::engine::general_purpose::STANDARD
        .decode(&dead_letter.frame_b64)
        .expect("frame_b64 is valid base64");
    // Untruncated entry: region_len records the archived length, no
    // segment was renamed.
    assert_eq!(dead_letter.region_len, frame_bytes.len() as u64);
    assert_eq!(dead_letter.archived_segment, None);
    let decoded = framing::decode_frame(&frame_bytes).expect("archived frame decodes");
    assert_eq!(decoded.record_version, 1);
    let record: JournalRecord =
        serde_json::from_slice(&decoded.body).expect("archived body re-parses");
    assert_eq!(record, sealed_journal_record());
}

#[test]
fn maximum_size_journal_frame_can_be_archived_and_framed_as_dead_letter() {
    let body = vec![b'X'; framing::MAX_RECORD_LEN as usize];
    let frame = framing::encode_frame(JournalRecord::SCHEMA_VERSION as u16, &body).unwrap();
    assert_eq!(frame.len(), DeadLetterRecord::MAX_ARCHIVED_BYTES);
    let archived = DeadLetterRecord::archive(
        dead_letter_reason::PAYLOAD_CONFLICT,
        1_783_900_806,
        &frame,
        None,
    );
    assert_eq!(archived.region_len, frame.len() as u64);
    let dead_letter_body = serde_json::to_vec(&archived).unwrap();
    let dead_letter_frame = framing::encode_frame_with_limit(
        DeadLetterRecord::SCHEMA_VERSION as u16,
        &dead_letter_body,
        framing::MAX_DEAD_LETTER_RECORD_LEN,
    )
    .expect("maximum legal journal frame fits in a dead-letter frame");
    let decoded = framing::decode_frame_with_limit(
        &dead_letter_frame,
        framing::MAX_DEAD_LETTER_RECORD_LEN,
    )
    .unwrap();
    assert_eq!(decoded.body, dead_letter_body);
}

#[test]
fn dead_letter_archive_truncates_over_limit_regions_to_the_prefix() {
    // M2 (r12), via the injectable-limit test seam: an over-limit region
    // stores its prefix, records the full length, and names the renamed
    // *.corrupt segment. Production uses MAX_ARCHIVED_BYTES (= one
    // max-size legal journal frame: MAX_RECORD_LEN + FRAME_OVERHEAD),
    // so any single legal frame archives verbatim (PR review P1).
    assert_eq!(
        DeadLetterRecord::MAX_ARCHIVED_BYTES,
        framing::MAX_RECORD_LEN as usize + framing::FRAME_OVERHEAD
    );
    let region: Vec<u8> = (0..100u8).collect();
    let entry = DeadLetterRecord::archive_with_limit(
        dead_letter_reason::CORRUPTION_UNREACHABLE,
        1_783_900_804,
        &region,
        10,
        Some("0197f9a0-writer.corrupt".into()),
    );
    let stored = base64::engine::general_purpose::STANDARD
        .decode(&entry.frame_b64)
        .unwrap();
    assert_eq!(stored, &region[..10], "prefix only");
    assert_eq!(entry.region_len, 100, "full length recorded");
    assert_eq!(
        entry.archived_segment.as_deref(),
        Some("0197f9a0-writer.corrupt")
    );
    // Under-limit regions are stored whole.
    let whole = DeadLetterRecord::archive_with_limit(
        dead_letter_reason::CORRUPTION_UNREACHABLE,
        1_783_900_804,
        &region,
        1000,
        None,
    );
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&whole.frame_b64)
            .unwrap(),
        region
    );
    assert_eq!(whole.region_len, 100);

    // Additive evolution: a pre-r12 document without the two new fields
    // still deserializes (region_len defaults to 0, segment to None).
    let legacy: DeadLetterRecord = serde_json::from_str(
        r#"{"reason":"payload_conflict","captured_at":1,"frame_b64":"AA=="}"#,
    )
    .unwrap();
    assert_eq!(legacy.region_len, 0);
    assert_eq!(legacy.archived_segment, None);
}

#[test]
fn dead_letter_reason_strings_are_pinned() {
    assert_eq!(dead_letter_reason::KDF_ROTATED, "kdf_rotated");
    assert_eq!(dead_letter_reason::PAYLOAD_CONFLICT, "payload_conflict");
    assert_eq!(dead_letter_reason::USER_DISCARDED, "user_discarded");
    assert_eq!(dead_letter_reason::UNKNOWN_KIND, "unknown_kind");
    assert_eq!(
        dead_letter_reason::CORRUPTION_UNREACHABLE,
        "corruption_unreachable"
    );
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
// MergeSummaryDto in the freeze (M2).
// ---------------------------------------------------------------------

#[test]
fn merge_summary_matches_golden() {
    assert_matches_golden("merge_summary.json", &merge_summary());
}

#[test]
fn merge_summary_legacy_document_defaults_the_conflict_counters() {
    // A summary emitted by a pre-freeze peer lacks the two conflict
    // counters; it must deserialize with both defaulting to zero.
    assert_decodes_golden(
        "merge_summary_legacy.json",
        "{\n  \"mergedEntries\": 2,\n  \"historySnapshotsAdded\": 1\n}",
        &MergeSummaryDto {
            merged_entries: 2,
            history_snapshots_added: 1,
            meta_conflicts_resolved: 0,
            icon_conflicts_resolved: 0,
        },
    );
}

#[test]
fn merge_summary_wire_field_names_are_pinned() {
    let value = serde_json::to_value(merge_summary()).unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "historySnapshotsAdded",
            "iconConflictsResolved",
            "mergedEntries",
            "metaConflictsResolved",
        ]
    );
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
            "schema_version": 1,
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
    assert_eq!(DeadLetterRecord::SCHEMA_VERSION, 1);
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
fn ledger_missing_schema_version_fails_closed() {
    let missing = r#"{
        "state": { "kind": "disabled" },
        "generation": 1,
        "policy": false
    }"#;
    assert!(serde_json::from_str::<QuickUnlockLedgerEntry>(missing).is_err());
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

// ---------------------------------------------------------------------
// B2: the three-branch passkey-registration idempotence law, exercised
// through the frozen pure decision function.
// ---------------------------------------------------------------------

#[test]
fn passkey_registration_replay_over_identical_payload_is_a_noop() {
    let payload = PasskeyRegistrationPayload {
        entry_id: "31e2f3b4-9a76-4c1d-8e0f-6a5b4c3d2e1f".into(),
        passkey: fixture_passkey(),
    };
    // First application: nothing exists under the credential UUID.
    assert_eq!(
        payload.registration_outcome(None),
        PasskeyRegistrationOutcome::Insert
    );
    // Replay after the effect is present: identical full payload ⇒ no-op,
    // no matter how many times it is re-applied.
    let stored = fixture_passkey();
    for _ in 0..3 {
        assert_eq!(
            payload.registration_outcome(Some((&payload.entry_id, &stored))),
            PasskeyRegistrationOutcome::NoOp
        );
    }
}

#[test]
fn passkey_registration_conflicting_payload_dead_letters() {
    let payload = PasskeyRegistrationPayload {
        entry_id: "31e2f3b4-9a76-4c1d-8e0f-6a5b4c3d2e1f".into(),
        passkey: fixture_passkey(),
    };
    // Same credential UUID, different stored data — any field difference
    // is a conflict, never a silent overwrite or silent keep.
    let mut divergent = fixture_passkey();
    divergent.user_handle = Some("ZGlmZmVyZW50".into());
    assert_eq!(
        payload.registration_outcome(Some((&payload.entry_id, &divergent))),
        PasskeyRegistrationOutcome::Conflict
    );
    // The frozen dead-letter reason string for this branch.
    assert_eq!(dead_letter_reason::PAYLOAD_CONFLICT, "payload_conflict");
}

// ---------------------------------------------------------------------
// B3: entry-level secrets are redacted from Debug output.
// ---------------------------------------------------------------------

#[test]
fn passkey_payload_debug_redacts_the_private_key() {
    let payload = PasskeyRegistrationPayload {
        entry_id: "31e2f3b4-9a76-4c1d-8e0f-6a5b4c3d2e1f".into(),
        passkey: fixture_passkey(),
    };
    let debug = format!("{payload:?}");
    assert!(
        !debug.contains("TEST-FIXTURE-NOT-A-REAL-KEY") && !debug.contains("PRIVATE KEY"),
        "Debug output leaked private key material: {debug}"
    );
    assert!(debug.contains("[REDACTED]"), "missing redaction marker");
    // Non-secret fields stay visible for diagnostics.
    assert!(debug.contains("example.com"));

    // The op enum's derived Debug goes through the same redaction.
    let op_debug = format!("{:?}", passkey_registration_op());
    assert!(!op_debug.contains("TEST-FIXTURE-NOT-A-REAL-KEY"));
    assert!(op_debug.contains("[REDACTED]"));
}

// ---------------------------------------------------------------------
// M1: the schema artifacts' semantic format constraints reject illegal
// values. The jsonschema crate is not available in the offline registry
// cache, so instead of full-document validation these tests execute the
// exact `pattern`/`minLength`/`const` constraints read from the frozen
// artifacts (which the schema snapshot test pins byte-exactly) with the
// regex crate — the same constraints a JSON Schema validator would
// enforce.
// ---------------------------------------------------------------------

fn schema_property(schema_file: &str, property: &str) -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join(schema_file);
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("missing frozen schema {}: {err}", path.display())),
    )
    .expect("schema artifact parses");
    schema["properties"][property].clone()
}

fn pattern_of(schema_file: &str, property: &str) -> regex::Regex {
    let prop = schema_property(schema_file, property);
    let pattern = prop["pattern"]
        .as_str()
        .unwrap_or_else(|| panic!("{schema_file}#{property} has no pattern"));
    regex::Regex::new(pattern).expect("frozen pattern compiles")
}

#[test]
fn schema_rejects_fingerprints_of_the_wrong_hex_length() {
    let pattern = pattern_of("cache_manifest.schema.json", "content_fingerprint");
    let valid = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    assert!(pattern.is_match(valid));
    assert!(!pattern.is_match(&valid[..63]), "63 hex chars must fail");
    assert!(
        !pattern.is_match(&format!("{valid}0")),
        "65 hex chars must fail"
    );
    assert!(
        !pattern.is_match(&valid.to_uppercase()),
        "uppercase hex must fail (lowercase is frozen)"
    );
    // kdf_generation and base_fingerprint carry the same constraint.
    assert!(!pattern_of("cache_manifest.schema.json", "kdf_generation").is_match("abc123"));
    assert!(
        !pattern_of("journal_record.schema.json", "base_fingerprint").is_match(&valid[..63])
    );
}

#[test]
fn schema_rejects_nonces_of_the_wrong_length() {
    let pattern = pattern_of("journal_record.schema.json", "nonce");
    assert!(pattern.is_match("AAECAwQFBgcICQoL"), "16 chars pass");
    assert!(!pattern.is_match("AAECAwQFBgcICQo"), "15 chars must fail");
    assert!(!pattern.is_match("AAECAwQFBgcICQoLA"), "17 chars must fail");
    assert!(!pattern.is_match("AAECAwQFBgcICQo="), "padding must fail");
}

#[test]
fn schema_rejects_empty_vault_ref_ids() {
    for schema_file in [
        "cache_manifest.schema.json",
        "journal_record.schema.json",
        "platform_record_key.schema.json",
    ] {
        let prop = schema_property(schema_file, "vault_ref_id");
        let min = prop["minLength"]
            .as_u64()
            .unwrap_or_else(|| panic!("{schema_file}#vault_ref_id has no minLength"));
        assert!(min >= 1, "{schema_file}: vault_ref_id must be non-empty");
        assert!(
            "".chars().count() < min as usize,
            "empty string violates the constraint"
        );
    }
}

#[test]
fn schema_constrains_op_id_to_uuidv7_and_payload_sealed_to_base64() {
    let op_id = pattern_of("journal_record.schema.json", "op_id");
    assert!(op_id.is_match("0197f9a0-5c00-7000-8000-3b9e21f04d11"));
    // UUIDv4 (version nibble 4) must fail — op_id is UUIDv7 by contract.
    assert!(!op_id.is_match("0197f9a0-5c00-4000-8000-3b9e21f04d11"));

    let sealed = schema_property("journal_record.schema.json", "payload_sealed");
    assert!(
        sealed["minLength"].as_u64().unwrap() >= 24,
        "payload_sealed must be at least one GCM tag long"
    );
    let sealed_pattern = regex::Regex::new(sealed["pattern"].as_str().unwrap()).unwrap();
    assert!(sealed_pattern.is_match(FAKE_PAYLOAD_SEALED_B64));
    assert!(!sealed_pattern.is_match("not base64!!"));
    assert!(!sealed_pattern.is_match(&"A".repeat(25)));
    assert!(!sealed_pattern.is_match("A"));
    assert!(!sealed_pattern.is_match("AAAA="));

    // The dead-letter's archived bytes carry the same standard-base64
    // constraint; a corruption_unreachable region can be a single raw byte,
    // whose encoding is four characters.
    let frame = schema_property("dead_letter_record.schema.json", "frame_b64");
    assert_eq!(frame["minLength"].as_u64().unwrap(), 4);
    let frame_pattern = regex::Regex::new(frame["pattern"].as_str().unwrap()).unwrap();
    assert!(frame_pattern.is_match("AA=="), "1 raw byte is archivable");
    assert!(!frame_pattern.is_match("A"));
    assert!(!frame_pattern.is_match("AAAA="));
    assert!(!frame_pattern.is_match("not base64!!"));
}

#[test]
fn schema_pins_schema_version_to_const_one() {
    let prop = schema_property("cache_manifest.schema.json", "schema_version");
    assert_eq!(prop["const"], serde_json::json!(1));
}
