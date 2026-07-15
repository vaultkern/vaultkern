//! Binary framing snapshot for journal segment files (003 r10, B1).
//!
//! `tests/fixtures/journal_segment.bin` is a golden **binary** segment:
//! segment header + one framed sealed `JournalRecord` (this
//! implementation's compact serde_json body). The tests cover the three
//! parse cases of 003's corruption algorithm against these exact bytes:
//! a normal record, a truncated tail, and a CRC-corrupted record.
//!
//! Scope (003 r11): this golden pins **this Rust implementation's
//! serialization as a regression baseline**, not a cross-language byte
//! spec. Any schema-conforming JSON body is a valid frame body; the CRC
//! covers whatever bytes the writer wrote, and no correctness property
//! depends on byte shape.

use std::path::PathBuf;

use base64::Engine as _;
use vaultkern_runtime_protocol::contracts::{DeadLetterRecord, JournalRecord, dead_letter_reason};
use vaultkern_runtime_protocol::framing::{
    self, FramingError, MAX_DEAD_LETTER_RECORD_LEN, MAX_RECORD_LEN, SEGMENT_HEADER_LEN,
};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/journal_segment.bin")
}

/// Same sealed record as the JSON golden (`journal_record_sealed.json`),
/// framed with this implementation's compact serde_json output — a
/// regression baseline, not a canonical form (003 r11).
fn golden_record() -> JournalRecord {
    JournalRecord {
        seq: 1,
        op_id: "0197f9a0-5c00-7000-8000-3b9e21f04d11".into(),
        vault_ref_id: "vault-ref-0f6c".into(),
        payload_sealed: "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl".into(),
        nonce: "AAECAwQFBgcICQoL".into(),
        base_fingerprint: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".into(),
        created_at: 1_783_900_801,
    }
}

fn build_segment() -> Vec<u8> {
    let body = serde_json::to_vec(&golden_record()).expect("serialize record body");
    let mut segment = framing::encode_segment_header().to_vec();
    segment.extend_from_slice(
        &framing::encode_frame(JournalRecord::SCHEMA_VERSION as u16, &body).expect("encode frame"),
    );
    segment
}

fn load_golden() -> Vec<u8> {
    let path = fixture_path();
    let built = build_segment();

    if std::env::var_os("VAULTKERN_BLESS").is_some() {
        if std::env::var_os("CI").is_some() {
            panic!("VAULTKERN_BLESS is set in CI; goldens are developer-machine only");
        }
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &built).unwrap();
        return built;
    }

    let golden = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("missing binary golden {}: {err}", path.display()));
    assert_eq!(
        built, golden,
        "binary segment framing changed; if intentional, regenerate with \
         VAULTKERN_BLESS=1 and review the diff"
    );
    golden
}

#[test]
fn golden_segment_parses_back_to_the_record() {
    // Case: normal record.
    let segment = load_golden();
    let (format_version, header_len) =
        framing::decode_segment_header(&segment).expect("segment header");
    assert_eq!(format_version, 1);
    assert_eq!(header_len, SEGMENT_HEADER_LEN);

    let frame = framing::decode_frame(&segment[header_len..]).expect("frame decodes");
    assert_eq!(frame.record_version, 1);
    assert_eq!(header_len + frame.consumed, segment.len(), "one frame only");

    let record: JournalRecord = serde_json::from_slice(&frame.body).expect("body deserializes");
    assert_eq!(record, golden_record());
}

#[test]
fn truncated_tail_reports_truncated_at_every_cut() {
    // Case: torn tail (003 case 2 at an active segment's EOF) — every
    // prefix of the frame yields Truncated, never CrcMismatch.
    let segment = load_golden();
    let frames = &segment[SEGMENT_HEADER_LEN..];
    for cut in 0..frames.len() {
        assert_eq!(
            framing::decode_frame(&frames[..cut]),
            Err(FramingError::Truncated),
            "cut at {cut}"
        );
    }
}

#[test]
fn corrupted_golden_fails_the_crc() {
    // Case: CRC corruption (003 cases 1/3) — flip one body byte.
    let segment = load_golden();
    let mut corrupt = segment[SEGMENT_HEADER_LEN..].to_vec();
    let body_byte = 6 + 1; // one byte into the JSON body
    corrupt[body_byte] ^= 0x01;
    assert_eq!(
        framing::decode_frame(&corrupt),
        Err(FramingError::CrcMismatch)
    );
}

#[test]
fn oversized_length_prefix_is_corruption_not_allocation() {
    let mut forged = Vec::new();
    forged.extend_from_slice(&(MAX_RECORD_LEN + 1).to_le_bytes());
    forged.extend_from_slice(&1_u16.to_le_bytes());
    forged.extend_from_slice(&[0_u8; 32]);
    assert_eq!(
        framing::decode_frame(&forged),
        Err(FramingError::RecordTooLong(MAX_RECORD_LEN + 1))
    );
}

#[test]
fn dead_letter_frame_limit_is_independent_from_journal_limit() {
    let body = vec![0_u8; MAX_RECORD_LEN as usize + 1];
    assert_eq!(
        framing::encode_frame(1, &body),
        Err(FramingError::RecordTooLong(MAX_RECORD_LEN + 1))
    );
    let frame = framing::encode_frame_with_limit(1, &body, MAX_DEAD_LETTER_RECORD_LEN)
        .expect("dead-letter framing accepts bodies above journal limit");
    let decoded = framing::decode_frame_with_limit(&frame, MAX_DEAD_LETTER_RECORD_LEN).unwrap();
    assert_eq!(decoded.body, body);
}

#[test]
fn one_to_nine_byte_torn_tails_archive_as_valid_dead_letters() {
    // B1 (r12): a sealed segment can end inside the length prefix or the
    // version field — 1 to 9 bytes of unreachable tail, shorter than any
    // well-formed frame. Each such region must (a) parse as Truncated and
    // (b) archive into a schema-valid DeadLetterRecord.
    let segment = load_golden();
    let frame = &segment[SEGMENT_HEADER_LEN..];
    for cut in 1..=9usize {
        let torn = &frame[..cut];
        assert_eq!(
            framing::decode_frame(torn),
            Err(FramingError::Truncated),
            "cut at {cut}"
        );
        let entry = DeadLetterRecord::archive(
            dead_letter_reason::CORRUPTION_UNREACHABLE,
            1_783_900_805,
            torn,
            None,
        );
        assert!(!entry.frame_b64.is_empty(), "non-empty floor holds");
        assert_eq!(entry.region_len, cut as u64);
        // Round-trips through the wire format and back to the same bytes.
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: DeadLetterRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, entry);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&decoded.frame_b64)
                .unwrap(),
            torn
        );
    }
}

// ---------------------------------------------------------------------
// M3 (r12): cross-serializer acceptance — "any schema-conforming JSON"
// as a tested fact, not a slogan. Four non-Rust-styled bodies must (a)
// deserialize to the very same record and (b) frame + CRC + decode
// cleanly with their exact bytes.
// ---------------------------------------------------------------------

fn assert_foreign_body_accepted(body: &[u8]) {
    // (a) Deserializes to the same record as the golden.
    let record: JournalRecord =
        serde_json::from_slice(body).expect("foreign-styled body deserializes");
    assert_eq!(record, golden_record());
    // (b) Frames, CRC-checks, and decodes with the exact foreign bytes.
    let frame = framing::encode_frame(1, body).expect("frames");
    let decoded = framing::decode_frame(&frame).expect("CRC + decode pass");
    assert_eq!(decoded.body, body, "the writer's exact bytes survive");
}

#[test]
fn accepts_reordered_fields() {
    assert_foreign_body_accepted(
        br#"{"created_at":1783900801,"base_fingerprint":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","nonce":"AAECAwQFBgcICQoL","payload_sealed":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl","vault_ref_id":"vault-ref-0f6c","op_id":"0197f9a0-5c00-7000-8000-3b9e21f04d11","seq":1}"#,
    );
}

#[test]
fn accepts_unknown_fields() {
    assert_foreign_body_accepted(
        br#"{"seq":1,"op_id":"0197f9a0-5c00-7000-8000-3b9e21f04d11","vault_ref_id":"vault-ref-0f6c","payload_sealed":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl","nonce":"AAECAwQFBgcICQoL","base_fingerprint":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","created_at":1783900801,"x_writer_hint":{"platform":"ios","nested":[1,2,3]}}"#,
    );
}

#[test]
fn accepts_unicode_escaped_strings() {
    // - is '-' — a serializer may \uXXXX-escape anything it likes;
    // the decoded value, not the escape form, is what the schema sees.
    assert_foreign_body_accepted(
        br#"{"seq":1,"op_id":"0197f9a0-5c00-7000-8000-3b9e21f04d11","vault_ref_id":"vault\u002dref\u002d0f6c","payload_sealed":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl","nonce":"AAECAwQFBgcICQoL","base_fingerprint":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","created_at":1783900801}"#,
    );
}

#[test]
fn accepts_pretty_printed_bodies() {
    assert_foreign_body_accepted(
        br#"{
    "seq": 1,
    "op_id": "0197f9a0-5c00-7000-8000-3b9e21f04d11",
    "vault_ref_id": "vault-ref-0f6c",
    "payload_sealed": "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl",
    "nonce": "AAECAwQFBgcICQoL",
    "base_fingerprint": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "created_at": 1783900801
}"#,
    );
}
