//! Binary framing snapshot for journal segment files (003 r10, B1).
//!
//! `tests/fixtures/journal_segment.bin` is a golden **binary** segment:
//! segment header + one framed sealed `JournalRecord` (canonical compact
//! JSON body). The tests cover the three parse cases of 003's
//! corruption algorithm against these exact bytes: a normal record, a
//! truncated tail, and a CRC-corrupted record.

use std::path::PathBuf;

use vaultkern_runtime_protocol::contracts::JournalRecord;
use vaultkern_runtime_protocol::framing::{
    self, FramingError, MAX_RECORD_LEN, SEGMENT_HEADER_LEN,
};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/journal_segment.bin")
}

/// Same sealed record as the JSON golden (`journal_record_sealed.json`),
/// framed as canonical **compact** JSON — the body encoding pinned by the
/// binary golden.
fn golden_record() -> JournalRecord {
    JournalRecord {
        seq: 1,
        op_id: "0197f9a0-5c00-7000-8000-3b9e21f04d11".into(),
        vault_ref_id: "vault-ref-0f6c".into(),
        payload_sealed: "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl"
            .into(),
        nonce: "AAECAwQFBgcICQoL".into(),
        base_fingerprint: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            .into(),
        created_at: 1_783_900_801,
    }
}

fn build_segment() -> Vec<u8> {
    let body = serde_json::to_vec(&golden_record()).expect("serialize record body");
    let mut segment = framing::encode_segment_header().to_vec();
    segment.extend_from_slice(
        &framing::encode_frame(JournalRecord::SCHEMA_VERSION as u16, &body)
            .expect("encode frame"),
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
