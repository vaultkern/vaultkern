//! 003 §"Journal contract" (r10) — the frozen binary framing of journal
//! segment files and the dead-letter file.
//!
//! Byte layout (all integers little-endian):
//!
//! ```text
//! segment file = magic "VKJS" (4 bytes) ‖ format_version u16 LE ‖ frame*
//! frame        = len u32 LE (byte length of body)
//!              ‖ record_version u16 LE
//!              ‖ body (schema-conforming JSON, UTF-8)
//!              ‖ crc u32 LE
//! ```
//!
//! A body is **any valid UTF-8 JSON conforming to the record's schema**
//! (003 r11): writers use their language's standard serializer, the CRC
//! covers the exact bytes the writer wrote, and **no correctness property
//! depends on the body's byte shape** — idempotence and dedup rest
//! entirely on `op_id`. Cross-writer byte determinism is neither required
//! nor assumed (the only byte-deterministic encoding in the system is
//! 005's canonical entry serialization, which is unrelated to journal
//! JSON).
//!
//! `crc` is CRC-32/ISO-HDLC (the zlib `crc32`: reflected, polynomial
//! 0xEDB88320, init 0xFFFFFFFF, xorout 0xFFFFFFFF) computed over
//! `len ‖ record_version ‖ body`. The maximum body length is **1 MiB**,
//! enforced in both directions: [`encode_frame`] refuses to build an
//! oversized frame and [`decode_frame`] treats an oversized `len` as
//! corruption.
//!
//! The dead-letter file uses this framing with the independent
//! [`MAX_DEAD_LETTER_RECORD_LEN`] body limit; its frame bodies are
//! `DeadLetterRecord` documents ([`crate::contracts::DeadLetterRecord`]).
//!
//! Pure functions only — no I/O, no policy, no replay logic. The
//! three-case corruption algorithm of 003 maps onto [`FramingError`]:
//! [`FramingError::Truncated`] at the EOF of an *active* segment is 003's
//! case 2 (a possibly in-progress append, skipped silently); every other
//! error, and `Truncated` in a *sealed* segment, is definitive corruption
//! (cases 1/3) — that adjudication belongs to the caller, which knows the
//! segment state.

/// Segment file magic, first 4 bytes of every segment and dead-letter file.
pub const SEGMENT_MAGIC: [u8; 4] = *b"VKJS";
/// Current segment format version, stored after the magic.
pub const SEGMENT_FORMAT_VERSION: u16 = 1;
/// Byte length of the segment header (`magic ‖ format_version`).
pub const SEGMENT_HEADER_LEN: usize = 6;
/// Maximum frame body length: 1 MiB, rejected on append and on parse.
pub const MAX_RECORD_LEN: u32 = 1024 * 1024;
/// Maximum dead-letter frame body length: enough for one maximum-size journal
/// frame after base64 encoding and JSON wrapping.
pub const MAX_DEAD_LETTER_RECORD_LEN: u32 = 2 * 1024 * 1024;
/// Bytes of frame overhead around the body (`len` + `record_version` +
/// `crc`).
pub const FRAME_OVERHEAD: usize = 4 + 2 + 4;

/// Framing-level failures. Carries no I/O and no interpretation — the
/// caller applies 003's three-case algorithm based on segment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// The first 4 bytes are not `"VKJS"`.
    BadMagic,
    /// The segment declares a format version this reader does not know.
    UnsupportedFormatVersion(u16),
    /// The input ends before a complete header or frame. At the EOF of an
    /// active segment this is 003's case 2 (append possibly in progress).
    Truncated,
    /// The declared body length exceeds [`MAX_RECORD_LEN`] — treated as
    /// corruption on read; also returned by [`encode_frame`] for an
    /// oversized body.
    RecordTooLong(u32),
    /// The stored CRC does not match `crc32(len ‖ record_version ‖ body)`.
    CrcMismatch,
}

/// One successfully decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    /// The `record_version` the frame carries (for `JournalRecord` bodies
    /// this is `JournalRecord::SCHEMA_VERSION`).
    pub record_version: u16,
    /// The frame body bytes (schema-conforming JSON, UTF-8, exactly as
    /// the writer wrote them).
    pub body: Vec<u8>,
    /// Total bytes this frame occupied in the input (advance the cursor by
    /// this much to reach the next frame).
    pub consumed: usize,
}

/// CRC-32/ISO-HDLC (the zlib `crc32`): reflected, polynomial 0xEDB88320,
/// init 0xFFFFFFFF, xorout 0xFFFFFFFF. Check value:
/// `crc32_iso_hdlc(b"123456789") == 0xCBF4_3926`.
pub fn crc32_iso_hdlc(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// The 6-byte segment header at [`SEGMENT_FORMAT_VERSION`].
pub fn encode_segment_header() -> [u8; SEGMENT_HEADER_LEN] {
    let mut header = [0_u8; SEGMENT_HEADER_LEN];
    header[..4].copy_from_slice(&SEGMENT_MAGIC);
    header[4..].copy_from_slice(&SEGMENT_FORMAT_VERSION.to_le_bytes());
    header
}

/// Reads and validates the segment header at the start of `input`.
/// Returns `(format_version, consumed)`.
pub fn decode_segment_header(input: &[u8]) -> Result<(u16, usize), FramingError> {
    if input.len() < SEGMENT_HEADER_LEN {
        return Err(FramingError::Truncated);
    }
    if input[..4] != SEGMENT_MAGIC {
        return Err(FramingError::BadMagic);
    }
    let format_version = u16::from_le_bytes([input[4], input[5]]);
    if format_version != SEGMENT_FORMAT_VERSION {
        return Err(FramingError::UnsupportedFormatVersion(format_version));
    }
    Ok((format_version, SEGMENT_HEADER_LEN))
}

/// Encodes one frame around `body`. Refuses bodies over [`MAX_RECORD_LEN`]
/// (the append-side half of the 1 MiB cap).
pub fn encode_frame(record_version: u16, body: &[u8]) -> Result<Vec<u8>, FramingError> {
    encode_frame_with_limit(record_version, body, MAX_RECORD_LEN)
}

/// Encodes a frame with an explicit body-length limit.
pub fn encode_frame_with_limit(
    record_version: u16,
    body: &[u8],
    max_record_len: u32,
) -> Result<Vec<u8>, FramingError> {
    if body.len() > max_record_len as usize {
        return Err(FramingError::RecordTooLong(body.len() as u32));
    }
    let len = body.len() as u32;
    let mut frame = Vec::with_capacity(body.len() + FRAME_OVERHEAD);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&record_version.to_le_bytes());
    frame.extend_from_slice(body);
    let crc = crc32_iso_hdlc(&frame);
    frame.extend_from_slice(&crc.to_le_bytes());
    Ok(frame)
}

/// Decodes one frame from the front of `input`.
///
/// - [`FramingError::Truncated`]: the input ends inside the frame — 003
///   case 2 when this is the EOF of an active segment.
/// - [`FramingError::RecordTooLong`] / [`FramingError::CrcMismatch`]:
///   definitive framing failure (003 cases 1/3, per segment state).
pub fn decode_frame(input: &[u8]) -> Result<DecodedFrame, FramingError> {
    decode_frame_with_limit(input, MAX_RECORD_LEN)
}

/// Decodes a frame with an explicit body-length limit.
pub fn decode_frame_with_limit(
    input: &[u8],
    max_record_len: u32,
) -> Result<DecodedFrame, FramingError> {
    if input.len() < 4 {
        return Err(FramingError::Truncated);
    }
    let len = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    if len > max_record_len {
        return Err(FramingError::RecordTooLong(len));
    }
    let body_len = len as usize;
    let total = FRAME_OVERHEAD + body_len;
    if input.len() < total {
        return Err(FramingError::Truncated);
    }
    let record_version = u16::from_le_bytes([input[4], input[5]]);
    let crc_offset = 6 + body_len;
    let stored_crc = u32::from_le_bytes([
        input[crc_offset],
        input[crc_offset + 1],
        input[crc_offset + 2],
        input[crc_offset + 3],
    ]);
    if crc32_iso_hdlc(&input[..crc_offset]) != stored_crc {
        return Err(FramingError::CrcMismatch);
    }
    Ok(DecodedFrame {
        record_version,
        body: input[6..crc_offset].to_vec(),
        consumed: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_iso_hdlc_check_value() {
        // The universal CRC-32/ISO-HDLC check value; pinning it here pins
        // the polynomial, reflection, init, and xorout all at once.
        assert_eq!(crc32_iso_hdlc(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_iso_hdlc(b""), 0);
    }

    #[test]
    fn segment_header_roundtrips_and_is_pinned() {
        let header = encode_segment_header();
        assert_eq!(&header[..4], b"VKJS");
        assert_eq!(header[4..6], 1_u16.to_le_bytes());
        assert_eq!(decode_segment_header(&header), Ok((1, SEGMENT_HEADER_LEN)));
    }

    #[test]
    fn segment_header_rejects_bad_magic_and_unknown_version() {
        assert_eq!(
            decode_segment_header(b"NOPE\x01\x00"),
            Err(FramingError::BadMagic)
        );
        assert_eq!(
            decode_segment_header(b"VKJS\x02\x00"),
            Err(FramingError::UnsupportedFormatVersion(2))
        );
        assert_eq!(decode_segment_header(b"VKJ"), Err(FramingError::Truncated));
    }

    #[test]
    fn frame_roundtrips() {
        let body = br#"{"hello":"world"}"#;
        let frame = encode_frame(1, body).unwrap();
        assert_eq!(frame.len(), body.len() + FRAME_OVERHEAD);
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.record_version, 1);
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.consumed, frame.len());
    }

    #[test]
    fn oversized_bodies_are_rejected_in_both_directions() {
        // Append side.
        let too_big = vec![0_u8; MAX_RECORD_LEN as usize + 1];
        assert_eq!(
            encode_frame(1, &too_big),
            Err(FramingError::RecordTooLong(MAX_RECORD_LEN + 1))
        );
        // Parse side: a forged oversized len is corruption, not an
        // allocation request.
        let mut forged = Vec::new();
        forged.extend_from_slice(&(MAX_RECORD_LEN + 1).to_le_bytes());
        forged.extend_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            decode_frame(&forged),
            Err(FramingError::RecordTooLong(MAX_RECORD_LEN + 1))
        );
    }

    #[test]
    fn truncated_frames_report_truncated_not_corrupt() {
        let frame = encode_frame(1, b"body-bytes").unwrap();
        for cut in 0..frame.len() {
            assert_eq!(
                decode_frame(&frame[..cut]),
                Err(FramingError::Truncated),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn corrupted_bytes_fail_the_crc() {
        let frame = encode_frame(1, b"body-bytes").unwrap();
        // Flip one bit in the body.
        let mut corrupt = frame.clone();
        corrupt[8] ^= 0x01;
        assert_eq!(decode_frame(&corrupt), Err(FramingError::CrcMismatch));
        // Flip one bit in the stored CRC itself.
        let mut bad_crc = frame;
        let last = bad_crc.len() - 1;
        bad_crc[last] ^= 0x01;
        assert_eq!(decode_frame(&bad_crc), Err(FramingError::CrcMismatch));
    }
}
