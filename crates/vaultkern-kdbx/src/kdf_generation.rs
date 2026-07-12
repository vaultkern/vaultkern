//! 002 §"Core decision" — the single authoritative `kdf_generation` formula.
//!
//! `kdf_generation = SHA256(canonical(KdfParameters VariantDictionary))`,
//! where the canonical encoding is: entries sorted by key, each serialized
//! as `len(key) u32 LE ‖ key ‖ type-tag ‖ len(value) u32 LE ‖ little-endian
//! value bytes` (002 r9 — the length prefixes remove concatenation
//! ambiguity between adjacent entries). The dictionary already contains the
//! KDF `$UUID` and the salt/seed as entries, so nothing is concatenated
//! externally.
//!
//! Format coverage (002, r8):
//! - **KDBX4** carries KdfParameters as a VariantDictionary — hashed as-is.
//! - **KDBX3** carries AES-KDF parameters as discrete header fields
//!   (TransformSeed, TransformRounds); [`kdbx3_canonical_kdf_params`]
//!   normalizes them into the synthetic canonical dictionary
//!   (`$UUID` = AES-KDF, `R` = rounds, `S` = seed) so one formula covers
//!   every supported form.
//!
//! Conservative failure direction: **any** byte-level parameter change —
//! including unknown/extra dictionary keys written by third-party tools, or
//! a KDBX3→KDBX4 format upgrade — changes the generation and triggers
//! `NeedsReenroll` (003). This module is pure functions only; no state, no
//! policy.
//!
//! The encoding is pinned and versioned with the envelope format; the
//! fixtures in the tests below pin one generation value per supported
//! (format version, KDF) combination. **Those hex values are the contract:
//! a change to any of them is a wire-format break** and requires a new
//! envelope format version, not a fixture update.

use vaultkern_crypto::sha256_bytes;

use crate::{KDF_AES_KDBX3_UUID, VariantDictionary, VariantValue, encode_variant_value};

/// The canonical byte encoding of a KdfParameters dictionary (002 r9):
/// entries sorted by key (the dictionary is key-ordered by construction),
/// each as `len(key) u32 LE ‖ key ‖ type-tag ‖ len(value) u32 LE ‖
/// little-endian value bytes`. The u32 LE length prefixes on key and value
/// remove concatenation ambiguity between adjacent entries — without them
/// two different dictionaries could encode to the same byte stream.
///
/// For known entries the type tags are the KDBX VariantDictionary wire
/// tags (0x04 UInt32, 0x05 UInt64, 0x08 Bool, 0x0C Int32, 0x0D Int64,
/// 0x18 String, 0x42 Bytes); integer values are little-endian, strings are
/// UTF-8 bytes, byte values are raw. Lengths count bytes, not characters.
/// This is a thin wrapper over [`canonical_kdf_entries`], which is the
/// tag-generic encoder.
pub fn canonical_kdf_params(params: &VariantDictionary) -> Vec<u8> {
    let encoded: Vec<(&str, u8, Vec<u8>)> = params
        .iter()
        .map(|(key, value)| {
            let (tag, value_bytes) = encode_variant_value(value);
            (key.as_str(), tag, value_bytes)
        })
        .collect();
    canonical_kdf_entries(
        encoded
            .iter()
            .map(|(key, tag, value)| (*key, *tag, value.as_slice())),
    )
}

/// The tag-generic canonical encoder (002 r10 hardening): **any** `u8`
/// type tag with its raw little-endian value bytes participates — there is
/// deliberately no tag whitelist. 002's conservative failure direction
/// requires unknown/extra dictionary entries written by third-party tools
/// to flow into the hash and perturb the generation; an encoder that
/// dropped or rejected unknown tags would silently accept a changed KDF
/// configuration.
///
/// `entries` MUST be supplied in ascending byte order of the keys (the
/// `VariantDictionary` wrapper guarantees this via its ordered map).
pub fn canonical_kdf_entries<'a, I>(entries: I) -> Vec<u8>
where
    I: IntoIterator<Item = (&'a str, u8, &'a [u8])>,
{
    let mut bytes = Vec::new();
    for (key, tag, value) in entries {
        let key_bytes = key.as_bytes();
        bytes.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(key_bytes);
        bytes.push(tag);
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}

/// `kdf_generation = SHA256(canonical(kdf_params))` — 002's single
/// authoritative formula, referenced by 003's generation registry.
/// An equality check, not an ordering.
pub fn kdf_generation(params: &VariantDictionary) -> [u8; 32] {
    sha256_bytes(&canonical_kdf_params(params))
}

/// [`kdf_generation`] as a lowercase hex string — the representation used
/// by the `CacheManifest.kdf_generation` contract field
/// (vaultkern-runtime-protocol).
pub fn kdf_generation_hex(params: &VariantDictionary) -> String {
    let mut out = String::with_capacity(64);
    for byte in kdf_generation(params) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// KDBX3 normalization (002): synthesize the canonical dictionary from the
/// discrete KDBX3 header fields — `$UUID` = AES-KDF, `R` = TransformRounds,
/// `S` = TransformSeed — so KDBX3 files get their generation from the same
/// formula as KDBX4.
pub fn kdbx3_canonical_kdf_params(
    transform_seed: &[u8; 32],
    transform_rounds: u64,
) -> VariantDictionary {
    let mut dict = VariantDictionary::default();
    dict.insert(
        "$UUID",
        VariantValue::Bytes(KDF_AES_KDBX3_UUID.into_bytes().to_vec()),
    );
    dict.insert("R", VariantValue::UInt64(transform_rounds));
    dict.insert("S", VariantValue::Bytes(transform_seed.to_vec()));
    dict
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KDF_AES_KDBX4_UUID, KDF_ARGON2D_UUID, KDF_ARGON2ID_UUID};

    /// Fixed 32-byte salt/seed used by every pinned fixture: 0x00..=0x1f.
    fn fixture_salt() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn kdbx4_argon2_params(uuid: &uuid::Uuid) -> VariantDictionary {
        let mut dict = VariantDictionary::default();
        dict.insert("$UUID", VariantValue::Bytes(uuid.into_bytes().to_vec()));
        dict.insert("V", VariantValue::UInt32(0x13));
        dict.insert("I", VariantValue::UInt64(2));
        dict.insert("M", VariantValue::UInt64(64 * 1024 * 1024));
        dict.insert("P", VariantValue::UInt32(4));
        dict.insert("S", VariantValue::Bytes(fixture_salt()));
        dict
    }

    fn kdbx4_aes_params() -> VariantDictionary {
        let mut dict = VariantDictionary::default();
        dict.insert(
            "$UUID",
            VariantValue::Bytes(KDF_AES_KDBX4_UUID.into_bytes().to_vec()),
        );
        dict.insert("R", VariantValue::UInt64(60_000_000));
        dict.insert("S", VariantValue::Bytes(fixture_salt()));
        dict
    }

    fn kdbx3_aes_params() -> VariantDictionary {
        let seed: [u8; 32] = fixture_salt().try_into().unwrap();
        kdbx3_canonical_kdf_params(&seed, 60_000_000)
    }

    // ------------------------------------------------------------------
    // Pinned generations — one per supported (format version, KDF)
    // combination, as required by 002. THESE HEX VALUES ARE THE
    // CONTRACT: if an edit to the canonical encoding changes any of them,
    // that edit is a wire-format break (every sealed quick unlock envelope
    // in existence falls into NeedsReenroll), and must ship as a new
    // versioned encoding — never as a silent fixture update.
    //
    // Pinned for the 002 r9 length-prefixed encoding
    // (`len(key) u32 LE ‖ key ‖ tag ‖ len(value) u32 LE ‖ value`) and
    // cross-verified byte-for-byte against an independent from-scratch
    // implementation of the 002 formula (Python hashlib) before pinning.
    // ------------------------------------------------------------------

    #[test]
    fn pins_kdbx4_argon2id_generation() {
        let params = kdbx4_argon2_params(&KDF_ARGON2ID_UUID);
        assert_eq!(
            kdf_generation_hex(&params),
            "6c2923f403eb289a70ddd461feeda074ee18a01e7140b8020ad525becfa49398"
        );
    }

    #[test]
    fn pins_kdbx4_argon2d_generation() {
        let params = kdbx4_argon2_params(&KDF_ARGON2D_UUID);
        assert_eq!(
            kdf_generation_hex(&params),
            "7b602102377629e80557bee59a2c21be3b97cef857d01c8956594f7b7f4b5dfd"
        );
    }

    #[test]
    fn pins_kdbx4_aes_generation() {
        assert_eq!(
            kdf_generation_hex(&kdbx4_aes_params()),
            "ae4c596f1ef86b94fffead3f8977fd92d5cc42de891efeaa4526e262474c39bf"
        );
    }

    #[test]
    fn pins_kdbx3_aes_generation() {
        assert_eq!(
            kdf_generation_hex(&kdbx3_aes_params()),
            "4e56697bf1700d95a5a7363af39ea6937dde389021644644e1f54b578028559b"
        );
    }

    // ------------------------------------------------------------------
    // The conservative failure direction (002): every parameter byte, any
    // unknown key, and the KDBX3↔KDBX4 distinction all perturb the
    // generation.
    // ------------------------------------------------------------------

    #[test]
    fn kdbx3_and_kdbx4_aes_generations_differ() {
        // A KDBX3→KDBX4 format upgrade changes the generation (002) even
        // when rounds and seed are identical, because the `$UUID` entries
        // differ.
        assert_ne!(
            kdf_generation(&kdbx3_aes_params()),
            kdf_generation(&kdbx4_aes_params())
        );
    }

    #[test]
    fn any_salt_byte_change_changes_the_generation() {
        let mut salt = fixture_salt();
        salt[0] ^= 0x01;
        let mut params = kdbx4_aes_params();
        params.insert("S", VariantValue::Bytes(salt));
        assert_ne!(kdf_generation(&params), kdf_generation(&kdbx4_aes_params()));
    }

    #[test]
    fn unknown_third_party_keys_change_the_generation() {
        let mut params = kdbx4_aes_params();
        params.insert("X-ThirdParty", VariantValue::Bool(true));
        assert_ne!(kdf_generation(&params), kdf_generation(&kdbx4_aes_params()));
    }

    #[test]
    fn dictionary_wrapper_and_generic_encoder_agree() {
        let params = kdbx4_aes_params();
        let encoded: Vec<(String, u8, Vec<u8>)> = params
            .iter()
            .map(|(key, value)| {
                let (tag, bytes) = crate::encode_variant_value(value);
                (key.clone(), tag, bytes)
            })
            .collect();
        let via_entries = canonical_kdf_entries(
            encoded
                .iter()
                .map(|(key, tag, value)| (key.as_str(), *tag, value.as_slice())),
        );
        assert_eq!(canonical_kdf_params(&params), via_entries);
    }

    #[test]
    fn unknown_type_tags_pass_through_generically() {
        // 002 r10: the encoder has no tag whitelist. A third-party entry
        // with an unknown tag (0x77 is no KDBX wire tag) participates in
        // the canonical bytes exactly as given and perturbs the generation.
        let rounds_le = 60_000_000_u64.to_le_bytes();
        let known: Vec<(&str, u8, &[u8])> = vec![
            ("$UUID", 0x42, &[0xAA; 16][..]),
            ("R", 0x05, &rounds_le[..]),
        ];
        let mut with_unknown = known.clone();
        let exotic_value = [0xDE, 0xAD, 0xBE, 0xEF];
        with_unknown.push(("Z-Exotic", 0x77, &exotic_value[..]));

        let base = canonical_kdf_entries(known);
        let extended = canonical_kdf_entries(with_unknown);

        // The unknown entry is appended verbatim: len(key) ‖ key ‖ tag ‖
        // len(value) ‖ value.
        let mut expected_suffix = Vec::new();
        expected_suffix.extend_from_slice(&8_u32.to_le_bytes());
        expected_suffix.extend_from_slice(b"Z-Exotic");
        expected_suffix.push(0x77);
        expected_suffix.extend_from_slice(&4_u32.to_le_bytes());
        expected_suffix.extend_from_slice(&exotic_value);
        assert_eq!(extended[..base.len()], base[..]);
        assert_eq!(extended[base.len()..], expected_suffix[..]);

        // And it perturbs the generation (conservative failure direction).
        assert_ne!(sha256_bytes(&base), sha256_bytes(&extended));
    }

    #[test]
    fn hex_form_matches_the_raw_digest() {
        let params = kdbx4_aes_params();
        let digest = kdf_generation(&params);
        let hex = kdf_generation_hex(&params);
        assert_eq!(hex.len(), 64);
        let rebuilt: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        assert_eq!(rebuilt, digest.to_vec());
    }
}
