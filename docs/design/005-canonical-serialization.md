# 005 — Canonical Serialization Byte Layout (v1)

Status: **Frozen — r12** (frozen with the Phase 0 contract freeze; four
freeze-hardening rounds). 2026-07-13.
Upstream: 001 (same-second tie rule, history dedupe key, Meta content-hash
fallback), 000 Execution discipline #1, 004 (contract-freeze root node).

This document pins the **canonical serialization** that 001 depends on: a
fixed, versioned byte encoding of an entry's persistent fields whose SHA-256
digest is the entry's *canonical content hash*. Two implementations at the
same `schema_version` MUST produce identical bytes for the same entry, or
same-second ties diverge (001). **The spec is frozen; the encoder
implementation and its byte goldens are the first deliverable of the
merge-algebra track and MUST land before any merge logic** — no merge code
may be written against an unimplemented tie rule. The implementation adds
golden byte fixtures pinning digests the same way the `kdf_generation`
fixtures pin theirs.

## 1. Purpose and scope

The canonical content hash is used by 001 in exactly three places:

1. **Same-second tie rule**: when two versions of the same entry share
   `modified_at`, the winner is the byte-wise larger/smaller (see §6)
   canonical content hash — both devices converge on the same winner.
2. **History dedupe key**: `UUID + modified_at + canonical content hash`.
3. **Fallback ordering** for untimestamped Meta fields and custom icons:
   byte-wise ordering of the canonical content hash of the field value /
   icon content (the "same determinism family" as the entry tie rule).

The encoding is **never written to disk and never crosses the protocol**; it
exists only as the input to SHA-256. It is therefore *not* subject to the
JSON contracts' additive-evolution rule: **any change whatsoever to this
layout is a breaking change** and requires a new `schema_version` (§7).

**Boundary (r11)**: this spec governs only the entry content-hash domain.
It constrains no JSON wire format anywhere in the system — in particular,
journal frame bodies (003) are ordinary schema-conforming JSON with no
byte-determinism requirement of any kind.

## 2. Primitive encodings

All multi-byte integers are **little-endian**. There is no padding and no
alignment anywhere.

| Primitive | Encoding |
|---|---|
| `bool` | one byte: `0x00` false, `0x01` true |
| `u32` / `i32` | 4 bytes LE (two's complement for signed) |
| `u64` / `i64` | 8 bytes LE (two's complement for signed) |
| byte string | `u32` LE byte length, then the raw bytes |
| text string | UTF-8 bytes of the stored value, encoded as a byte string (length prefix counts **bytes**, not characters). No Unicode normalization is applied — the vault's stored bytes are authoritative; normalizing would make the hash disagree with third-party writers |
| UUID | exactly 16 raw bytes, **no** length prefix |
| `Option<T>` | one byte: `0x00` absent; or `0x01` immediately followed by the encoding of `T` |
| list | `u32` LE element count, then each element's encoding in list order |
| set | `u32` LE element count, then each element's encoding, elements ordered by unsigned byte-wise comparison of their encodings (ascending) |
| map (string keys) | `u32` LE entry count, then each entry as: key (text string) followed by value encoding; entries ordered by unsigned byte-wise comparison of the key's UTF-8 bytes (ascending) |
| struct | its fields' encodings concatenated **in the exact order this document lists them** — no field names, no field count |
| enum | the variant **name** as a text string (the Rust variant name, e.g. `"Sha256"`), followed by the variant's payload fields in declared order. Encoding names rather than ordinals makes the layout **reorder-safe**: adding, removing, or reordering variants in source never changes the encoding of existing variants. (No enum-typed field appears in the v1 entry record; the rule is pinned now so future versions and other record types cannot improvise) |
| timestamp | the model's integer value (`u64` or `i64`, second granularity), encoded as the corresponding integer |

## 3. Stream framing

A canonical serialization stream is:

```
"VKCS"                      # 4 ASCII bytes, domain separation
u32 LE schema_version        # this document: 1
<record>                     # the entry record, §4
```

The digest is `SHA256(framing ‖ record)`. Including the version in the
hashed bytes means digests produced under different layout versions can
never collide silently — they are simply incomparable, which is the intended
failure mode (§7).

## 4. Entry record v1 — field list and order

The record is the `struct` encoding (§2) of the following fields **in this
exact order**. Types refer to §2 primitives. Optionality mirrors the model:
a field the model stores as `Option` is encoded as `Option<T>`; absent means
absent-in-model (not "empty string").

| # | Field | Type |
|---|---|---|
| 1 | `id` | UUID |
| 2 | `title` | text string |
| 3 | `username` | text string |
| 4 | `password` | text string |
| 5 | `url` | text string |
| 6 | `notes` | text string |
| 7 | `field_protection` | struct: `protect_title`, `protect_username`, `protect_password`, `protect_url`, `protect_notes` — five `bool`s in that order |
| 8 | `tags` | set of text string |
| 9 | `attributes` | map: key → struct(`value`: text string, `protected`: bool) |
| 10 | `attachments` | map: attachment name → struct(`protect_in_memory`: bool, `content_sha256`: 32 raw bytes, no length prefix). **Content hash, never the bytes** (001: attachments are content-addressed; the pool deduplicates identical bytes) |
| 11 | `icon_id` | `Option<u32>` |
| 12 | `custom_icon_id` | `Option<UUID>` |
| 13 | `foreground_color` | `Option<text string>` |
| 14 | `background_color` | `Option<text string>` |
| 15 | `override_url` | `Option<text string>` |
| 16 | `created_at` | `u64` |
| 17 | `modified_at` | `u64` |
| 18 | `expires` | `bool` |
| 19 | `expiry_time` | `Option<i64>` |
| 20 | `last_accessed_at` | `Option<u64>` |
| 21 | `usage_count` | `Option<u64>` |
| 22 | `location_changed_at` | `Option<u64>` |
| 23 | `previous_parent` | `Option<UUID>` |
| 24 | `auto_type` | `Option<struct>`: `enabled`: `Option<bool>`, `obfuscation`: `Option<i32>`, `default_sequence`: `Option<text string>`, `associations`: list of struct(`window`: text string, `sequence`: text string) |
| 25 | `custom_data` | map: key → text string |
| 26 | `custom_data_items` | map: item key → struct(`value`: text string, `last_modified`: `Option<i64>`). All `CustomDataItem`s from all of the entry's custom-data blocks, collected into one map (see exclusions: block boundaries and XML anchors are fidelity state). If the same key appears more than once, the last occurrence in document order wins — the same resolution the KDBX reader applies |
| 27 | `exclude_from_reports` | `bool` |

### Excluded from the canonical bytes (deliberate, with reasons)

- **`history`** — excluded by definition (001: "canonical serialization of
  the entry fields, excluding history"). The hash identifies one version;
  history is the set of versions.
- **`passkey`, `totp`** — these model fields are *projections* parsed out of
  the entry's attributes (`KPEX_PASSKEY_*`, `otp`). The attributes map
  (field 9) already contains their source of truth; encoding the projections
  too would double-count the same data and let a projection-parsing
  difference between implementations diverge the hash.
- **`raw_state`, `opaque_xml`, custom-data block boundaries and anchors** —
  XML round-trip fidelity state (node order, raw string forms, unknown-node
  placement). Two tools writing the same semantic content in different XML
  shapes MUST hash identically, otherwise every third-party save would look
  like a content conflict.
- **Attachment bytes** — represented by their SHA-256 content hash
  (field 10), per 001.

## 5. Non-entry uses

- **Meta field fallback** (001): the canonical content hash of a Meta field
  value is `SHA256("VKCS" ‖ schema_version ‖ primitive encoding of the
  value per §2)`.
- **Custom icon fallback** (001): the icon's content hash is
  `SHA256("VKCS" ‖ schema_version ‖ byte string encoding of the icon data)`.

## 6. Byte-wise comparison

Wherever 001 says "byte-wise ordering/comparison" of hashes: compare the two
32-byte digests as unsigned bytes, left to right (lexicographic;
`memcmp` semantics). The **greater** digest wins the tie. The direction is
arbitrary but must be identical everywhere; it is hereby pinned as
greater-wins.

## 7. Versioning and evolution

- `schema_version` is `1`. It is a `u32` and lives inside the hashed bytes
  (§3).
- **Every** layout change — adding a field, reordering, changing an
  encoding — bumps `schema_version`. There is no additive tolerance: the
  output feeds a hash, so any byte change is semantically breaking.
- Digests under different versions are incomparable. Implementations MUST
  compute the version pinned for their protocol major version; a version
  bump is a coordinated cutover shipped like any other breaking protocol
  change (D5 negotiation), never a silent upgrade.
- The implementing work item (Phase 1 merge algebra) MUST ship golden byte
  fixtures: at least one fully-populated entry (every `Option` present,
  non-empty map/set/list, an attachment reference) and one minimal entry
  (every `Option` absent, empty collections), with the full canonical byte
  stream and its digest pinned in the repository. Those fixtures then have
  the same status as the `kdf_generation` fixtures: changing them is
  changing the contract.
