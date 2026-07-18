> **Retired (2026-07-19).** Superseded by the r16 scope reset (000) and 007.
> Historical record only — not a requirement on any current code.

# 006 Freeze Evidence — Canonical Field 9 Golden Audit

Status: **Recorded freeze evidence**. 2026-07-17.

This audit compares the fully populated canonical-v1 golden from the original
plain-005 implementation (`1cd4738`) with the `A(e)` materialized golden frozen
by 006. The executable audit is
`full_entry_golden_delta_is_confined_to_field_9` in
`crates/vaultkern-model/src/canonical_serialization.rs`.

| Stream | Length | SHA-256 | Field 9 entries | Field 9 length |
|---|---:|---|---:|---:|
| obsolete plain-005 | 565 | `b67612dd8309382583d1b1a132b599ae734f6427332a557dd4da07261a7616e6` | 2 | 36 |
| 006 `A(e)` | 1173 | `55979e79a38604f9dea969536290bdfc92864202db484614ff8c0e25ab4a54e2` | 15 | 644 |

The test decodes both streams according to all 27 field types, rather than
searching for a byte substring. It asserts:

- the `VKCS` framing and `schema_version = 1` bytes are identical;
- fields 1–8 and 10–27 have byte-identical encoded slices;
- field 9 is the only differing slice;
- field 9 grows from the two ordinary custom attributes to those same entries
  plus the 13 materialized TOTP/passkey source attributes.

Reproduce the audit with:

```text
rtk cargo test --locked -p vaultkern-model full_entry_golden_delta_is_confined_to_field_9
```
