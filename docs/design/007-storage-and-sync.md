# 007 — Storage and Sync

Status: **Stable — r1**. 2026-07-19. Replaces the retired 001/005/006
contracts.

## Container

- Read KDBX 3.x/4.x; write 4.1 only.
- Opening an existing KeePass file **is** migration; the file itself **is**
  the export and the escape hatch. No import/export feature exists or is
  needed.

## The luggage rule

- Unknown CustomData entries, String keys, and XML elements are carried
  verbatim: never read, never interpreted, never modified — re-emitted on
  save. Verbatim means the decrypted value: protected values are deciphered
  at load and re-enciphered under the fresh inner stream at save, keeping
  their protected flag — raw ciphertext bytes cannot survive a save because
  the inner stream key and positions change every time.
- vaultkern's own extension data lives only in CustomData and String
  key-values — no invented XML elements. (KeePass-family tools preserve the
  former and may drop the latter.)

## Writing modeled data

- Modeled data is written in KeePass-readable standard spellings.
- Editing a TOTP clears the entire reserved OTP family
  (`otp`, `TimeOtp-*`, `HmacOtp-*`) before writing the new spelling —
  mirroring KeePass's own `RemoveOtpSecrets` — so no stale higher-priority
  secret survives an edit.
- Saves are atomic and durable: write the temp file, flush it, rename, and
  flush the directory metadata (the existing durable-write path). The save
  commits only if the target still matches the session's last-known content
  fingerprint, checked immediately before the rename; a mismatch takes the
  conflict path instead of silently replacing a foreign edit.

## Sync

- File-level over user storage (OneDrive first). Remote writes are
  serialized by ETag CAS; local state keeps the content fingerprint. After
  a successful sync, keep the synced **base copy** locally.
- Remote changed, no local edits → adopt it. Remote changed, local edits →
  the three-way field patch below. Anything the patch cannot represent —
  including a foreign write whose lineage over our kept base is unclear —
  becomes a sibling conflict-copy `.kdbx` for the user to reconcile;
  nothing is ever silently blended outside the patch rules.
- Quick unlock survives foreign saves: in the app, the blob's master
  credential re-derives silently after a salt rotation (002) — one slow
  unlock, no password prompt. Extension processes never run a KDF, so on a
  cache miss they fail gracefully and direct the user to open the app once
  (002/003).

## Three-way field patch

Because pushes are serialized by CAS, the kept base `B` is always an
ancestor of the remote head `R`, and the local vault `L` is `B` plus this
device's edits. On a failed CAS push: pull `R`, compute `diff(B, L)`, apply
it onto `R`, push again under CAS (retry loop). One device at a time
performs this rebase; no symmetric-convergence requirement exists.

- Granularity: per object UUID (entry, group, meta); within an entry, per
  field — each standard field, each attribute by key, the tag set, each
  attachment by name, TOTP and passkey as single units, icon and colors,
  and the parent group as the location field.
- Only one side differs from `B` → take that side. Both sides identical →
  nothing to do.
- Both changed the same field → the later entry `modified_at` wins; on a
  tie the remote value stays. The losing entry version is pushed into KDBX
  history first, so nothing becomes unrecoverable.
- Edit versus delete → the edit wins (the entry comes back). A delete
  sticks only when the other side left the object untouched.
- Conflicting parents resolve by the later `location_changed_at`; tie →
  remote stays.
- A group deletion never orphans entries: if anything inside changed, the
  group survives.
- History lists merge by union, subject to the vault's own retention
  settings.
- Any situation the patch cannot represent falls back to the conflict-copy
  path above — the optimization's failure mode is the mechanism it
  optimizes away.

Permanently out of scope: merge algebra, canonical hashes, convergence
proofs. The ETag loop is the serializer.
