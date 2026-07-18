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
  save. Unknown protected values stay protected.
- vaultkern's own extension data lives only in CustomData and String
  key-values — no invented XML elements. (KeePass-family tools preserve the
  former and may drop the latter.)

## Writing modeled data

- Modeled data is written in KeePass-readable standard spellings.
- Editing a TOTP clears the entire reserved OTP family
  (`otp`, `TimeOtp-*`, `HmacOtp-*`) before writing the new spelling —
  mirroring KeePass's own `RemoveOtpSecrets` — so no stale higher-priority
  secret survives an edit.
- Saves are atomic: temp file + rename.

## Sync

- File-level over user storage (OneDrive first). Remote writes are
  serialized by ETag CAS; local state keeps the content fingerprint. After
  a successful sync, keep the synced **base copy** locally.
- Remote changed, no local edits → adopt it. Remote changed, local edits →
  keep one version live, write the other as a sibling conflict-copy
  `.kdbx`; the user reconciles. Foreign (non-vaultkern) writes are handled
  identically — adopt or fork, never silently blended.
- Quick unlock survives foreign saves: after a salt rotation the blob's
  master credential re-derives silently (002); the cost is one slow unlock,
  never a password prompt.

## Designated upgrade path (not built now)

If conflict copies ever become a real annoyance: a three-way field patch
against the kept base — `diff(base, local)` applied onto the remote head;
disjoint fields merge; same-field collisions resolve by entry `modified_at`
or user choice; overwritten values go into KDBX history. The ETag loop
remains the serializer. Permanently out of scope: merge algebra, canonical
hashes, convergence proofs.
