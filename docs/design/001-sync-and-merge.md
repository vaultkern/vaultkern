# 001 — Sync and Merge Semantics

Status: **Decided** (conflict-matrix cells may be added before freeze; the model
itself may not change). 2026-07-12.
Upstream decision: D1 (000).

## Model

- **The unit of sync is the KDBX file.** No record-level sync service, no server
  component. The transport layer keeps the existing assets: OneDrive eTag CAS
  (`If-Match` conditional writes), the pending-generation chain, and
  offline-cache opens.
- **KDBX compatibility is product identity**: a vault may be edited concurrently
  by third-party tools (KeePassXC etc.), so merge semantics must assume the
  other side is not vaultkern.
- **Merge happens at save time**: re-read the remote before saving; if the
  fingerprint moved, semantically merge first, then conditional-write; a 412
  conflict enters the pending queue for retry (existing mechanism, kept).

## Current gaps (must be closed before implementation)

`Vault::merge_from` (crates/vaultkern-model) is currently an entry-level
newest-wins additive merge. Missing:

| # | Gap | Consequence | Target behavior |
|---|-----|-------------|-----------------|
| M1 | `deleted_objects` is never read or written | deletions resurrect | deletion time > entry's last modification ⇒ deletion wins; otherwise the entry wins (edit-resurrects rule, matching KeePassXC). Local deletions are recorded in `deleted_objects` and persisted with the file |
| M2 | entries match by UUID only within the same group | moves create duplicate entries | vault-wide UUID index; group membership decided by the newer `location_changed_at` |
| M3 | group metadata is not merged | group renames/attribute changes are lost | groups match by UUID, metadata newest-wins; group deletion follows M1 |
| M4 | local history is truncated on overwrite | history chains are lost | history is merged as a union by modification time, deduplicated, respecting maxItems/maxSize trimming. The existing test that pins the wrong behavior (asserting only two history entries survive) is rewritten to the new semantics |

## Conflict matrix

Rows = local operation, columns = remote operation, cell = merge outcome.
"Newer wins" = by entry `modified_at`; the loser goes intact into the winner's
history (M4 union semantics); no conflict-copy files are created.

| local \ remote | edit | delete | move | no-op |
|---|---|---|---|---|
| **edit** | newer wins, loser into history; same-second ties broken deterministically by UUID ordering so both devices converge identically | edit time > deletion time ⇒ resurrect with the edit; otherwise deletion wins | edit and move are orthogonal: fields from the edit, location from the newer `location_changed_at` | local wins |
| **delete** | symmetric to top-right | deleted; the earlier deletion time enters `deleted_objects` | deletion time > `location_changed_at` ⇒ deleted; otherwise the entry survives at the new location | deletion propagates |
| **move** | symmetric | symmetric | newer `location_changed_at` wins | local location |
| **group rename/attrs** | — | group deletion vs. newer entries inside ⇒ the group survives (entries are never orphaned) | — | local wins |

Supplementary rules:

- `usage_count` merges as max; `custom_data` / Meta are newest-wins by their own
  timestamps where KDBX provides them; custom icons merge as a union by UUID.
- Timestamps are second-granularity local clocks. **The backstop for ties and
  clock skew is deterministic tie-breaking + history**: any discarded version
  must be recoverable from history. Merge never silently destroys data.
- Merge results are reported to the UI via `MergeSummaryDto` ("merged, N spots
  resolved to the newer version"); the UI takes part in no merge decision (D5).

## Convergence requirements (these become tests)

Table-driven tests cover every cell of the matrix, plus two property tests:

1. **Two-sided convergence**: A merge B and B merge A produce semantically
   equivalent vaults (same entry set, locations, and history sets).
2. **Idempotence**: merging the same input twice equals merging it once.

## Platform and process constraints

- Only the resident app performs sync (D4); extensions read the cached copy in
  the app group container and may see stale data — **accepted**; no sync path
  is added for extensions.
- Writes produced by extensions (passkey registration, usage_count) enter the
  main store via the writer lock / journal defined in 003 and participate in
  the next save's merge.

## Immediate fixes (do not wait for the new architecture; fix on main)

1. Local-file save CAS baseline misalignment (TOCTOU): the expected fingerprint
   for `write` must be the snapshot taken at merge time, not one re-read after
   `begin_write` acquires the lock.
2. OneDrive refresh token stored as a plaintext file: move into each platform's
   secure storage (DPAPI / Keychain / Keystore).
3. Windows quick unlock records use non-atomic `fs::write`: unify on the
   durable atomic write path.
