# 001 — Sync and Merge Semantics

Status: **Decided — r2** (revised after external review). 2026-07-12.
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
| M1 | `deleted_objects` is not consulted by the merge (the KDBX layer already parses and serializes it; only `merge_from` ignores it) | deletions resurrect | deletion time > the object's last modification ⇒ deletion wins; otherwise the object wins (edit-resurrects rule, matching KeePassXC). Local deletions are recorded in `deleted_objects` and persisted with the file |
| M2 | entries match by UUID only within the same group | moves create duplicate entries | vault-wide UUID index; group membership decided by the newer `location_changed_at` |
| M3 | group metadata is not merged | group renames/attribute changes are lost | groups match by UUID, metadata newest-wins; group deletion follows M1 |
| M4 | local history is truncated on overwrite | history chains are lost | history is merged as a union (dedupe key below), respecting maxItems/maxSize trimming. The existing test that pins the wrong behavior (asserting only two history entries survive) is rewritten to the new semantics |

## Merge algebra: per-type rules

The merge is defined over the whole vault object graph, not just entries.
Match keys and rules per type:

| Object | Match key | Rule |
|---|---|---|
| Entry | UUID (vault-wide index) | fields newest-wins by `modified_at`; the losing version goes intact into the winner's history; location decided separately by the newer `location_changed_at` |
| Entry history | UUID + `modified_at` + canonical content hash (the dedupe key) | union of both sides, ordered by time, trimmed per entry by maxItems/maxSize (attachment sizes count toward maxSize) |
| Group | UUID (vault-wide) | metadata newest-wins; children merge recursively; deletion follows the DeletedObject rule; a group with surviving newer entries survives (entries are never orphaned) |
| DeletedObject | UUID. KDBX tombstones carry no type field — entry and group UUIDs share one global space; this is a format constraint, not a modeling gap, and adding a type field would break interoperability | union of both sides, keeping the earliest deletion time per UUID; a tombstone wins against objects modified before it and loses against objects modified after it (edit-resurrects). Retention: a tombstone is pruned once it is older than 365 days and its UUID appears in neither side's live set |
| Entry `custom_data` (untimestamped string map) | map key | key-level union; on a same-key conflict the value rides the entry winner (part of entry newest-wins) |
| `CustomDataItem` blocks (carry `last_modified`) | item key | newest-wins by `last_modified` |
| Custom icons | UUID | union |
| Meta / recycle-bin config | — | newest-wins by the Meta change timestamps KDBX records; where KDBX records none, the side with the newer file-level modification wins and the choice is surfaced in `MergeSummaryDto` |
| Attachments | content (the binaries pool is content-addressed at serialization) | no independent merge — attachment references ride their entry version; the pool deduplicates identical bytes |

## Conflict matrix

Rows = local operation, columns = remote operation, cell = merge outcome.
"Newer wins" = by entry `modified_at`; the loser goes intact into the winner's
history (M4 union semantics); no conflict-copy files are created.

| local \ remote | edit | delete | move | no-op |
|---|---|---|---|---|
| **edit** | newer wins, loser into history; same-second ties broken by the tie rule below | edit time > deletion time ⇒ resurrect with the edit; otherwise deletion wins | edit and move are orthogonal: fields from the edit, location from the newer `location_changed_at` | local wins |
| **delete** | symmetric to top-right | deleted; the earlier deletion time enters `deleted_objects` | deletion time > `location_changed_at` ⇒ deleted; otherwise the entry survives at the new location | deletion propagates |
| **move** | symmetric | symmetric | newer `location_changed_at` wins | local location |
| **group rename/attrs** | — | group deletion vs. newer entries inside ⇒ the group survives (entries are never orphaned) | — | local wins |

**Tie rule (same-second conflicts).** Both versions share the entry's UUID, so
UUID ordering cannot decide between them. When `modified_at` is equal, the
winner is chosen by byte-wise comparison of the two versions' canonical content
hashes (canonical serialization of the entry fields, excluding history). Both
devices compute the same ordering, so both converge on the same winner; the
loser enters history like any other loser.

Supplementary rules:

- `usage_count` merges as max.
- Timestamps are second-granularity local clocks. **The backstop for ties and
  clock skew is deterministic tie-breaking + history**: any discarded version
  must be recoverable from history. Merge never silently destroys data.
- Merge results are reported to the UI via `MergeSummaryDto` ("merged, N spots
  resolved to the newer version"); the UI takes part in no merge decision (D5).

## Convergence requirements (these become tests)

Table-driven tests cover every cell of the matrix — including same-second tie
cases — plus two property tests:

1. **Two-sided convergence**: A merge B and B merge A produce semantically
   equivalent vaults (same entry set, locations, and history sets).
2. **Idempotence**: merging the same input twice equals merging it once.

Third-party semantics (KeePassXC move/delete/history behavior) are validated
against real fixture files, not assumed.

## Platform and process constraints

- Only the resident app performs sync and writes the KDBX file (D4/003);
  extensions read the cached copy in the app group container and may see stale
  data — **accepted**; no sync path is added for extensions.
- Extension-originated mutations (passkey registration, usage_count) are
  **journal-only** (003's journal contract): the app replays them into the
  vault, and they participate in the next save's merge like any other local
  change.

## Immediate fixes (do not wait for the new architecture; fix on main)

1. Local-file save CAS baseline misalignment (TOCTOU): the expected fingerprint
   for `write` must be the snapshot taken at merge time, not one re-read after
   `begin_write` acquires the lock.
2. OneDrive refresh token stored as a plaintext file: move into each platform's
   secure storage (DPAPI / Keychain / Keystore).
3. Windows quick unlock records use non-atomic `fs::write`: unify on the
   durable atomic write path.
