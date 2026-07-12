# 001 — Sync and Merge Semantics

Status: **Decided — r10** (seven external review rounds + two freeze-hardening rounds). 2026-07-13.
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
| DeletedObject | UUID. KDBX tombstones carry no type field — entry and group UUIDs share one global space; this is a format constraint, not a modeling gap, and adding a type field would break interoperability | union of both sides, keeping the **latest** deletion time per UUID; a tombstone wins against objects modified before it and loses against objects modified after it (edit-resurrects). The tombstone is itself an LWW fact: only the latest deletion event competes with the latest edit. Keeping the earliest would break delete→resurrect→delete-again (tombstone t=10, edit t=20 resurrects, delete t=30: an earliest-kept t=10 loses to the t=20 edit and the t=30 deletion vanishes; latest-kept t=30 wins — correct). **Retention: tombstones are permanent — no pruning of any kind, automatic or user-invoked.** Any pruning path (including an explicit "compact") re-opens resurrection by long-offline replicas and makes the convergence property conditional; permanence makes it unconditional. Tombstones are ~24 bytes each and deletions are rare in a password vault; the cost is accepted, and no maintenance operation is offered |
| Entry `custom_data` (untimestamped string map) | map key | key-level union; on a same-key conflict the value rides the entry winner (part of entry newest-wins) |
| `CustomDataItem` blocks (carry `last_modified`) | item key | newest-wins by `last_modified` |
| Custom icons | UUID | union; if the same UUID carries different data/name, newest-wins by the icon's `last_modified` where present, else byte-wise ordering of the content hash (same determinism family as the entry tie rule). **The losing icon version is discarded** — icons are decorative, carry no user secrets, and do not participate in history. Icon conflicts are still counted in `MergeSummaryDto` (`icon_conflicts_resolved`, alongside `meta_conflicts_resolved`) so the user can see that a configuration conflict occurred even though the loser is not kept |
| Meta / recycle-bin config | — | newest-wins by the per-field change timestamps KDBX Meta records (NameChanged, RecycleBinChanged, SettingsChanged, …). For the few fields with no timestamp, the fallback is byte-wise ordering of the field's canonical content hash — **never physical file mtime**, which is not a comparable clock across devices/transports. Resolved Meta conflicts are counted in `MergeSummaryDto` (this requires extending the current DTO — an additive protocol change: e.g. `meta_conflicts_resolved`) |
| Attachments | content (the binaries pool is content-addressed at serialization) | no independent merge — attachment references ride their entry version; the pool deduplicates identical bytes |

## Conflict matrix

Rows = local operation, columns = remote operation, cell = merge outcome.
"Newer wins" = by entry `modified_at`; the loser goes intact into the winner's
history (M4 union semantics); no conflict-copy files are created.

| local \ remote | edit | delete | move | no-op |
|---|---|---|---|---|
| **edit** | newer wins, loser into history; same-second ties broken by the tie rule below | edit time > deletion time ⇒ resurrect with the edit; otherwise deletion wins | edit and move are orthogonal: fields from the edit, location from the newer `location_changed_at` | local wins |
| **delete** | symmetric to top-right | deleted; the **later** deletion time enters `deleted_objects` (the tombstone is an LWW fact — see the DeletedObject rule) | deletion time > `location_changed_at` ⇒ deleted; otherwise the entry survives at the new location | deletion propagates |
| **move** | symmetric | symmetric | newer `location_changed_at` wins | local location |
| **group rename/attrs** | — | group deletion vs. newer entries inside ⇒ the group survives (entries are never orphaned) | — | local wins |

**Tie rule (same-second conflicts).** Both versions share the entry's UUID, so
UUID ordering cannot decide between them. When `modified_at` is equal, the
winner is chosen by byte-wise comparison of the two versions' canonical content
hashes (canonical serialization of the entry fields, excluding history). Both
devices compute the same ordering, so both converge on the same winner; the
loser enters history like any other loser.

**Canonical serialization** is a fixed, versioned encoding: field order and
optional-value encoding as defined by the protocol schema, UTF-8 strings,
history excluded, attachments represented by their content hashes (not bytes).
Its exact byte layout is pinned **in the contract freeze (the final Phase 0
deliverable, per 004) — before any merge code is written**, and carries a
`schema_version`; two implementations at the same version must produce
identical bytes, or same-second ties diverge.

Edge rules:

- `location_changed_at` absent is treated as the epoch (loses to any present
  value); if absent on both sides and the groups differ, the winner is chosen
  by byte-wise ordering of the two group UUIDs — deterministic on both ends.
  This corner is **arbitrary by necessity**: KDBX records only
  `previous_parent` + `location_changed_at`, no move lineage, and inventing a
  richer versioned location object would break interoperability (third-party
  tools would not maintain it). Both-sides-absent means a third-party file
  moved the entry without stamping a time — there is no reliable parent signal
  to prefer, so the rule optimizes for deterministic convergence, with history
  preserving the losing version's fields as always.
- Re-creating an object with a previously deleted UUID is the edit-resurrects
  rule in action (new `modified_at` > deletion time ⇒ the object wins). Our
  own implementation always generates fresh UUIDs for new objects; UUID reuse
  is only ever encountered from third-party files.

Supplementary rules:

- `usage_count` merges as max.
- Timestamps are second-granularity local clocks. **The backstop for ties and
  clock skew is deterministic tie-breaking + history**: any discarded version
  of **entry data** must be recoverable from history, **subject to the
  vault's own history retention policy** (maxItems/maxSize). Retention is the
  single, deliberate, user-controlled exception: merge losers enter history
  like any other snapshot and age out under the same policy as any other
  snapshot — **merge itself never discards entry data outside of what
  retention would**. No separate conflict archive is introduced (it would
  live outside the KDBX format and break interoperability). Meta fields and
  custom icons are explicitly exempt from this promise — they are
  decorative/configuration data, carry no secrets, and have no history
  mechanism in KDBX; their losers are discarded but counted in
  `MergeSummaryDto` (consistent with the CustomIcon rule above).
- Merge results are reported to the UI via `MergeSummaryDto` ("merged, N spots
  resolved to the newer version"); the UI takes part in no merge decision (D5).

**Capacity posture for permanent tombstones**: at ~24 bytes each, even ten
thousand lifetime deletions cost ≈ 240 KB — negligible against attachments in
any realistic vault. The tombstone count is surfaced in diagnostics; there is
no silent growth and no GC. Retiring a pathological vault's history is a
support procedure, not a protocol feature; its minimal form is three steps:
(1) export entries and attachments into a fresh vault, (2) re-enroll quick
unlock on every device, (3) archive the old vault read-only.

## Convergence requirements (these become tests)

Table-driven tests cover every cell of the matrix — including same-second tie
cases — plus two property tests:

1. **Two-sided convergence**: A merge B and B merge A produce semantically
   equivalent vaults (same entry set, locations, and history sets).
2. **Idempotence**: merging the same input twice equals merging it once.

Third-party semantics (KeePassXC move/delete/history behavior) are validated
against real fixture files, not assumed.

## Platform and process constraints

- In the target topology, only the resident app performs sync and writes the
  KDBX file (D4/003). **Windows transition exception** (per D4): the per-port
  native host writes under the OS writer lock until the plugin-authenticator
  phase. Extensions read the cached copy in the app group container and may
  see stale data — **accepted**; no sync path is added for extensions.
- **System-extension** mutations (passkey registration, usage_count) are
  **journal-only** (003's journal contract): the app replays them into the
  vault, and they participate in the next save's merge like any other local
  change. **Browser-extension** mutations are ordinary protocol commands
  executed inside the app (or transition-period native host) process — they
  never touch the journal.

## Immediate fixes (do not wait for the new architecture; fix on main)

1. Local-file save CAS baseline misalignment (TOCTOU): the expected fingerprint
   for `write` must be the snapshot taken at merge time, not one re-read after
   `begin_write` acquires the lock.
2. OneDrive refresh token stored as a plaintext file: move into each platform's
   secure storage (DPAPI / Keychain / Keystore).
3. Windows quick unlock records use non-atomic `fs::write`: unify on the
   durable atomic write path.
