# 003 — Quick Unlock State Machine and Process Topology

Status: **Frozen — r12** (seven external review rounds + four freeze-hardening rounds). 2026-07-13. Amendments only via the 000 revision process; contracts evolve additively per the 003 version matrix.
Upstream decisions: D3, D4, D5 (000).

## Part 1: the quick unlock state machine (platform-neutral, designed once)

### Source of truth

One persistent ledger per extension scope (reusing the vault-references store's
durable atomic write + exclusive lock pattern), one row per vault:

```
QuickUnlockLedgerEntry {
    state:      Disabled | Enrolled | NeedsReenroll(reason),
    generation: u64,          // monotonically increasing, baked into the envelope AAD
    policy:     bool,         // user intent (quick unlock enabled or not)
}
```

**Records in platform secure storage (Keychain/Keystore/CNG) are ciphertext
caches indexed by generation**: a mismatch of `generation` or `kdf_generation`
(002) is equivalent to non-existence. Consequently:

- **Disable/rotation = one atomic ledger write** (`policy=false, state=Disabled,
  generation+1`). There is no separate `Revoked` ledger state: the write itself
  is the revocation, because generation mismatch makes every existing record
  cryptographically dead. Physical deletion of old records is background
  best-effort; failure is harmless. "Cleanup pending" is a **derived display
  state** (Disabled/rotated while an old-generation platform record still
  physically exists), never a stored state.
- **Records are never auto-deleted on error** (the principle the Touch ID
  branch needed four commits to arrive at, here fixed as an axiom): errors
  drive state transitions, never destruction.
- The Touch ID branch's five parallel states (suppressed / invalidation
  tombstones / poison flag / process_authorizations / refresh_pending) are all
  abolished or demoted to values derived from the ledger. UI-visible state =
  `f(ledger, current operation result)` — a single function, table-testable.

### Cross-store write-order axiom (enroll / re-seal / disable)

Ledger and platform secure storage are two stores; no cross-store transaction
exists, and none is needed — the ordering rule plus generation semantics *is*
the transaction:

- **Precondition — the platform record key contains the generation**:
  records are physically stored under
  `(identifier_scope, vault_ref_id, record_generation)` (002). Sealing
  `gen+1` therefore creates a **new** record and never overwrites the current
  one. An overwrite-in-place implementation would falsify this entire axiom
  (the crash window would destroy the current record while the ledger still
  points at it); the LedgerEntry/secure-record contract pins this key
  structure, and the provider negative test (004) enforces it.
- **Enroll / re-seal: seal the platform record first (at `gen+1`), then commit
  the ledger** (one atomic write: `state=Enrolled, generation=gen+1`). The
  ledger write is the **only commit point**.
  - Seal fails ⇒ ledger untouched, nothing changed.
  - Seal succeeds, crash before the ledger write ⇒ the platform holds a
    `gen+1` record while the ledger still says `gen` — the `gen` record is
    untouched and still fully usable, the `gen+1` record is equivalent to
    non-existent (generation mismatch), a **harmless orphan**; the ledger
    state still tells the truth, and the next attempt seals at `gen+2` and
    cleans up best-effort.
- **Disable: the reverse order** — commit the ledger first
  (`Disabled, gen+1`), which cryptographically kills every existing record,
  then delete platform records best-effort (already specified above).
- Every crash interleaving therefore fails closed; "ledger says Enrolled but
  no usable record exists" is impossible by construction, and orphaned
  platform records are inert by generation mismatch.

### State transitions (total over the error taxonomy; every cell is tested)

```
Disabled        --enable (requires password-unlocked session; platform reports
                  NotEnrolled ⇒ refuse with guidance, no state change)--> Enrolled(gen+1)
Enrolled        --unlock success-->                               Enrolled
Enrolled        --PermanentlyInvalidated-->                       NeedsReenroll(biometry_changed)
Enrolled        --kdf_generation mismatch (002)-->                NeedsReenroll(kdf_rotated)
Enrolled        --TemporarilyUnavailable | UserCancelled-->       Enrolled (unchanged; report only)
Enrolled        --LockedOut-->                                    Enrolled (unchanged; UI additionally
                                                                  offers password unlock, which resets
                                                                  the platform lockout)
Enrolled        --NotEnrolled at runtime (biometrics removed in OS settings)-->
                    Apple:            surfaces as PermanentlyInvalidated
                                      (biometryCurrentSet) → NeedsReenroll
                    Android/Windows:  key still valid ⇒ treated as
                                      TemporarilyUnavailable (record kept;
                                      user directed to system settings)
NeedsReenroll   --next successful full-credential unlock-->       Enrolled(gen+1, automatic re-seal)
any             --user disables policy-->                         Disabled (single atomic write, above)
```

**Totality, precisely defined.** Error categories are inputs only to the
`Enrolled` unlock/re-seal operations; in `Disabled` there is no record to
operate on, and in `NeedsReenroll` quick unlock attempts are gated off
(refused with guidance toward a full-credential unlock) before any platform
call happens. The table is total in this form: for every (state, operation,
result-category) triple, **any triple not listed above means "refused or
no-op, no state change"** — and the table-driven tests enumerate the full
cross product to verify exactly that, so no cell's behavior is an accident of
implementation.

### Four-platform error taxonomy (defined once in the core; platforms only map)

| Core category | macOS/iOS (LAError/SE/Keychain) | Android (BiometricPrompt/Keystore) | Windows (Hello/NCrypt) |
|---|---|---|---|
| PermanentlyInvalidated | biometryCurrentSet invalidated, SE key voided | KeyPermanentlyInvalidatedException | Hello reset, key missing |
| TemporarilyUnavailable | biometryNotAvailable, passcode unset, system busy | HW_UNAVAILABLE, LOCKOUT (temporary) | device busy, service not running |
| UserCancelled | userCancel, systemCancel | USER_CANCELED, NEGATIVE_BUTTON | user cancelled |
| LockedOut | biometryLockout | LOCKOUT_PERMANENT (credential required) | locked out |
| NotEnrolled | biometryNotEnrolled | NO_BIOMETRICS | Hello not set up |

Misclassification (treating temporary as permanent) was fixed twice on the
Touch ID branch — once in Rust, once in Swift. This table is the single mapping
point; onboarding a new platform = fill in one column + run the same core test
suite.

## Part 2: process topology (one target shape; Windows transitions to it)

```
                    ┌──────────── resident app (one per platform) ────────────┐
                    │ Rust core (UniFFI): vault session, sync, state machine,  │
                    │ policy. Sole owner of runtime state, sole KDBX writer;   │
                    │ may exit in the background and recover from persistence. │
                    └──┬──────────────┬───────────────┬───────────────────────┘
   browser extension ── thin shim ┘   system extension    UI (SwiftUI/Compose/Web)
   (native messaging               (credential provider /  (DTO projection,
    → forwarded over local IPC)     autofill service)        zero business state)
```

### Fixed rules

1. **The resident app is the sole KDBX writer (target topology; the Windows
   transition exception is confined to the access matrix below). Extensions
   never write the vault file.** System-extension mutations (passkey
   registration, usage_count) are appended to a persistent journal in the app
   group container; a WebAuthn ceremony completes once its journal append is
   durable.
   The app replays the journal idempotently on activation, then saves through
   the 001 merge flow.
   - The extension's read view = the cached vault copy **plus an overlay of its
     own un-replayed journal records**, so a just-registered passkey can assert
     immediately.
   - The OS-level writer lock remains as a defense layer (Windows transition
     period runs multiple native hosts; the app also serializes internally).
     Lock acquisition must **fail fast with a timeout** (the current
     ExclusiveFileLock blocks indefinitely; abolished).
2. **The browser extension only ever speaks native messaging to the shim**; the
   shim is stateless and logic-free — forwarding plus peer authentication only.
   The Touch ID branch's "verify the parent process is Chrome" mechanism is
   abolished in the app world (the trust boundary moves to the shim↔app
   channel). The channel's security requirements (details pinned in the
   contract freeze):
   - **Mutual peer authentication**, both directions: macOS XPC with a
     code-signing requirement validated on the peer connection; Windows named
     pipe with a restrictive ACL, SID check, and impersonation rejected.
   - **Framing**: length-prefixed messages with a hard maximum size; request
     IDs with timeout and cancellation semantics.
   - **Replay posture**: this is local OS IPC, not a network — replay
     protection is the OS channel semantics plus request IDs; no additional
     cryptographic session layer is added.
   - **User-verification-required command class**: commands that release
     secrets or change policy are marked in the protocol and require a fresh
     interactive verification regardless of channel trust.
   - **Signature change**: a peer whose code signature no longer satisfies
     the requirement (upgrade gone wrong, resigned binary) is treated as
     untrusted — connection refused, no degraded mode.
3. **Extension read path**: the cached vault copy in the app group container +
   the envelope in shared secure storage (002) + its own journal overlay.
   Stale reads are possible — accepted (001).
4. **The protocol is the single behavioral spec and the FFI vocabulary** (D5):
   every client (three UIs, the shim, extension bridges) consumes protocol
   DTOs only; initially they cross the FFI as JSON strings, typed bindings
   later. Handshake: the client sends `{protocol_version, capabilities[]}`,
   the core answers `{accepted_version, capabilities[]}` and refuses versions
   below its minimum with a self-describing error DTO. Within a major version,
   changes are additive-only (extension-store review lag makes old/new
   coexistence the norm, not an anomaly).
5. **Runtime modularization precedes UniFFI**: extract `QuickUnlockCoordinator`,
   `SyncCoordinator`, and `VaultSession` out of runtime.rs (12k+ lines); the
   FFI surface exposes module interfaces only. The god file must not become a
   dependency shared by four platforms.

### Journal contract

```
JournalRecord {
    seq:              u64,           // diagnostic field — see the framing note
    op_id:            UUIDv7,        // idempotency identity of the mutation
    vault_ref_id:     string,        // plaintext: routing + pre-replay validation;
                                     // authenticated via the sealing AAD (below)
    payload_sealed:   bytes,         // AES-256-GCM ciphertext of the op vocabulary:
                                     // kind (PasskeyRegistration | UsageCount | ...)
                                     // + the kind-specific payload DTO
    nonce:            bytes,         // fresh random 12-byte per-record GCM nonce
    base_fingerprint: fingerprint of the cached vault the extension saw
                      (diagnostic only; replay does not require a match),
    created_at:       u64,
}
```

- **Payload sealing (at-rest confidentiality)**: the op vocabulary — `kind`
  plus its kind-specific payload DTO — is stored **sealed**:
  AES-256-GCM with `key = HKDF-SHA256(transformed, info =
  "vaultkern.journal.v1")`, a fresh random nonce per record, and
  `AAD = op_id ‖ vault_ref_id`. Rationale: the journal is the only on-disk
  location outside the vault itself that can hold secrets (a passkey
  registration carries the private key); the container's same-signature
  isolation argues **write integrity, not confidentiality** — sealing under
  a key derived from the vault session's `transformed` puts journal secrets
  in the same protection class as the vault body. Both sides can
  seal/unseal: the extension holds `transformed` after its biometric unseal
  (registration happens inside an already-unlocked autofill session by
  construction), and the app holds it after any unlock. The target
  `vault_ref_id` lives **only** in the plaintext record header — kept there
  for routing and pre-replay validation, bound into the AAD so it cannot be
  swapped; payload DTOs do not duplicate it.
- **Sealing vs. KDF rotation — drain before rotate**: sealed records are
  bound to the current `transformed`, so a master-credential change MUST
  first drain the journal (replay + prune to empty) and only then rotate
  `kdf_generation`. The credential-change flow first replays to the fixed
  point; records **still pending at that point are presented to the user
  as a list** with exactly two choices — discard them explicitly
  (dead-lettered with reason `user_discarded`) or abort the credential
  change. No new persisted ledger state is introduced: once the drain is
  empty the rotation completes atomically within the same session — there
  is no on-disk "rotation pending" state. Crash before the rotation ⇒
  nothing has changed; crash after ⇒ any leftover sealed records are
  undecryptable and follow the existing rule: dead-lettered (by copy, per
  the dead-letter rule below) with reason `kdf_rotated` and surfaced to
  the UI — the affected passkeys need re-registration. The corner case is
  made visible, never silent.
- **Framing (frozen byte layout)**: a segment file begins with the header

  `magic "VKJS" (4 bytes) ‖ format_version u16 LE`

  followed by zero or more record frames:

  `len u32 LE (byte length of body) ‖ record_version u16 LE ‖
  body (JournalRecord JSON, UTF-8) ‖ crc u32 LE`

  where `crc` is CRC-32/ISO-HDLC (the zlib `crc32`) computed over
  `len ‖ record_version ‖ body`. The **body is any valid UTF-8 JSON
  serialization conforming to the JournalRecord schema** — a writer uses
  its language's standard serializer; the CRC covers the exact bytes that
  writer wrote. **Cross-writer byte determinism is neither required nor
  assumed**: idempotence and dedup rest entirely on `op_id`, and no
  correctness property depends on the body's byte shape. (The only place
  that does require byte determinism is 005's canonical entry
  serialization — a binary encoding feeding the tie-break hash — which has
  nothing to do with journal JSON; 005's own Boundary note states the
  same separation from its side.) The maximum record length is **1
  MiB**, enforced in both directions: a writer refuses to append an
  oversized record, and a reader treats an oversized `len` as corruption.
  A record failing length or CRC checks is discarded and counted
  (surfaced to the UI as a diagnostic), never silently; sealed-EOF and
  corruption adjudication follows the three-case algorithm below.
  `base_fingerprint`, `created_at`, and `seq` are **diagnostic fields**:
  implausible values never cause a record to be rejected (only framing
  does). `seq` is normally monotonic within its writer's segment but
  plays no part in correctness; `seq` holes — a single writer that
  crashed mid-append — are tolerated. The **dead-letter file uses this same framing**; its
  body is a `DeadLetterRecord { reason, captured_at, frame_b64,
  region_len, archived_segment }` document that carries the original
  frame's **raw bytes** (`len ‖ record_version ‖ body ‖ crc`, standard
  base64) verbatim — never a re-serialization (size cap and truncation
  fields per the corruption-algorithm note below).
- **Storage — one segment file per writer, never shared**: each writer
  instance (an extension process) appends to its own segment file, named by
  its writer id (a per-instance UUID), inside the app group container
  (Windows target-state equivalent: a dedicated `%LOCALAPPDATA%` directory
  with a restrictive ACL; the Windows *transition* topology has no system
  extension and therefore no journal). Single-writer segments dissolve
  writer-vs-writer concurrency entirely: `seq` is allocated trivially by its
  sole writer (normally monotonic within the segment, but diagnostic only —
  correctness never depends on it), there is no append lock, no
  cross-process ordering, and no seq-hole recovery. Replay reads **all** segments and runs to a fixed point
  (below), which makes application order across segments irrelevant — for
  independent ops by semantic idempotence, and for dependent ops by
  re-passing. fsync per append; the atomicity unit is one record — a
  truncated tail record is discarded at replay.
- **Segment lifecycle and ownership — `active → sealed → replayed (logical)
  → deleted (logical)`**
  (writer-vs-pruner concurrency is dissolved by construction, not by care).
  On disk only two states exist: the active file and `*.sealed`; `replayed`
  and `deleted` are logical phases tracked via the applied set and file
  removal, not file suffixes:
  - A writer holds an OS advisory lock on its segment file for its entire
    lifetime. The app may **read** active segments at any time (for overlay
    and replay) but never renames, truncates, edits, or deletes them.
  - **Sealing is app-driven and lock-gated**: if the app can acquire a
    segment's lock, its writer is dead; the app atomically renames the file
    to `*.sealed`, claiming ownership. Writers never reopen old segments — a
    restarted extension is a new writer id with a new file — so a sealed
    segment provably has no living writer, and append-vs-prune overlap is
    impossible rather than unlikely.
  - **Deletion is whole-segment only**, and only when every record in the
    sealed segment is either in the applied set or moved to dead-letter.
    Records replayed out of still-active segments simply remain in the
    applied set until their segment is eventually sealed and deleted.
- **Fixed-point replay**: one replay pass applies every applicable record
  from every segment; passes repeat until a pass makes no progress. A
  creation in segment A and a dependent mutation in segment B therefore land
  regardless of scan order — the mutation applies one pass later at worst.
  Records still unapplicable at the fixed point are **pending**: they stay in
  their segment (blocking its deletion), are excluded from the applied set,
  and are retried on every future replay; a pending record whose target is
  confirmed dead (a newer tombstone) is dead-lettered (by copy, as above)
  with that reason.
  **Termination is a contract law, not a property of the current examples**:
  every journal op kind — present and future — MUST be idempotent
  (re-application to a vault already containing its effect is a no-op) and
  monotonic (applying one op never un-applies or oscillates another). A new
  `kind` cannot be added to the vocabulary without declaring its idempotence
  and monotonicity laws, its applicability predicate, and shipping a
  termination property test. Under these laws each pass strictly grows the
  applied set or halts, and the record count is finite — the fixed point
  always exists and is order-independent.
  **No segment compaction**: sealed segments are never rewritten. A pending
  record keeps its segment alive; that is accepted (records are tiny, pending
  is rare and surfaced to the UI) — compaction would rewrite files and
  complicate `op_id`/applied-set accounting for no real gain.
  **Capacity posture (growth is visible, not silent)**: journal segments are
  bounded by the replay/prune cadence in normal operation; what can persist
  is pending records and dead-letters, both of which are rare, tiny (one
  framed record each), and **surfaced as counts in the diagnostics DTO** —
  the design substitutes visibility for garbage collection. Recovering a
  pathological store (or retiring long-dead replicas) is a support procedure
  — export to a fresh vault — not a protocol feature.
- **Two correctness layers** (both required):
  1. **Semantic idempotence of every op kind**: applying an op to a vault that
     already contains its effect is a no-op. Passkey registration inserts by
     credential UUID under a **three-branch law**: (a) a credential with the
     same UUID exists and its stored data equals the record's full canonical
     payload ⇒ no-op; (b) same UUID but a differing payload ⇒ the record is
     dead-lettered (by copy) with reason `payload_conflict` — **silent
     overwrite and silent keep are both forbidden**; (c) no such UUID ⇒
     insert. No passkey update semantics exist (a WebAuthn private key has
     no update scenario; a re-registration arrives as a new credential
     UUID). Usage-count ops carry the observed value and merge as max —
     **increment-style ops are forbidden**. This makes correctness
     independent of applied-marker timing.
  2. **Applied tracking bound to the save, not to replay**: replay applies
     records to the in-memory vault only (no persistent marker written).
     Only after the 001 save flow durably commits does the app persist the
     **complete set of applied `op_id`s** — written into the ledger store
     document itself, in the same durable atomic write that records the saved
     vault's fingerprint (one physical commit, no cross-file ordering) — then
     prune those journal records. Layer 1 covers the residual window (crash
     after save, before the applied-set write: re-applying to a vault that
     already contains the effect is a no-op).
     **Applied-set lifecycle (bounded by construction)**: an applied entry
     exists only to skip a journal record that is still physically present;
     once that record is pruned it can never replay again, so its applied
     entry is deleted in the same maintenance pass. A crash between prune and
     drop leaves surplus applied entries, which the next pass removes by
     intersecting the applied set with the records that still exist
     (dead-letter records are outside this intersection — see below). The
     set's size is therefore bounded by the number of un-pruned journal
     records plus one maintenance window — it cannot grow without bound.

- **Maintenance ordering — publication-before-prune (the cache/journal
  commit boundary)**: the full post-replay sequence is pinned as

  `source save → CacheManifest publication (002) → applied-set commit →
  journal prune → applied-entry drop`

  The invariant: **a journal record may be pruned only after a durably
  published cache contains its effect.** "Contains its effect" holds **by
  construction**, not by per-record marking: the published cache is
  serialized from the exact post-replay merged vault that the save committed.
  Without this invariant, an extension whose acknowledged mutation was just
  pruned would see an old cache and no overlay — a confirmed passkey silently
  vanishing from its view. Crash matrix:

  | crash after… | journal | cache | extension view |
  |---|---|---|---|
  | save only | intact | old | overlay on old cache — mutation visible |
  | cache published | intact | new | overlay is a no-op (idempotence) — correct |
  | applied-set commit | intact | new | overlay no-op; next pass re-prunes |
  | prune | pruned | new | cache already contains the effect — correct |

  No interleaving makes an acknowledged mutation invisible.
- **Crash cases**: crash mid-append ⇒ the ceremony was never reported
  successful; the torn record fails CRC and is discarded. Crash after replay
  but before save ⇒ no applied marker exists; the next replay redoes the work.
  Crash after save but before the applied-set write ⇒ the next replay
  re-applies onto a vault that already contains the effect — a no-op by
  layer 1. No interleaving loses a durably-acknowledged mutation.
- **Replay-time validation**: payloads are validated like any protocol input,
  against the record's target `vault_ref_id` and the current ledger; a record
  that fails validation is **dead-lettered by copy, never by moving**: the
  original frame's raw bytes are captured **byte-for-byte** into a
  `DeadLetterRecord` appended to the app-owned dead-letter file (same
  framing) and its `op_id` is marked dead-lettered — the original stays
  untouched in its segment (active segments are never edited; the ownership
  rule holds without exception) and is excluded from replay by the
  dead-letter marking. Because the capture is the raw frame, unknown
  fields, the writer's original serialization, and even undecodable bodies
  survive intact; a retry re-parses from those bytes. No extra encryption
  layer is needed for the dead-letter file: the archived frame's payload
  is already sealed (under the HKDF(transformed) key), the only plaintext
  is the routing header — its at-rest protection is exactly that of the
  journal segments it copies from. When the
  segment is eventually sealed and deleted, dead-lettered `op_id`s count as
  resolved for the whole-segment-deletion accounting. Dead-letter records
  never enter the applied set and are invisible to the applied-set
  intersection maintenance — they cannot be mistaken for processed. They are
  not retried automatically; the user resolves them explicitly (retry once
  the cause is fixed, or discard). The dead-letter file itself is owned and
  written **only by the app** (its writes are serialized by the app
  internally; no lock ceremony needed).
- **Corrupt-record parsing algorithm (one rule set, no ambiguity)** — framing
  is sequential, so a bad record makes everything after it unreachable:
  1. **Sealed segment**: any length/CRC failure ⇒ the failing record and all
     unreachable bytes after it are definitively discarded and **counted**
     (surfaced as a diagnostic).
  2. **Active segment, failure at EOF** (trailing incomplete record): this
     may simply be an append in progress — skipped silently, not counted,
     re-examined next pass, adjudicated only at sealing.
  3. **Active segment, failure followed by further valid bytes**: genuine
     corruption, surfaced as a diagnostic immediately — but the file is
     still never edited; final accounting happens at sealing like case 1.
  The earlier "discarded and counted" framing rule is case 1/3; the torn-tail
  exception is exactly and only case 2.
  **Truncation is accepted by design; the unreachable bytes are archived.**
  No resync marker is added to the format: with tiny single-writer segments,
  mid-segment corruption is effectively hardware failure, and a resync
  scan cannot distinguish a genuine next frame from stale garbage that
  happens to frame-parse — so the design does not pretend to recover.
  Instead, the entire unreachable region (from the failing frame to EOF)
  is captured as **one** dead-letter entry — reason
  `corruption_unreachable`, `frame_b64` holding the raw unreachable bytes
  verbatim — and counted in the diagnostics surfaced to the UI. The bytes
  remain available for manual forensics: "never silently lost" is made
  literal.
  **Archive size cap (r12)**: a single dead-letter entry archives at most
  **1 MiB** of raw bytes — deliberately equal to the record cap, so a
  dead-letter entry is never larger than the largest legal record. A
  longer unreachable region stores its first 1 MiB as the prefix, records
  the full length in `region_len`, and the corrupt segment file itself is
  renamed to `*.corrupt` and kept whole in the container (named by
  `archived_segment`; never parsed again, read directly by the support
  procedure). Diagnostics DTOs carry only counts and sizes — never
  bytes.
- **Writer-id lifecycle**: a writer id is a fresh UUID per process instance,
  never reused. Segments of dead writers are replayed and pruned by the app
  like any other; a fully-pruned segment file is deleted.
- **Overlay on a stale cache**: a creation-type op (e.g. passkey
  registration creating a credential) synthesizes a provisional entry in the
  extension's read view; a mutation-type op whose target entry is absent from
  the stale cache is surfaced as pending-sync rather than applied — the
  authoritative application always happens in the app's replay+merge.
- **Trust boundary**: the container is writable only by same-signature
  processes — a **product security assumption** (platform code-signing
  isolation), not a cryptographic guarantee.

### Vocabulary evolution and the version matrix

Every enum in the frozen vocabulary has a defined unknown-variant
behavior — no reader may ever guess:

- **Protocol DTO enums**: an unknown variant fails that request with a
  self-describing error DTO. Capability negotiation (rule 4 above)
  prevents sending a new variant to a peer that never declared it, so
  this path is a defense layer, not the normal case.
- **Ledger — unknown `state`**: **fail closed.** Quick unlock for that
  vault is gated off exactly as in `NeedsReenroll` (treated as "this app
  is too old for this ledger"), surfaced to the UI with an
  update-the-app hint. The ledger is never guessed at and never
  rewritten by the older reader.
- **Journal — unknown op `kind`**: the record is dead-lettered (raw
  frame bytes preserved) with reason `unknown_kind`; the segment is not
  blocked. A newer app can later retry the dead-letter from its
  preserved bytes.
- **Unknown dead-letter `reason` strings**: displayed verbatim and
  handled generically (retry/discard); reasons are an additive
  vocabulary, not an enum.

Version fields, who increments them, and what a reader does when it
meets a higher one:

| Version | Level | Incremented when | Reader on higher version |
|---|---|---|---|
| segment `format_version` | file (segment header) | the frame byte layout itself changes | reject the **entire file**, fail closed, surface a diagnostic (an unreadable layout cannot be partially trusted) |
| `record_version` | frame | the JournalRecord body shape changes incompatibly | dead-letter that record (raw bytes preserved, `unknown_kind`-family semantics); the segment is not blocked |
| contract `SCHEMA_VERSION`s | JSON document (CacheManifest / JournalRecord / DeadLetterRecord / ledger) | an incompatible document change (additive changes do **not** increment) | as above per domain: cache manifest ⇒ treated as no cache (fail closed); ledger ⇒ quick unlock gated; journal ⇒ dead-letter with bytes preserved |
| `protocol_version` | handshake | protocol majors | below the core's minimum ⇒ refused with a self-describing error DTO (rule 4) |

**Additive-field iron law (r12)**: an additive field on `JournalRecord`
or on any op kind's payload MUST be **ignore-safe** — an old reader that
drops it must not change the replay semantics of the fields it does
understand; this is enforced at review time for every added field. Any
field whose omission would mis-replay the record is by definition an
incompatible change ⇒ bump `record_version`, and old readers dead-letter
it under the existing rule instead of silently mis-applying it. In one
line: **additive = ignore-safe; semantic = version bump ⇒ dead-letter.**

### Generation registry (all "generations" in one place)

| Identifier | Lives in | Changes when | Semantics |
|---|---|---|---|
| `record_generation` | quick unlock ledger | enroll / re-enroll / disable | monotonic ordering per (extension scope, vault) |
| `kdf_generation` | derived from the KDBX header: `H(canonical(KdfParameters VariantDictionary))` — the dictionary already contains `$UUID` and the salt as entries (002's single authoritative formula) | master-credential change (ours); any salt rotation (third parties) | equality check, not an ordering |
| vault fingerprint | storage layer / cache manifest | every save | identity check for CAS; not an ordering |
| pending-chain generation | remote cache manifest | each offline-queued save | ordering within one cached remote vault |

Relationships: envelope validity = `record_generation` matches the ledger AND
`kdf_generation` matches the file header — and a stale envelope also fails
closed cryptographically (002). Journal replay **ordering** depends on none
of these (idempotency comes from `op_id`); **unsealing** a record's payload
does require the `transformed` of the KDF generation it was sealed under —
the drain-before-rotate rule (journal contract) keeps that the current one,
and leftovers sealed under a rotated-away generation dead-letter as
`kdf_rotated`. Only `record_generation` and the pending chain are orderings;
the rest are equality/identity checks.

### Access matrix

| Actor | mode | read cached vault | write KDBX | append journal | write ledger | run KDF |
|---|---|---|---|---|---|---|
| resident app | target | yes | **sole writer** | (applies/prunes) | **sole writer** | yes |
| system extension | target | yes (+ own journal overlay) | never | yes | never | never |
| shim | target | no | no | no | no | no |
| browser extension | target | via protocol only | never | never — its mutations are protocol commands executed **inside the app process**; they never touch the journal | never | never |
| Windows per-port native host | **transition exception (D4)** | yes | yes (under the writer lock) | n/a (no system extension exists in this mode) | yes (same core ledger code) | yes |

The last row is the sanctioned D4 transition state, not part of the target
topology; it disappears at the plugin-authenticator phase. In the target
state the "sole KDBX writer" claim holds without exception.

Row scoping: the "system extension" row applies to **Apple appexes** (separate
processes). Android's AutofillService/CredentialProviderService run inside the
app process and therefore occupy the **resident app** row (see Lifecycle
notes) — they never use the journal.

Scope note: the OS writer lock serializes **local file access** only. The
remote copy (OneDrive) is serialized by the transport layer's eTag CAS (001);
the two mechanisms compose, they do not overlap.

### Lifecycle notes

- Desktop (macOS): the app is resident (an LSUIElement menu-bar form is
  optional); Chrome only ever spawns the shim. The entire problem domain of
  multiple native host processes concurrently writing state disappears.
- **Windows transition period** (per D4's target/transition split): status quo
  remains (extension + per-port native host) with two binding constraints —
  the state layer uses this document's ledger via the shared Rust core (no
  platform fork), and all KDBX writes go through the writer lock. Convergence
  to the resident app happens in the plugin-authenticator phase.
- **Android — no separate extension process, therefore no journal**: unlike
  iOS/macOS appexes, AutofillService/CredentialProviderService components run
  inside the app's own process, and the OS starts that process on demand —
  the service entry point *is* the resident app. Android therefore needs no
  app group container, no journal, and no overlay: service-originated
  mutations invoke the core in-process like any other app code path, under
  the same writer lock. The journal/overlay machinery exists only where the
  platform forces a separate extension process (Apple appexes). In the access
  matrix, Android services occupy the resident-app row, not the
  system-extension row. The 000 background-lifecycle spike validates the
  cold-start chain: process spawned by the system → ledger/cache/envelope
  read → biometric unseal → fill.
- Mobile (Apple): after the system kills the main app, the extension must
  complete the full chain independently — "biometric → envelope unseal → read
  cached copy (+ journal overlay) → fill" (002 guarantees its memory
  feasibility).

### UI "zero state", precisely

Zero business state means: no persistent domain state, no reconciliation
logic, no caches that acquire authority of their own. Transient view state —
in-flight operation flags, error banners, the last DTO held for rendering — is
expected and allowed.

One DTO nuance: in `NeedsReenroll`, the state DTO distinguishes "attempt gated
off before any platform call" from "a platform call was made and failed"
(derived from the current-operation result), so the UI can word the two cases
differently without owning any state.

## Testing doctrine (D5 expanded; applies uniformly to 001/002/003)

1. State machine and merge semantics: table-driven + property tests inside the
   Rust core, platform-independent, all run in CI. The transition table is
   tested as a total function over (state × error category).
2. Platform providers: fakes injected at the trait boundary (existing pattern
   kept); on-device integration tests cover only "can enroll, can unseal, error
   mapping correct" — ≤ 10 per platform.
3. Highest-risk boundaries get dedicated tests: journal crash-recovery and
   double replay; envelope↔cache binding and rollback posture; secure-storage
   record vs. ledger generation divergence; concurrent app + extension
   activity; KDF-cap bypass attempts; third-party KDBX fixtures for
   delete/move/history merges.
4. grep-as-test (source-text assertions) is banned. Packaging/signing
   verification is delegated to the Xcode/Gradle toolchains — no more
   hand-written contract tests for it.
