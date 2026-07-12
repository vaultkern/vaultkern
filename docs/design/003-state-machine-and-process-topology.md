# 003 — Quick Unlock State Machine and Process Topology

Status: **Decided — r2** (revised after external review). 2026-07-12.
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
NeedsReenroll   --next successful password unlock-->              Enrolled(gen+1, automatic re-seal)
any             --user disables policy-->                         Disabled (single atomic write, above)
```

The transition table is **total** over (state × error category): table-driven
tests enumerate the full cross product, so no category can be handled by
accident of implementation.

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

1. **The resident app is the sole KDBX writer. Extensions never write the
   vault file.** Extension-originated mutations (passkey registration,
   usage_count) are appended to a persistent journal in the app group
   container; a WebAuthn ceremony completes once its journal append is durable.
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
   macOS: XPC + code-signing requirement; Windows: named pipe + SID check. The
   Touch ID branch's "verify the parent process is Chrome" mechanism is
   abolished in the app world (the trust boundary moves to the shim↔app
   channel).
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
    op_id:            UUIDv7,        // idempotency key; replay dedupes on it
    kind:             PasskeyRegistration | UsageCount | ...,
    payload:          kind-specific DTO,
    base_fingerprint: fingerprint of the cached vault the extension saw
                      (diagnostic only; replay does not require a match),
    created_at:       u64,
}
```

- **Storage**: append-only file per extension scope inside the app group
  container; fsync per append; the atomicity unit is one record — a truncated
  tail record is discarded at replay.
- **Replay**: idempotent by `op_id` (the applied-set high-water mark persists
  in the ledger store); application is a semantic merge per 001, not a byte
  patch; applied records are pruned only after a successful save.
- **Crash cases**: append-then-crash ⇒ applied exactly once via `op_id`;
  replay-then-crash-before-prune ⇒ next replay skips via the applied set;
  crash mid-append ⇒ the ceremony was never reported successful, and the
  truncated record is discarded.
- **Trust boundary**: the app group container is writable only by
  same-signature processes; that is the authentication of the journal. Payloads
  are still validated like any protocol input.

### Generation registry (all "generations" in one place)

| Identifier | Lives in | Changes when | Semantics |
|---|---|---|---|
| `record_generation` | quick unlock ledger | enroll / re-enroll / disable | monotonic ordering per (extension scope, vault) |
| `kdf_generation` | derived from the KDBX header (hash of KDF uuid + params + salt) | master-credential change (ours); any salt rotation (third parties) | equality check, not an ordering |
| vault fingerprint | storage layer / cache manifest | every save | identity check for CAS; not an ordering |
| pending-chain generation | remote cache manifest | each offline-queued save | ordering within one cached remote vault |

Relationships: envelope validity = `record_generation` matches the ledger AND
`kdf_generation` matches the file header — and a stale envelope also fails
closed cryptographically (002). Journal replay depends on none of these
(idempotency comes from `op_id`). Only `record_generation` and the pending
chain are orderings; the rest are equality/identity checks.

### Access matrix

| Actor | read cached vault | write KDBX | append journal | write ledger | run KDF |
|---|---|---|---|---|---|
| resident app | yes | **sole writer** | (applies/prunes) | **sole writer** | yes |
| system extension | yes (+ own journal overlay) | never | yes | never | never |
| shim | no | no | no | no | no |
| browser extension | via protocol only | never | never (its writes are protocol commands) | never | never |
| Windows transition native host | yes | yes (under the writer lock) | n/a | yes (same core ledger code) | yes |

### Lifecycle notes

- Desktop (macOS): the app is resident (an LSUIElement menu-bar form is
  optional); Chrome only ever spawns the shim. The entire problem domain of
  multiple native host processes concurrently writing state disappears.
- **Windows transition period** (per D4's target/transition split): status quo
  remains (extension + per-port native host) with two binding constraints —
  the state layer uses this document's ledger via the shared Rust core (no
  platform fork), and all KDBX writes go through the writer lock. Convergence
  to the resident app happens in the plugin-authenticator phase.
- Mobile: after the system kills the main app, the extension must complete the
  full chain independently — "biometric → envelope unseal → read cached copy
  (+ journal overlay) → fill" (002 guarantees its memory feasibility).

### UI "zero state", precisely

Zero business state means: no persistent domain state, no reconciliation
logic, no caches that acquire authority of their own. Transient view state —
in-flight operation flags, error banners, the last DTO held for rendering — is
expected and allowed.

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
