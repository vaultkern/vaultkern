# 003 — Quick Unlock State Machine and Process Topology

Status: **Decided**. 2026-07-12.
Upstream decisions: D3, D4, D5 (000).

## Part 1: the quick unlock state machine (platform-neutral, designed once)

### Source of truth

One persistent ledger per extension scope (reusing the vault-references store's
durable atomic write + exclusive lock pattern), one row per vault:

```
QuickUnlockLedgerEntry {
    state:      Disabled | Enrolled | NeedsReenroll(reason) | Revoked,
    generation: u64,          // monotonically increasing, baked into the envelope AAD
    policy:     bool,         // user intent (quick unlock enabled or not)
}
```

**Records in platform secure storage (Keychain/Keystore/CNG) are ciphertext
caches indexed by generation**: a mismatch of `generation` or `kdf_generation`
(002) is equivalent to non-existence. Consequently:

- **Revocation/rotation = generation+1 or state=Revoked in the ledger — one
  atomic write completes it.** Physically deleting old records is background
  best-effort; failure is harmless (old records are already cryptographically
  dead).
- **Records are never auto-deleted on error** (the principle the Touch ID
  branch needed four commits to arrive at, here fixed as an axiom): errors
  drive state transitions, never destruction.
- The Touch ID branch's five parallel states (suppressed / invalidation
  tombstones / poison flag / process_authorizations / refresh_pending) are all
  abolished or demoted to values derived from the ledger. UI-visible state =
  `f(ledger, current operation result)` — a single function, table-testable.

### State transitions (the core table; every transition gets a table-driven test)

```
Disabled        --enable (requires password-unlocked session)-->  Enrolled(gen+1)
Enrolled        --unlock success-->                               Enrolled
Enrolled        --PermanentlyInvalidated-->                       NeedsReenroll(biometry_changed)
Enrolled        --kdf_generation mismatch (002)-->                NeedsReenroll(kdf_rotated)
Enrolled        --TemporarilyUnavailable/Cancelled-->             Enrolled (unchanged! report only)
NeedsReenroll   --next successful password unlock-->              Enrolled(gen+1, automatic re-seal)
any             --user disables policy-->                         Revoked → Disabled
```

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

## Part 2: process topology (identical on all four platforms)

```
                    ┌──────────── resident app (one per platform) ────────────┐
                    │ Rust core (UniFFI): vault session, sync, state machine,  │
                    │ policy. Sole owner of runtime state; may exit in the     │
                    │ background and recover from the persistence layer.       │
                    └──┬──────────────┬───────────────┬───────────────────────┘
   browser extension ── thin shim ┘   system extension    UI (SwiftUI/Compose/Web)
   (native messaging               (credential provider /  (DTO projection,
    → forwarded over local IPC)     autofill service)        zero state)
```

### Fixed rules

1. **Vault writes are serialized by a single OS-level writer lock** (note:
   single-writer *lock*, not single-writer *process* — passkey registration
   happens in the extension process, and forbidding extension writes would make
   system-level passkeys unimplementable).
   - Lock available ⇒ write directly (walking the 001 merge flow);
   - Lock unavailable (the main app is writing) ⇒ append to a journal in the
     app group container; the main app replays and merges on resume.
   - Lock implementation: file locks must **fail fast with a timeout** (the
     current ExclusiveFileLock blocks indefinitely; abolished).
2. **The browser extension only ever speaks native messaging to the shim**; the
   shim is stateless and logic-free — forwarding plus peer authentication only.
   macOS: XPC + code-signing requirement; Windows: named pipe + SID check. The
   Touch ID branch's "verify the parent process is Chrome" mechanism is
   abolished in the app world (the trust boundary moves to the shim↔app
   channel).
3. **Extension read path**: the cached vault copy in the app group container +
   the envelope in shared secure storage (002). Stale reads are possible —
   accepted (001).
4. **The protocol is the single behavioral spec**: every client (three UIs, the
   shim, extension bridges) consumes protocol DTOs only. The protocol gains a
   `protocol_version` + capability handshake (extension-store review lag makes
   old/new coexistence the norm, not an anomaly).
5. **Runtime modularization precedes UniFFI**: extract `QuickUnlockCoordinator`,
   `SyncCoordinator`, and `VaultSession` out of runtime.rs (12k+ lines); the
   FFI surface exposes module interfaces only. The god file must not become a
   dependency shared by four platforms.

### Lifecycle notes

- Desktop (macOS): the app is resident (an LSUIElement menu-bar form is
  optional); Chrome only ever spawns the shim. The entire problem domain of
  multiple native host processes concurrently writing state disappears.
- Windows transition period: status quo remains (extension + per-port native
  host), but the state layer uses this document's ledger design directly
  (shared Rust core, no platform fork); convergence to the resident app happens
  in the plugin-authenticator phase.
- Mobile: after the system kills the main app, the extension must complete the
  full chain independently — "biometric → envelope unseal → read cached copy →
  fill" (002 guarantees its memory feasibility).

## Testing doctrine (D5 expanded; applies uniformly to 001/002/003)

1. State machine and merge semantics: table-driven + property tests inside the
   Rust core, platform-independent, all run in CI.
2. Platform providers: fakes injected at the trait boundary (existing pattern
   kept); on-device integration tests cover only "can enroll, can unseal, error
   mapping correct" — ≤ 10 per platform.
3. grep-as-test (source-text assertions) is banned. Packaging/signing
   verification is delegated to the Xcode/Gradle toolchains — no more
   hand-written contract tests for it.
