# 003 — Process Topology

Status: **Stable — r16** (r16 makes the browser integration a popup-only
client of the resident app; r15 added rule 7, settings as desired state;
r14 was rewritten in the r16 scope reset — the quick-unlock state machine
and the journal contract are retired, see 002's unlock blob and the outbox
below). 2026-07-22.

## Shape (one target, all platforms)

The **resident app** hosts the Rust core in-process: vault session, sync,
policy. Mobile/native-language shells reach that core through UniFFI; the
Windows Tauri app is Rust and calls it directly. The resident app is the sole
owner of runtime state and the sole KDBX writer. Everything else is a client:
the browser extension (through a thin shim), out-of-process system credential
extensions, and the UI layers.

## Rules

1. **The app is the sole KDBX writer.** Extensions never write the vault
   file. An OS-level writer lock remains as a defense layer and must fail
   fast with a timeout.
2. **Apple appex outbox.** Credential-provider extensions run as separate
   processes and cannot launch the app (iOS), so a completed operation — a
   newly registered passkey — is written as **one keychain item in the
   shared access group**: encrypted, atomic, and shared for free. The app
   consumes outbox items on activation: apply to the vault, save, delete the
   item. Items are keyed by credential ID and applied as create-or-update,
   so replaying an item after a crash between apply and delete is harmless.
   A WebAuthn ceremony completes once its outbox item is stored. The
   extension's read view is the vault's local working copy — which lives in
   the app group container precisely so extensions can read it — plus its
   own unconsumed outbox items, so a just-registered passkey can assert
   immediately. Registrations only — no usage-count relay.
3. **Android services run inside the app process.** They are the resident
   app: no outbox, no overlay, same writer lock.
   The Windows passkey plugin COM server follows the same ownership rule: it
   is hosted by the resident process family and calls the in-process core
   bridge directly, with no outbox.
4. **The browser integration is a popup-only client of the resident app.**
   It speaks native messaging to a stateless shim, which forwards over
   authenticated local IPC. The trust boundary is the fixed official
   extension ID plus a signed browser, shim, and resident app; Windows also
   applies a same-user named-pipe ACL and SID check and rejects
   impersonation. Length-prefixed framing has a hard maximum; request IDs
   have timeout and cancellation. A peer failing these checks is refused —
   no degraded mode. Reconnecting an authenticated channel does not require
   Hello; platform verification is reserved for operations whose own policy
   requires it. The extension never receives a master password or
   keyfile, never unlocks a vault, and has no vault-management or settings
   surface. The popup exposes only fixed routes that activate the resident
   app's unlock, vault-management, or settings UI. While unlocked, it may request
   origin-scoped autofill credentials from the current resident session
   without per-fill Hello; locking revokes subsequent requests. A user-confirmed
   login save or update is an optimistic mutation request to the resident app,
   which remains the only KDBX writer. Passkey ceremonies remain available,
   but every operation that requires WebAuthn user verification performs fresh
   platform verification and cannot reuse autofill authorization. Policy
   changes remain resident-app-only.
5. **Windows target.** The Tauri resident app owns the in-process Rust core.
   The native-messaging executable is a stateless shim into that resident
   process, while the passkey COM server is hosted by the resident process
   family and calls the same core bridge. Neither owns a second runtime.
6. **Protocol**: clients consume DTOs only. Handshake negotiates
   `{protocol_version, capabilities}`; changes are additive within a major
   version. Runtime modularization precedes UniFFI — the FFI exposes module
   interfaces, not a god file.
7. **Settings are desired state.** Saving settings persists the desired
   state and nothing else — the settings store, or vault fields through the
   normal save path. The save succeeds or fails on that persistence alone;
   on failure nothing has changed and the user's draft stays. Everything
   that makes the world match the settings — OS provider registration,
   browser passkey-proxy attachment or detachment, credential-metadata sync,
   unlock-blob creation or revocation — runs as idempotent reconciliation,
   never inline in the save path. The resident app is the single owner of
   settings; browser clients receive a read-only projection and reconcile
   their local proxy on startup, browser wake, and a periodic retry.
   The resident boundary rejects new browser passkey work while the saved
   browser-proxy setting is off, even if browser-side detachment is stale or
   failed; ledger cleanup remains retryable. System-provider callbacks are
   likewise disabled from desired state before unregistering, so a failed OS
   unregister leaves a harmless stale registration rather than a live policy
   bypass. Reconciliation runs after a successful settings commit and after
   every unlock. Steps
   that need vault data are skipped while the vault is locked — skipped,
   never executed against empty data — and the next unlock applies them;
   steps that don't need the vault run immediately. A skipped or crashed
   reconciliation is harmless: the next reconciliation point converges
   actual state to the saved settings.

## Access matrix

| Actor | reads | writes KDBX | outbox |
|---|---|---|---|
| resident app | vault | **sole writer** | consumes |
| Apple appex | cached copy + own outbox items | never | appends |
| Windows passkey provider | via resident in-process bridge | resident app writes | never |
| browser extension / shim | current-origin autofill, confirmed login-mutation, and passkey DTOs via protocol only | never | never |

The OS writer lock serializes local file access; the remote copy is
serialized by the sync layer's ETag CAS (007). The two compose and do not
overlap.
