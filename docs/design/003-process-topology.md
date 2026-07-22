# 003 — Process Topology

Status: **Stable — r15** (r15 adds rule 7, settings as desired state; r14
was rewritten in the r16 scope reset — the quick-unlock state machine and
the journal contract are retired, see 002's unlock blob and the outbox
below). 2026-07-21.

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
4. **The browser extension speaks native messaging to a stateless shim**,
   which forwards over authenticated local IPC. Mutual peer authentication
   (macOS XPC with a code-signing requirement; Windows named pipe with a
   restrictive ACL and SID check, impersonation rejected). Length-prefixed
   framing with a hard maximum; request IDs with timeout and cancellation.
   Commands that release secrets or change policy require fresh interactive
   verification regardless of channel trust. A peer failing the signature
   requirement is refused — no degraded mode.
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
   credential-metadata sync, unlock-blob creation or revocation — runs as
   idempotent reconciliation, never inline in the save path. Reconciliation
   runs after a successful settings commit and after every unlock. Steps
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
| browser extension / shim | via protocol only | never | never |

The OS writer lock serializes local file access; the remote copy is
serialized by the sync layer's ETag CAS (007). The two compose and do not
overlap.
