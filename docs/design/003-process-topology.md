# 003 — Process Topology

Status: **Stable — r14** (rewritten in the r16 scope reset; the quick-unlock
state machine and the journal contract are retired — see 002's unlock blob
and the outbox below). 2026-07-19.

## Shape (one target, all platforms)

The **resident app** hosts the Rust core (UniFFI): vault session, sync,
policy. It is the sole owner of runtime state and the sole KDBX writer.
Everything else is a client: the browser extension (through a thin shim),
system credential extensions, and the UI layers.

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
4. **The browser extension speaks native messaging to a stateless shim**,
   which forwards over authenticated local IPC. Mutual peer authentication
   (macOS XPC with a code-signing requirement; Windows named pipe with a
   restrictive ACL and SID check, impersonation rejected). Length-prefixed
   framing with a hard maximum; request IDs with timeout and cancellation.
   Commands that release secrets or change policy require fresh interactive
   verification regardless of channel trust. A peer failing the signature
   requirement is refused — no degraded mode.
5. **Protocol**: clients consume DTOs only. Handshake negotiates
   `{protocol_version, capabilities}`; changes are additive within a major
   version. Runtime modularization precedes UniFFI — the FFI exposes module
   interfaces, not a god file.

## Access matrix

| Actor | reads | writes KDBX | outbox |
|---|---|---|---|
| resident app | vault | **sole writer** | consumes |
| Apple appex | cached copy + own outbox items | never | appends |
| browser extension / shim | via protocol only | never | never |

The OS writer lock serializes local file access; the remote copy is
serialized by the sync layer's ETag CAS (007). The two compose and do not
overlap.
