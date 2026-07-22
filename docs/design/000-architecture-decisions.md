# 000 — Architecture Decisions

Status: **Stable — r17** (resident-owned browser integration). 2026-07-22. Changes go through
ordinary PR review; only 002's cryptographic content gets strict review. The
retired Phase-0 contract set lives in `archive/` as historical record; r1–r15
are in git history.

## Product

vaultkern is a personal credential manager — passwords, TOTP, passkeys —
built as native apps over one shared Rust core. It is **not** a
KeePass-ecosystem co-editing tool: KDBX is its storage container and escape
hatch, not an interoperability contract.

## Decisions

| # | Decision | Details |
|---|---|---|
| D1 | KDBX 4.x is the storage container. Opening an existing KeePass file **is** migration; the file itself **is** the export/escape hatch. vaultkern is the only routine writer; foreign writes are adopt-or-fork events, never silently blended | 007 |
| D2 | Unlock: one biometric-gated keychain blob per vault, `{master credential, cached transformed key}`. The cache validates against the file's own HMAC and refreshes on mismatch; the blob is the only unlock state (enrolled = blob exists; revoke = delete it). Keyfiles participate as content-hash contribution, never as a path | 002 |
| D3 | Process topology: the resident app owns runtime state, unlock, settings, and all KDBX writes. Apple credential-provider extensions hand completed operations to the app through a keychain outbox; the browser extension is a popup-only protocol client for current-origin autofill and passkey ceremonies, never receives unlock credentials, and never writes KDBX; Android services run inside the app process | 003 |
| D4 | Sync is file-level over user storage (OneDrive first), serialized by ETag/fingerprint CAS. Concurrent edits resolve by a base-copy three-way field patch; anything the patch cannot represent falls back to a recoverable conflict copy — never merge algebra or canonical hashes | 007 |
| D5 | The Rust core is the sole product substance (UniFFI); protocol DTOs are the single behavioral spec and FFI vocabulary, additive within a major version. Vault key-hierarchy material never appears in any DTO; entry secrets are zeroized in core-owned buffers, redacted in Debug/logs; secret-bearing DTOs do not derive Clone. UI renders DTOs and holds no business state | 003 |
| D6 | Platform floors: iOS 17+ / macOS 14+ / Android 14+ / Windows 11 (plugin-authenticator phase). No compatibility branches below | — |
| D7 | UI stacks: SwiftUI (one codebase for macOS+iOS), Compose (Android), and web UI for the Windows resident shell plus a minimal browser popup. Vault unlock, management, and settings surfaces live only in the resident app | — |
| D8 | Apple platforms use the data-protection keychain with access groups; the legacy file keychain, SecTrustedApplication, and SecAccessCreate remain banned | 002 |
| D9 | KDF parameters of externally created files are capped at open; extension processes never run a KDF | 002 |
| D10 | Pre-release: storage, unlock, and state formats ship without migration paths — re-enroll / re-save. The window closes at the first public release | — |

## Platform strategy

No fixed platform order and no capability-priority mandate. Pick a platform,
build its **vertical slice** end to end — app, unlock, storage, its
credential integration — evaluate the result, then decide the next platform.
Each slice starts with a small spike validating that platform's integration
assumptions. The capability map:

| Capability | Windows | macOS | iOS | Android |
|---|---|---|---|---|
| Biometrics | Windows Hello (CNG) | Touch ID (SE + LAContext) | Face ID (SE + LAContext) | BiometricPrompt + Keystore |
| System passkeys | plugin authenticator | ASCredentialProviderExtension | ASCredentialProviderExtension (shared with macOS) | CredentialProviderService |
| Autofill | browser extension | browser extension + credential provider | credential provider | AutofillService |

## Revision history

- r17 (2026-07-22): made the resident app the owner of browser-integration
  settings and reduced the browser extension to a popup-only client. The
  extension requests current-origin autofill from an already-unlocked
  resident session without per-fill Hello, while passkey operations retain
  WebAuthn user-verification requirements.
- r16 (2026-07-19): scope reset. KDBX demoted from interoperability contract
  to storage container; merge algebra, canonical serialization, and the
  contract-freeze ceremony retired (001/005/006 archived; 004's mission
  complete); quick unlock redesigned as a master-credential blob with a
  self-validating cache, replacing the envelope/generation machinery; the
  journal replaced by a keychain outbox; platform phasing replaced by
  vertical slices with no fixed order.
- r1–r15: see git history and `archive/`.
