# 000 — Architecture Decision Record (Phase 0)

Status: **Decided — r4** (three external review rounds). 2026-07-12.

This is the top-level decision record for the four-platform product form
(Windows / macOS / iOS / Android; Linux deferred). Every decision here is a
deliberate close-out: overturning any of them requires a new numbered document
explaining why — silent drift during implementation is not allowed. The three
load-bearing design documents (001/002/003) expand the decisions that need
detail; 004 is the salvage manifest for the `codex/macos-touch-id-quick-unlock`
branch (which will not be merged).

## Background summary

Post-mortem of the macOS Touch ID branch (38 commits / +11.7k lines / 20+ fixes):
the feature's technical choices were sound, but (1) state had no single owner
(one fact stored in five places), (2) the envelope stored a credential copy that
inevitably went stale, (3) the product form (headless native host) lagged behind
feature requirements (both Touch ID and system-level passkeys demand a real app),
and (4) branch scope was uncontrolled. This record closes out all four problem
classes at the design level.

## Decisions

| # | Decision | Expanded in |
|---|----------|-------------|
| D1 | KDBX is the on-disk format and the interoperability contract; sync = file-level sync + full semantic merge | 001 |
| D2 | The quick unlock envelope stores only post-KDF derived key material (the transformed key), never passwords or credential copies | 002 |
| D3 | The quick unlock state machine is platform-neutral and designed once: explicit per-vault state + a monotonic generation baked into the envelope AAD; records in platform secure storage are ciphertext caches, not sources of truth | 003 |
| D4 | The **target** process topology is identical on all four platforms: a resident app owns runtime state and is the sole KDBX writer; system extensions and the browser extension are clients (extensions append to a journal, never the vault file). Windows runs a **sanctioned transition topology** (extension + per-port native host) until the plugin-authenticator phase, under two binding constraints: its state layer uses the shared core ledger (no platform fork) and all KDBX writes go through the writer lock | 003 |
| D5 | The Rust core is the sole product substance, exposed via UniFFI; protocol DTOs are the single behavioral spec **and the FFI vocabulary** (initially crossing the FFI as JSON strings, typed bindings later), with version negotiation. Typed bindings are **generated from the same DTO schema** — field names, optionality, and enum representation have the protocol schema as their sole authority, so going typed is a representation change, never a semantic one; any field change follows the protocol's additive-versioning rule. Credentials appear only in dedicated input DTOs (unlock, credential change); key material never appears in any DTO (002). UI holds zero business state and zero policy — it renders DTOs and sends commands; transient view state is allowed, persistent domain state and reconciliation logic are not | 003 |
| D6 | Platform floors: iOS 17+ / macOS 14+ / Android 14+ / Windows 11 (for the plugin-authenticator phase). No compatibility branches below these | — |
| D7 | Three UIs: SwiftUI (one codebase for macOS+iOS), Compose (Android), Web (browser extension + Windows desktop for now). The macOS manager goes straight to SwiftUI — no WebView transition period | — |
| D8 | Both Apple platforms use the data protection keychain + keychain-access-groups. The file-based legacy keychain, SecTrustedApplication, and SecAccessCreate are banned from the codebase | 002 |
| D9 | KDF parameters of externally-created KDBX files are capped (desktop requires explicit confirmation above the cap; extension processes never run the KDF — envelope path only) | 002 |
| D10 | Compatibility baseline: the product is pre-release. The redesign of envelope formats, state storage, and the key hierarchy ships without migration — re-enroll everywhere. This window closes at the first public release | — |

## Platform integration matrix (fixed together with D6)

| Capability | Windows | macOS | iOS | Android |
|------------|---------|-------|-----|---------|
| Biometrics | Windows Hello (CNG) | Touch ID (SE + LAContext) | Face ID (SE + LAContext) | BiometricPrompt + Keystore (StrongBox where available) |
| System-level passkeys | plugin authenticator (last) | ASCredentialProviderExtension | ASCredentialProviderExtension (shared code with macOS) | CredentialProviderService (Credential Manager) |
| Autofill | browser extension | browser extension + credential provider | credential provider | AutofillService |
| UI | shared-web-ui (interim) | SwiftUI | SwiftUI (shared with macOS) | Compose |
| Sequence | status quo serves; last in queue | Phase 1 | Phase 2 | Phase 3 |

Phase 2 (iOS) precedes Android because iOS reuses everything Phase 1 produces
(UniFFI bindings, the SE envelope Swift, the AuthenticationServices extension,
the SwiftUI screens) — it is the highest-reuse step.

The per-platform integration schemes in this matrix are **target designs, not
verified feasibility claims** — no platform shell exists on main yet. Each
phase's first milestone is a spike with explicit pass criteria; feature work
does not build on an unvalidated assumption:

- **iOS spike passes when**: a credential provider extension on a real device
  completes "biometric unseal → decrypt a cached 1000-entry vault → return a
  credential" within the extension memory ceiling.
- **Apple shared-keychain spike passes when**: the app and the extension read
  and write the same data protection keychain record through an access group,
  and `.biometryCurrentSet` invalidation behaves as 003 assumes (enrollment
  change ⇒ PermanentlyInvalidated).
- **Android spike passes when**: a CredentialProviderService completes a
  minimal passkey registration + assertion round-trip against the Rust core.
- **Background-lifecycle spike (both mobile platforms) passes when**: the
  extension completes its full chain with the main app killed.

## Execution discipline

1. No implementation code before 001/002/003 are complete and frozen. **The
   contract freeze (004) is the final Phase 0 deliverable**, not the first
   Phase 1 task: CacheManifest, JournalRecord, LedgerEntry, the canonical
   serialization byte layout, and the MergeSummaryDto extension are pinned as
   concrete schemas before any consumer is written. The canonical source of
   the protocol schema is the Rust types in `vaultkern-runtime-protocol`
   (serde); a generated JSON Schema artifact is checked in, and CI snapshot-
   diffs it to enforce additive-only evolution.
2. Any business state or reconciliation logic appearing in a UI layer is an
   architecture violation (Touch ID branch lesson: the UI-side reconciliation
   code was ultimately deleted wholesale, −465 lines).
3. A single feature branch must not touch multiple decision domains;
   packaging/signing/release infrastructure stays out of feature branches.
4. Testing doctrine: state-machine behavior is covered by table-driven tests in
   the Rust core; platform providers get thin integration tests only; source-text
   assertions (grep-as-test) are banned.

## Revision history

- r1 (2026-07-12): initial version.
- r2 (2026-07-12): revised after an external adversarial review (Codex). D4
  split into target/transition topology; D5 pins the FFI vocabulary; 001 gains
  the per-type merge algebra and a workable same-second tie rule; 002 gains the
  envelope↔cache binding posture and the KDF-cap enforcement point; 003 gains a
  total transition table, the journal contract, the generation registry, and
  the access matrix; extensions are now journal-only writers.
- r3 (2026-07-12): second review round. Tombstones are never auto-pruned
  (offline-replica resurrection); Meta merge drops file-mtime for per-field
  timestamps + content-hash fallback; journal gains two correctness layers
  (semantic idempotence of every op + applied set bound to the durable save;
  increment ops forbidden; seq + CRC framing; dead-letter); "master-credential
  change" corrected to "collect at least one credential"; CacheManifest wire
  format + content-addressed two-file commit; AES-KDF rounds cap;
  kdf_generation canonical encoding; totality formally defined; access matrix
  gains a target/transition mode column; D5 gains the JSON→typed migration
  rule and the key-material-in-DTO ban; platform matrix marked as
  target-not-verified with per-phase spikes; 004 gains the contract-freeze
  root node and the provider statelessness negative test.
- r4 (2026-07-12): third review round. Tombstones become fully permanent —
  the explicit compact escape hatch is removed, making convergence
  unconditional; the cross-store write-order axiom closes the ledger↔secure-
  storage transaction gap (seal first, ledger commit second, orphans inert by
  generation); the journal moves to single-writer segment files (dissolving
  seq allocation and append concurrency) with a bounded applied-set lifecycle
  tied to prune; AES-KDF caps get concrete rounds values; canonical
  serialization and kdf_generation encoding move into the contract freeze,
  which is now explicitly the final Phase 0 deliverable; spike pass criteria
  are made concrete; the dead-letter segment and the NeedsReenroll DTO nuance
  are specified.
