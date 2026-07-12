# 004 — Touch ID Branch Salvage Manifest

Status: **Decided**. 2026-07-12.
Subject: `codex/macos-touch-id-quick-unlock` (38 commits, +11.7k/−1.0k,
**will not be merged**). The branch is kept as a read-only reference; items are
carried over per the tables below, **remade** to the 000–003 designs rather than
cherry-picked verbatim (most code on that branch grew around decisions that are
now abolished).

## Carry over (design assets, remade into the new implementation)

| Asset | Branch location | How it carries over |
|-------|-----------------|---------------------|
| SE envelope cryptography (P256 ECDH + HKDF + AES-256-GCM, biometryCurrentSet, non-interactive re-seal via SE public key) | ~1/3 of `SecureEnclaveBridge.swift` (create/derive/restore entry points + accessControl/derivedKEK); `macos_secure_enclave.rs` FFI marshalling and ForeignBuffer zeroing | Payload switches to the transformed key per 002; storage layer rewritten for the data protection keychain (D8); shared across both Apple platforms |
| `QuickUnlockProvider` trait seam (unified enable/unlock/refresh/delete lifecycle) | commits 33d03f0, e3ec509 | Interface kept; the macOS-leaked capability flags (`requires_same_process_credential_proof` etc.) are removed — platform policy moves into the 003 state machine |
| Durable atomic write + exclusive file lock pattern | commits 5107a64, 7c48131 (vault_reference_store.rs, durable_file) | Pattern carries over as the ledger storage layer; the lock changes to fail-fast with timeout (003) |
| Field-tested error-mapping knowledge (temporary vs. permanent) | classification fixes in commits 63b35cc, 08d3443 | Feeds the four-platform mapping table in 003; classification happens once on the Rust side, Swift passes domain/code through |
| The "policy belongs to the runtime, state as protocol DTOs" direction | protocol commands + `QuickUnlockStateDto` from commit 9c33985 | DTOs remade around the 003 ledger states (the six-branch capability match collapses) |
| Knowledge of the native-messaging main-thread block vs. Cocoa run loop deadlock | commit 9f0bc94 | In the app world, LA interaction happens in the app process and the problem disappears; the shim stays UI-free |
| Behavioral-test methodology for packaging scripts (fake codesign + really running the script + rollback assertions) | latter half of `macos_package_contract.rs` | Methodology only, for future installer scripts; the tested object itself is discarded |

## Independent fixes (unrelated to the new architecture; fix directly on main — see end of 001)

1. OneDrive refresh token stored as plaintext on disk → platform secure storage.
2. Local-file save CAS baseline TOCTOU window.
3. Windows quick unlock records written with non-atomic `fs::write`.
4. No cap on KDF parameters of external KDBX files (D9).

## Discard (not carried over; reasons on record)

| Item | Reason |
|------|--------|
| The entire legacy file-based login keychain + SecTrustedApplication ACL machinery (~2/3 of the Swift bridge: global interaction toggle, per-call ACL re-validation, SecAccessCreate) | Deprecated by Apple; incompatible with the app+extension dual-executable form; no iOS counterpart; banned by D8 |
| `package_macos.sh` / `install_native_host_macos.sh` / signing-identity continuity checks | The whole problem domain disappears once Xcode owns packaging and signing |
| First half of `macos_package_contract.rs` (~1000 lines of source-text grep assertions) | grep-as-test; banned by doctrine |
| The "verify the parent process is Chrome-signed" caller binding | Trust boundary moves to the shim↔app channel (003) |
| The five parallel states (suppressed / tombstones / poison flag / process_authorizations / refresh_pending) and all reconciliation logic | Replaced by the 003 ledger |
| Implicit refresh after manual unlock, delete-record-on-failure, and other mechanisms the branch itself overturned | Falsified on the branch itself |
| The parts of `MemoryQuickUnlockProvider` that baked macOS capability flags into the test contract | Removed together with the trait cleanup |
| The macOS osascript KDBX picker | The app world uses native NSOpenPanel/file pickers |
| The objc2 + hand-written run loop pump of the second LocalAuthentication integration (macos_local_authentication.rs) | LA converges to a single path (inside the app process) |
| The `chrome.webAuthenticationProxy` takeover pipeline (webauthnProxy.ts, 7.5k lines, on main) | Not on this branch, but classified here per D4/platform matrix: demoted to a Windows/Chrome transition measure once system-level passkeys land; no further investment |

## Sequencing

1. Phase 0 (the branch holding this document): the three design documents are
   frozen.
2. The four independent fixes can proceed at any time; they do not depend on
   Phase 0.
3. When Phase 1 starts, carry-over items are remade one by one per the table —
   one focused PR per item; bulk transplants are forbidden.
