# 002 — Key Hierarchy and the Quick Unlock Envelope

Status: **Decided — r3** (two external review rounds). 2026-07-12.
Upstream decisions: D2, D8, D9, D10 (000).

## Derivation chain (current, unchanged)

```
raw_key        = SHA256( SHA256(password) ‖ keyfile_bytes ‖ provider_bytes )   // composite
transformed    = KDF(raw_key)          // Argon2id default 64 MiB / AES-KDF, params in file header
encryption_key = SHA256( master_seed ‖ transformed )                            // master_seed rotates every save
mac_seed       = SHA512( master_seed ‖ transformed ‖ 0x01 )
```

## Core decision: the envelope payload is the transformed key

**The quick unlock envelope seals only `transformed` (post-KDF key material)
plus a KDF-generation identifier — never the password, the key file path, or
any replayable user credential.**

```
EnvelopePayload {
    transformed_key: [u8; 32],
    kdf_generation:  H(kdf_uuid ‖ canonical(kdf_params)),   // bound to the KDF generation that produced it
}
envelope AAD ⊇ { vault_ref_id, identifier_scope, record_generation (see 003), kdf_generation }
```

`canonical(kdf_params)` = the KDBX VariantDictionary serialized canonically:
entries sorted by key, each as `key ‖ type-tag ‖ little-endian value bytes`
(this includes the salt/seed). The encoding is pinned and versioned with the
envelope format.

Rationale (two independent lines of reasoning converge, hence fixed):

1. **Consistency.** A credential copy inevitably drifts from the vault's real
   credentials — that drift was the root cause of the Touch ID branch's entire
   reconcile/refresh/tombstone chase. `transformed` is not a copy; it is a
   derived value: it expires precisely with its KDF generation, and expiry is
   decidable (`kdf_generation` mismatch) — no "guess whether the record is
   stale" error taxonomy required.
2. **Mobile hard constraint.** iOS credential provider extensions live within a
   memory ceiling in the tens of MB and cannot run Argon2 (64 MiB by default).
   Biometric unseal of `transformed` → `SHA256(master_seed ‖ transformed)` →
   decrypt, with zero KDF, is the only viable unlock path inside an extension.

Corollary: **quick unlock is repositioned from a convenience feature to the
first-class unlock mechanism for extensions.**

## KDF salt rotation policy (the key new decision in this document)

`transformed` is bound to the KDF salt; rotating the salt invalidates every
envelope. Therefore:

- **vaultkern's own saves do not rotate the KDF salt**; the salt is regenerated
  only when the master credential changes (password change / key file change /
  KDF parameter change). Cryptographically, a salt must be unique per vault —
  per-save rotation is not required; `master_seed` still rotates every save and
  carries that duty.
- **A master-credential change necessarily involves collecting at least one
  master credential and re-running the KDF** (a key-file swap or KDF-parameter
  change does not always re-prompt for the password), which is the natural
  re-enrollment point: the local device re-seals immediately with the new
  transformed key; other devices' envelopes fall into `NeedsReenroll` on
  `kdf_generation` mismatch and re-enroll automatically at their next
  full-credential unlock (see the 003 state machine) with no explicit user
  action.
- **Third-party tools (KeePassXC) may rotate the salt on save — degrade
  gracefully**: same path as above; `kdf_generation` mismatch ⇒ `NeedsReenroll`;
  desktop falls back to password unlock and recovers automatically; extensions
  show "unlock once in the main app first". This is a normal path, not an error
  path — no heuristic patching is permitted here.

## Session key material

- After a successful unlock, the runtime session holds `transformed` (in a
  zeroizing buffer) and **immediately discards the plaintext password and key
  file contents**; the current practice of `LoadedVault` retaining
  `password: Option<String>` long-term is abolished.
- Saving no longer re-runs the KDF (currently every save re-reads the key file
  and re-runs Argon2): with an unchanged salt, the session's `transformed` is
  reused directly. **The save API consumes the session's key-material handle,
  not credentials** — only a master-credential change collects credentials and
  re-derives.
- A master-credential change is the only operation that re-collects credentials
  and re-runs the KDF.

## Envelope↔cache binding and rollback posture

The extension decrypts the cached vault copy with an unsealed `transformed`.
The binding rules:

- **Cryptographic fail-closed is the base layer**: if the cached file's header
  carries a different KDF generation than the envelope's `transformed`, the
  derived `encryption_key = SHA256(master_seed ‖ transformed)` is wrong and the
  header MAC check fails — a stale envelope cannot silently decrypt the wrong
  file. The explicit `kdf_generation` equality check exists on top of this to
  produce a friendly `NeedsReenroll` instead of a generic open failure.
- **Cache identity**: the cache manifest binds the cached bytes to a
  `vault_ref_id`; the extension refuses a cache whose manifest `vault_ref_id`
  differs from the one in the envelope AAD.
- **Rollback posture**: substituting an older-but-genuine cached file (plus its
  then-valid envelope) requires write access to the app group container —
  i.e., a same-signature process. This is a **product security assumption**
  (platform code-signing isolation), not a cryptographic guarantee, and it is
  explicitly the trust boundary; attacks from within it are out of scope.
  Stale-but-genuine caches are an accepted read state per 003.

### CacheManifest wire format and atomic publication

```
CacheManifest {
    schema_version:      u32,
    vault_ref_id:        string,
    content_fingerprint: H(cached bytes),     // also the cache file's name
    kdf_generation:      as above,
    source_etag:         optional string,     // remote identity at snapshot time
    published_at:        u64,
}
```

Publication protocol (two-file commit; **the manifest is the authority**):

1. Write the new vault bytes to a file named by their `content_fingerprint`
   (content-addressed), fsync.
2. Atomically replace the manifest (temp + rename + fsync) pointing at the new
   fingerprint.
3. Delete orphaned old cache files (best-effort).

Readers verify `H(bytes) == manifest.content_fingerprint`; any mismatch —
including every possible crash interleaving of steps 1–3 — degrades to
"no cache" (fail closed; the extension directs the user to the main app).
A crash between 1 and 2 leaves the old manifest pointing at the old,
still-present file: consistent. Content-addressing makes a torn or partial
state impossible to mistake for a valid one.

## Extension unlock path (Apple / Android)

```
Apple:   envelope in the data protection keychain (shared access group, D8) +
         SE P256 key (.biometryCurrentSet); inside the extension:
         Face ID/Touch ID → SE unseals KEK → unseal transformed →
         decrypt the cached vault copy in the app group container.
Android: AutofillService/CredentialProviderService share the app's process
         domain; a Keystore key (setUserAuthenticationRequired + StrongBox
         where available) unseals the same payload.
Windows: Hello CNG unseals the same payload (the existing v2 envelope format is
         remade per this document; D10 permits shipping without migration).
```

- Extensions **never run the KDF** (D9): with no envelope, or an expired one,
  they direct the user to the main app — no fallback.
- The SE envelope cryptography carries over from the Touch ID branch
  (P256 ECDH + HKDF + AES-256-GCM; non-interactive re-seal via the SE public
  key), but the storage layer is rewritten for the data protection keychain
  (see 004).

## KDF cap for external files (D9 expanded)

- Desktop: opening a file with Argon2 memory > 256 MiB requires explicit
  confirmation; > 1 GiB is refused.
- Mobile main app: Argon2 > 128 MiB is refused with a hint to lower the
  parameters on desktop.
- **AES-KDF has no memory parameter; its cap is a rounds threshold** sized to
  equivalent wall-clock (~10 s on the target device class): desktop confirms
  above it, mobile refuses above it.
- Extensions: never run any KDF (above).
- **Enforcement point**: in the core, after KDBX header decode and before KDF
  profile construction. The host injects a policy value —
  `Allow | Confirm(limit) | Refuse(limit) | Forbid` — so no UI or entry path
  can bypass the check, and the extension profile is simply `Forbid`.

## Memory hygiene (implementation constraints, fixed with this document)

1. `transformed` and all key material use zeroizing types; they must never
   enter a `String`, a log line, or a DTO.
2. The full encrypted file bytes are not retained after unlock (the current
   long-lived `LoadedVault.bytes` is abolished; re-reads come from the cache
   file).
3. Attachments load lazily: the model holds handles and decrypts on demand;
   history snapshots do not clone attachment bytes (currently N references cost
   N+1 copies). The extension memory budget is designed around "KDBX ciphertext
   + XML plaintext + model (without attachments)".

Items 2–3 are a **structural refactor** of the KDBX/model/session layers, not a
provider swap; they are scheduled as their own Phase 1 work items in the 004
sequencing, separate from the envelope work.
