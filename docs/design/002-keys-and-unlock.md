# 002 — Keys and Unlock

Status: **Stable — r14** (rewritten in the r16 scope reset). 2026-07-19.
Cryptographic changes here get strict review.

## Derivation chain (fixed by the KDBX format)

```
raw_key        = SHA256( SHA256(password) ‖ keyfile_bytes ‖ provider_bytes )
transformed    = KDF(raw_key)                     // Argon2id / AES-KDF, params in file header
encryption_key = SHA256( master_seed ‖ transformed )
mac_seed       = SHA512( master_seed ‖ transformed ‖ 0x01 )
```

## Unlock blob (replaces the envelope/generation design)

One keychain item per vault — data-protection keychain, Secure-Enclave-wrapped
key, biometric ACL, shared access group so credential extensions can unlock
too:

```
{ master_credential           // password bytes + keyfile content-hash contribution
, cached_transformed_key }    // pure performance cache
```

Unlock: biometric → decrypt blob → try `cached_transformed_key`, with the
file's own HMAC check as the validity oracle. Hit → open with no KDF run.
Miss (someone rotated the salt) → derive from `master_credential`, open,
write the fresh transformed key back. Credential wrong (master password
changed elsewhere) → interactive prompt; on success, recreate the blob.

States: enrolled (blob exists) / not enrolled. Revoke = delete the blob.
There are no generations, no ledgers, and no reconciliation machinery.

Keyfiles are stored as their content-hash contribution, never as a path.

## Save-time key policy

- Ordinary saves reuse the loaded `KdfParameters`, salt included — this keeps
  the cached transformed key warm. Master seed, IVs, and inner-stream keys
  are fresh on every save.
- Only a master-credential change or an explicit KDF-parameter change
  generates a fresh salt; both re-derive and update the blob.
- After unlock the session holds `transformed` in a zeroizing buffer and
  discards plaintext credentials; saving consumes the session key handle,
  not credentials.

## KDF caps for external files (D9)

- Argon2: desktop confirms above 256 MiB memory, refuses above 1 GiB;
  mobile refuses above 128 MiB.
- AES-KDF: desktop confirms above 600 M rounds, refuses above 6 G; mobile
  refuses above 600 M. All constants, recalibratable on spike hardware.
- Enforced in the core after header decode, before KDF construction; the
  host injects `Allow | Confirm | Refuse | Forbid`. Extension processes are
  `Forbid` — they never run a KDF; the blob's cached key covers them.

## Memory hygiene

1. Key material lives in zeroizing types; never in `String`s, logs, or DTOs.
2. Encrypted file bytes are not retained after unlock.
3. Attachments load lazily; history snapshots do not clone attachment bytes.
