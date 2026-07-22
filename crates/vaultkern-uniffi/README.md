# vaultkern-uniffi

This crate is the mobile and macOS FFI boundary around the resident
`vaultkern-runtime`. It exports the existing session, unlock, source, sync, and
passkey operations without adding platform behavior. Native apps provide an
explicit `VaultSessionConfig` with their private state/cache directories and
implement `UnlockBlobAdapter` plus `OneDriveTokenAdapter`; keychain, biometric,
and OAuth presentation code remains on the platform side of those traits.
Local files use `openVault` followed by `unlockVault`. A persisted source
selected through `VaultSources` uses `unlockCurrent`, which lets the runtime
load either its local or OneDrive snapshot before applying the same unlock
policy.

Android initiates passkey ceremonies through `beginPasskeyOperation`. The
returned scoped object owns the runtime lease: register/assert, commit a
registration when applicable, then `finish` (or release/close the language
object, whose Rust destructor rolls back an unfinished operation). D3 requires
Apple credential-provider extensions to use an encrypted outbox rather than
write KDBX directly. Until that separate boundary exists, macOS reports
`applePasskeyOutbox = false` and rejects Android-style direct persistence
instead of pretending it is supported.
While a passkey operation is active, ordinary session mutations are rejected;
only the scoped register/assert/commit methods may change the vault. This keeps
an uncommitted registration from escaping through an unrelated save or sync.

The exported records retain the D5 runtime-protocol names and field vocabulary.
Secret-bearing strings and unlock-blob bytes use custom Swift/Kotlin owner
types. They redact `description`/`toString`, keep owned bytes clearable, and
must be closed after use. `reveal()` necessarily creates a short-lived native
language `String`; that rendering copy is outside Rust's zeroization guarantee.

## Generate bindings

Build the native library, then point the checked-in bindgen CLI at that library:

```sh
cargo build --locked --release -p vaultkern-uniffi --features bindgen-cli
cargo run --locked --release -p vaultkern-uniffi --features bindgen-cli \
  --bin uniffi-bindgen -- generate --no-format --language kotlin \
  --out-dir crates/vaultkern-uniffi/bindings/kotlin \
  target/release/libvaultkern_uniffi.so
cargo run --locked --release -p vaultkern-uniffi --features bindgen-cli \
  --bin uniffi-bindgen -- generate --no-format --language swift \
  --out-dir crates/vaultkern-uniffi/bindings/swift \
  target/release/libvaultkern_uniffi.so
```

On macOS, use `target/release/libvaultkern_uniffi.dylib` instead. The committed
Swift and Kotlin outputs are checked by the UniFFI Bindings workflow.

## Tests

The Rust contract test exercises every facade area and fake platform adapters.
The two language smoke tests additionally compile the generated code, open the
external KeePassXC fixture, list entries, and complete enroll/unlock/revoke
through an in-memory adapter:

```sh
cargo test --locked -p vaultkern-uniffi -- --test-threads=1
gradle -p crates/vaultkern-uniffi/tests/kotlin connectedDebugAndroidTest
```

The workflow builds an arm64 Android artifact and runs the Kotlin test with the
x86_64 artifact inside an Android 14/API 34 emulator. Swift is compiled and run
on a macOS runner with deployment target 14.0; Linux is not treated as evidence
for the macOS slice.
