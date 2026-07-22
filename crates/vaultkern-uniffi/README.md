# vaultkern-uniffi

This crate is the mobile and macOS FFI boundary around the resident
`vaultkern-runtime`. It exports the existing session, unlock, sync, and passkey
operations without adding platform behavior. Native apps implement
`UnlockBlobAdapter`; keychain and biometric UI remain on the platform side of
that trait. Apps initiate passkey ceremonies through the exported register and
assert entry points.

The exported records retain the D5 runtime-protocol names and field vocabulary.
Secret-bearing strings use the `SensitiveString` custom type so their resident
Rust allocations are zeroized on drop and redacted from Rust debug output.

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

The Rust contract test exercises every facade area and the fake unlock-blob
adapter. The two language smoke tests additionally compile the generated code,
open the external KeePassXC fixture, list entries, and complete enroll/unlock/
revoke through an in-memory adapter:

```sh
XDG_STATE_HOME=/tmp/vaultkern-uniffi-test-state \
  cargo test --locked -p vaultkern-uniffi -- --test-threads=1
gradle -p crates/vaultkern-uniffi/tests/kotlin run
```

The workflow also links the Rust library for Android API 34 on arm64. The
Swift compile and link commands are kept there as well and run on macOS.
