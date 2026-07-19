mod autofill_persist;
mod command_loop;
mod match_fill;
pub mod native_host;
mod passkey;
mod providers;
#[cfg(any(windows, test))]
pub mod resident_ipc;
mod runtime;
mod session;
mod state_paths;
mod sync;
mod unlock;
mod vault_reference_store;

pub use command_loop::run_stdio_loop;
pub use native_host::render_manifest;
pub use passkey::{
    PlatformPasskeyAssertionInput, PlatformPasskeyAssertionOutput, PlatformPasskeyCredential,
    PlatformPasskeyRegistrationInput, PlatformPasskeyRegistrationOutput,
};
pub use runtime::Runtime;
