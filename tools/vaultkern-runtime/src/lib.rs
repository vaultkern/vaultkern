mod autofill_persist;
mod command_loop;
#[cfg(target_os = "macos")]
mod macos_secure_enclave;
mod match_fill;
pub mod native_host;
mod passkey;
mod providers;
mod runtime;
mod session;
mod state_paths;
mod vault_reference_store;

pub use command_loop::run_stdio_loop;
pub use native_host::render_manifest;
pub use runtime::Runtime;

pub fn verify_native_messaging_browser_caller() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    if !macos_secure_enclave::native_messaging_caller_is_trusted() {
        anyhow::bail!("native messaging host was not launched by a trusted Chrome process");
    }
    Ok(())
}
