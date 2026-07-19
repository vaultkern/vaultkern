use vaultkern_runtime::render_manifest;
#[cfg(windows)]
use vaultkern_runtime::resident_ipc::run_windows_native_messaging_shim;
#[cfg(not(windows))]
use vaultkern_runtime::{Runtime, run_stdio_loop};

const USAGE: &str = "usage: vaultkern-runtime [--help] [--print-native-host-manifest <binary-path> <extension-origin>]";

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    RunStdio {
        browser_origin: Option<String>,
        parent_window: Option<usize>,
    },
    PrintUsage,
    PrintManifest {
        binary_path: String,
        extension_origin: String,
    },
    Invalid,
}

fn main() {
    match classify_invocation(std::env::args().skip(1)) {
        Invocation::RunStdio {
            browser_origin,
            parent_window,
        } => {
            if let Err(error) = run_native_host(browser_origin.as_deref(), parent_window) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        Invocation::PrintUsage => {
            println!("{USAGE}");
        }
        Invocation::PrintManifest {
            binary_path,
            extension_origin,
        } => {
            println!("{}", render_manifest(&binary_path, &extension_origin));
        }
        Invocation::Invalid => {
            eprintln!("{USAGE}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn run_native_host(
    browser_origin: Option<&str>,
    _parent_window: Option<usize>,
) -> anyhow::Result<()> {
    let runtime = browser_origin
        .map(Runtime::new_for_browser_origin)
        .unwrap_or_else(Runtime::new);
    run_stdio_loop(runtime)
}

#[cfg(windows)]
fn run_native_host(
    browser_origin: Option<&str>,
    parent_window: Option<usize>,
) -> anyhow::Result<()> {
    let browser_origin = browser_origin
        .ok_or_else(|| anyhow::anyhow!("browser extension origin is required on Windows"))?;
    run_windows_native_messaging_shim(browser_origin, parent_window)
}

fn classify_invocation(args: impl IntoIterator<Item = String>) -> Invocation {
    let args = args.into_iter().collect::<Vec<_>>();

    match args.as_slice() {
        [] => Invocation::RunStdio {
            browser_origin: None,
            parent_window: None,
        },
        [flag] if flag == "--help" => Invocation::PrintUsage,
        [flag, binary_path, extension_origin] if flag == "--print-native-host-manifest" => {
            Invocation::PrintManifest {
                binary_path: binary_path.clone(),
                extension_origin: extension_origin.clone(),
            }
        }
        [origin, rest @ ..] if is_browser_origin(origin) => {
            let Some(parent_window) = parse_parent_window_arguments(rest) else {
                return Invocation::Invalid;
            };
            Invocation::RunStdio {
                browser_origin: Some(origin.clone()),
                parent_window,
            }
        }
        _ => Invocation::Invalid,
    }
}

fn is_browser_origin(value: &str) -> bool {
    value.starts_with("chrome-extension://")
}

fn parse_parent_window_arguments(arguments: &[String]) -> Option<Option<usize>> {
    match arguments {
        [] => Some(None),
        [argument] => argument
            .strip_prefix("--parent-window=")?
            .parse::<usize>()
            .ok()
            .map(|handle| (handle != 0).then_some(handle)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Invocation, classify_invocation};

    #[test]
    fn browser_invocation_with_origin_and_parent_window_runs_stdio() {
        let invocation = classify_invocation([
            "chrome-extension://test-extension-id/".to_string(),
            "--parent-window=4660".to_string(),
        ]);

        assert_eq!(
            invocation,
            Invocation::RunStdio {
                browser_origin: Some("chrome-extension://test-extension-id/".to_string()),
                parent_window: Some(0x1234),
            }
        );
    }

    #[test]
    fn browser_invocation_with_origin_only_runs_stdio() {
        let invocation = classify_invocation(["chrome-extension://test-extension-id/".to_string()]);

        assert_eq!(
            invocation,
            Invocation::RunStdio {
                browser_origin: Some("chrome-extension://test-extension-id/".to_string()),
                parent_window: None,
            }
        );
    }

    #[test]
    fn zero_parent_window_is_a_supported_headless_browser_context() {
        let invocation = classify_invocation([
            "chrome-extension://test-extension-id/".to_string(),
            "--parent-window=0".to_string(),
        ]);

        assert_eq!(
            invocation,
            Invocation::RunStdio {
                browser_origin: Some("chrome-extension://test-extension-id/".to_string()),
                parent_window: None,
            }
        );
    }

    #[test]
    fn malformed_or_duplicate_parent_window_arguments_are_rejected() {
        assert_eq!(
            classify_invocation([
                "chrome-extension://test-extension-id/".to_string(),
                "--parent-window=not-a-handle".to_string(),
            ]),
            Invocation::Invalid
        );
        assert_eq!(
            classify_invocation([
                "chrome-extension://test-extension-id/".to_string(),
                "--parent-window=1".to_string(),
                "--parent-window=2".to_string(),
            ]),
            Invocation::Invalid
        );
    }
}
