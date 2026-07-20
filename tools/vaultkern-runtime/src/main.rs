use vaultkern_runtime::{Runtime, is_supported_browser_origin, render_manifest, run_stdio_loop};

const USAGE: &str = "usage: vaultkern-runtime [--help] [--print-native-host-manifest <binary-path> <extension-origin>]";

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    RunStdio {
        browser_origin: Option<String>,
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
        Invocation::RunStdio { browser_origin } => {
            let runtime = browser_origin
                .as_deref()
                .map(Runtime::new_for_browser_origin)
                .unwrap_or_else(Runtime::new);
            if let Err(error) = run_stdio_loop(runtime) {
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

fn classify_invocation(args: impl IntoIterator<Item = String>) -> Invocation {
    let args = args.into_iter().collect::<Vec<_>>();

    match args.as_slice() {
        [] => Invocation::RunStdio {
            browser_origin: None,
        },
        [flag] if flag == "--help" => Invocation::PrintUsage,
        [flag, binary_path, extension_origin] if flag == "--print-native-host-manifest" => {
            Invocation::PrintManifest {
                binary_path: binary_path.clone(),
                extension_origin: extension_origin.clone(),
            }
        }
        [origin, rest @ ..]
            if is_supported_browser_origin(origin)
                && rest.iter().all(|arg| arg.starts_with("--parent-window=")) =>
        {
            Invocation::RunStdio {
                browser_origin: Some(origin.clone()),
            }
        }
        _ => Invocation::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::{Invocation, classify_invocation};

    #[test]
    fn browser_invocation_with_origin_and_parent_window_runs_stdio() {
        let invocation = classify_invocation([
            "chrome-extension://testextensionid/".to_string(),
            "--parent-window=0".to_string(),
        ]);

        assert_eq!(
            invocation,
            Invocation::RunStdio {
                browser_origin: Some("chrome-extension://testextensionid/".to_string())
            }
        );
    }

    #[test]
    fn browser_invocation_with_origin_only_runs_stdio() {
        let invocation = classify_invocation(["chrome-extension://testextensionid/".to_string()]);

        assert_eq!(
            invocation,
            Invocation::RunStdio {
                browser_origin: Some("chrome-extension://testextensionid/".to_string())
            }
        );
    }

    #[test]
    fn malformed_browser_origin_is_rejected_instead_of_using_resident_runtime() {
        let invocation = classify_invocation(["chrome-extension://UpperCase/".to_string()]);

        assert_eq!(invocation, Invocation::Invalid);
    }
}
