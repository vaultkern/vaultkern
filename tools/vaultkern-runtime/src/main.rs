use vaultkern_runtime::{Runtime, render_manifest, run_stdio_loop};

const USAGE: &str = "usage: vaultkern-runtime [--help] [--print-native-host-manifest <binary-path> <extension-origin>]";

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    RunStdio,
    PrintUsage,
    PrintManifest {
        binary_path: String,
        extension_origin: String,
    },
    Invalid,
}

fn main() {
    match classify_invocation(std::env::args().skip(1)) {
        Invocation::RunStdio => {
            if let Err(error) = run_stdio_loop(Runtime::new()) {
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
        [] => Invocation::RunStdio,
        [flag] if flag == "--help" => Invocation::PrintUsage,
        [flag, binary_path, extension_origin] if flag == "--print-native-host-manifest" => {
            Invocation::PrintManifest {
                binary_path: binary_path.clone(),
                extension_origin: extension_origin.clone(),
            }
        }
        [origin, rest @ ..]
            if is_browser_origin(origin)
                && rest.iter().all(|arg| arg.starts_with("--parent-window=")) =>
        {
            Invocation::RunStdio
        }
        _ => Invocation::Invalid,
    }
}

fn is_browser_origin(value: &str) -> bool {
    value.starts_with("chrome-extension://")
}

#[cfg(test)]
mod tests {
    use super::{Invocation, classify_invocation};

    #[test]
    fn browser_invocation_with_origin_and_parent_window_runs_stdio() {
        let invocation = classify_invocation([
            "chrome-extension://test-extension-id/".to_string(),
            "--parent-window=0".to_string(),
        ]);

        assert_eq!(invocation, Invocation::RunStdio);
    }

    #[test]
    fn browser_invocation_with_origin_only_runs_stdio() {
        let invocation = classify_invocation(["chrome-extension://test-extension-id/".to_string()]);

        assert_eq!(invocation, Invocation::RunStdio);
    }
}
