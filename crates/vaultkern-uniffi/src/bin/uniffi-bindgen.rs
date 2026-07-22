use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

fn main() {
    let output_dir = bindgen_output_dir(env::args_os());
    uniffi::uniffi_bindgen_main();

    if let Some(output_dir) = output_dir
        && let Err(error) = normalize_generated_bindings(&output_dir)
    {
        eprintln!(
            "failed to normalize generated bindings in {}: {error}",
            output_dir.display()
        );
        std::process::exit(1);
    }
}

fn bindgen_output_dir(args: impl IntoIterator<Item = std::ffi::OsString>) -> Option<PathBuf> {
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        if argument == "--out-dir" || argument == "-o" {
            return args.next().map(PathBuf::from);
        }

        if let Some(argument) = argument.to_str()
            && let Some(path) = argument.strip_prefix("--out-dir=")
        {
            return Some(PathBuf::from(path));
        }
    }
    None
}

fn normalize_generated_bindings(directory: &Path) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            normalize_generated_bindings(&path)?;
            continue;
        }

        let generated_source = matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("h" | "kt" | "modulemap" | "swift")
        );
        if !generated_source {
            continue;
        }

        let generated = fs::read_to_string(&path)?;
        let normalized = normalize_generated_text(&generated);
        if normalized != generated {
            fs::write(path, normalized)?;
        }
    }
    Ok(())
}

fn normalize_generated_text(generated: &str) -> String {
    let mut normalized = generated
        .split('\n')
        .map(|line| line.trim_end_matches([' ', '\t', '\r']))
        .collect::<Vec<_>>()
        .join("\n");
    while normalized.ends_with('\n') {
        normalized.pop();
    }
    if !normalized.is_empty() {
        normalized.push('\n');
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::normalize_generated_text;

    #[test]
    fn removes_trailing_whitespace_and_extra_terminal_blank_lines() {
        let generated = "first  \nsecond\t\n\n";

        assert_eq!(normalize_generated_text(generated), "first\nsecond\n");
    }
}
