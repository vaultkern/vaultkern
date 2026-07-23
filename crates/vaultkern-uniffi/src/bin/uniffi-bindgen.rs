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
    normalized = clear_kotlin_sensitive_byte_copies(normalized);
    normalized = avoid_kotlin_sensitive_plain_strings(normalized);
    normalized = close_sensitive_kotlin_callback_returns(normalized);
    while normalized.ends_with('\n') {
        normalized.pop();
    }
    if !normalized.is_empty() {
        normalized.push('\n');
    }
    normalized
}

fn clear_kotlin_sensitive_byte_copies(generated: String) -> String {
    generated
        .replace(
            r#"    override fun lower(value: SensitiveBytes): RustBuffer.ByValue {
        val builtinValue = value.copyBytes()
        return FfiConverterByteArray.lower(builtinValue)
    }"#,
            r#"    override fun lower(value: SensitiveBytes): RustBuffer.ByValue {
        val builtinValue = value.copyBytes()
        return try {
            FfiConverterByteArray.lower(builtinValue)
        } finally {
            builtinValue.fill(0)
        }
    }"#,
        )
        .replace(
            r#"    override fun allocationSize(value: SensitiveBytes): ULong {
        val builtinValue = value.copyBytes()
        return FfiConverterByteArray.allocationSize(builtinValue)
    }"#,
            r#"    override fun allocationSize(value: SensitiveBytes): ULong {
        val builtinValue = value.copyBytes()
        return try {
            FfiConverterByteArray.allocationSize(builtinValue)
        } finally {
            builtinValue.fill(0)
        }
    }"#,
        )
        .replace(
            r#"    override fun write(value: SensitiveBytes, buf: ByteBuffer) {
        val builtinValue = value.copyBytes()
        FfiConverterByteArray.write(builtinValue, buf)
    }"#,
            r#"    override fun write(value: SensitiveBytes, buf: ByteBuffer) {
        val builtinValue = value.copyBytes()
        try {
            FfiConverterByteArray.write(builtinValue, buf)
        } finally {
            builtinValue.fill(0)
        }
    }"#,
        )
}

fn avoid_kotlin_sensitive_plain_strings(generated: String) -> String {
    generated.replace(
        r#"public object FfiConverterTypeSensitiveString: FfiConverter<SensitiveString, RustBuffer.ByValue> {
    override fun lift(value: RustBuffer.ByValue): SensitiveString {
        val builtinValue = FfiConverterString.lift(value)
        return VaultKernSensitiveString.fromString(builtinValue)
    }

    override fun lower(value: SensitiveString): RustBuffer.ByValue {
        val builtinValue = value.reveal()
        return FfiConverterString.lower(builtinValue)
    }

    override fun read(buf: ByteBuffer): SensitiveString {
        val builtinValue = FfiConverterString.read(buf)
        return VaultKernSensitiveString.fromString(builtinValue)
    }

    override fun allocationSize(value: SensitiveString): ULong {
        val builtinValue = value.reveal()
        return FfiConverterString.allocationSize(builtinValue)
    }

    override fun write(value: SensitiveString, buf: ByteBuffer) {
        val builtinValue = value.reveal()
        FfiConverterString.write(builtinValue, buf)
    }
}"#,
        r#"public object FfiConverterTypeSensitiveString: FfiConverter<SensitiveString, RustBuffer.ByValue> {
    override fun lift(value: RustBuffer.ByValue): SensitiveString = try {
        val bytes = ByteArray(value.len.toInt())
        try {
            value.asByteBuffer()!!.get(bytes)
            VaultKernSensitiveString.fromUtf8Bytes(bytes)
        } finally {
            bytes.fill(0)
        }
    } finally {
        RustBuffer.free(value)
    }

    override fun lower(value: SensitiveString): RustBuffer.ByValue {
        val bytes = value.copyUtf8Bytes()
        return try {
            val buffer = RustBuffer.alloc(bytes.size.toULong())
            try {
                buffer.asByteBuffer()!!.put(bytes)
                buffer
            } catch (error: Throwable) {
                RustBuffer.free(buffer)
                throw error
            }
        } finally {
            bytes.fill(0)
        }
    }

    override fun read(buf: ByteBuffer): SensitiveString {
        val bytes = ByteArray(buf.getInt())
        return try {
            buf.get(bytes)
            VaultKernSensitiveString.fromUtf8Bytes(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    override fun allocationSize(value: SensitiveString): ULong {
        val bytes = value.copyUtf8Bytes()
        return try {
            4UL + bytes.size.toULong()
        } finally {
            bytes.fill(0)
        }
    }

    override fun write(value: SensitiveString, buf: ByteBuffer) {
        val bytes = value.copyUtf8Bytes()
        try {
            buf.putInt(bytes.size)
            buf.put(bytes)
        } finally {
            bytes.fill(0)
        }
    }
}"#,
    )
}

fn close_sensitive_kotlin_callback_returns(mut generated: String) -> String {
    for (sensitive_type, converter) in [
        ("SensitiveString", "FfiConverterOptionalTypeSensitiveString"),
        ("SensitiveBytes", "FfiConverterOptionalTypeSensitiveBytes"),
    ] {
        let original = format!(
            "            val writeReturn = {{ value: {sensitive_type}? -> uniffiOutReturn.setValue({converter}.lower(value)) }}"
        );
        let replacement = format!(
            "            val writeReturn = {{ value: {sensitive_type}? ->\n                try {{\n                    uniffiOutReturn.setValue({converter}.lower(value))\n                }} finally {{\n                    value?.close()\n                }}\n            }}"
        );
        generated = generated.replace(&original, &replacement);
    }
    generated
}

#[cfg(test)]
mod tests {
    use super::{
        avoid_kotlin_sensitive_plain_strings, clear_kotlin_sensitive_byte_copies,
        close_sensitive_kotlin_callback_returns, normalize_generated_text,
    };

    #[test]
    fn removes_trailing_whitespace_and_extra_terminal_blank_lines() {
        let generated = "first  \nsecond\t\n\n";

        assert_eq!(normalize_generated_text(generated), "first\nsecond\n");
    }

    #[test]
    fn clears_a_generated_sensitive_byte_copy_after_lowering() {
        let generated = r#"    override fun lower(value: SensitiveBytes): RustBuffer.ByValue {
        val builtinValue = value.copyBytes()
        return FfiConverterByteArray.lower(builtinValue)
    }"#;

        let hardened = clear_kotlin_sensitive_byte_copies(generated.to_owned());

        assert!(hardened.contains("finally {\n            builtinValue.fill(0)"));
    }

    #[test]
    fn replaces_generated_sensitive_string_lowering_with_clearable_bytes() {
        let generated = r#"public object FfiConverterTypeSensitiveString: FfiConverter<SensitiveString, RustBuffer.ByValue> {
    override fun lift(value: RustBuffer.ByValue): SensitiveString {
        val builtinValue = FfiConverterString.lift(value)
        return VaultKernSensitiveString.fromString(builtinValue)
    }

    override fun lower(value: SensitiveString): RustBuffer.ByValue {
        val builtinValue = value.reveal()
        return FfiConverterString.lower(builtinValue)
    }

    override fun read(buf: ByteBuffer): SensitiveString {
        val builtinValue = FfiConverterString.read(buf)
        return VaultKernSensitiveString.fromString(builtinValue)
    }

    override fun allocationSize(value: SensitiveString): ULong {
        val builtinValue = value.reveal()
        return FfiConverterString.allocationSize(builtinValue)
    }

    override fun write(value: SensitiveString, buf: ByteBuffer) {
        val builtinValue = value.reveal()
        FfiConverterString.write(builtinValue, buf)
    }
}"#;

        let hardened = avoid_kotlin_sensitive_plain_strings(generated.to_owned());

        assert!(!hardened.contains("FfiConverterString"));
        assert!(hardened.contains("value.copyUtf8Bytes()"));
    }

    #[test]
    fn closes_sensitive_kotlin_callback_returns_after_lowering() {
        let generated = "            val writeReturn = { value: SensitiveString? -> uniffiOutReturn.setValue(FfiConverterOptionalTypeSensitiveString.lower(value)) }";

        let normalized = close_sensitive_kotlin_callback_returns(generated.into());

        assert!(normalized.contains("value?.close()"));
        assert!(
            normalized.find("lower(value)").unwrap() < normalized.find("value?.close()").unwrap()
        );
    }
}
