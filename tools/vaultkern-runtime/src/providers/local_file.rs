use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFileSnapshot {
    pub bytes: Vec<u8>,
    pub fingerprint: VaultSourceFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSourceFingerprint {
    pub content_sha256: String,
    pub size_bytes: u64,
    pub modified_at: Option<u64>,
}

pub struct LocalFileVaultSourceProvider;

impl LocalFileVaultSourceProvider {
    pub fn pick(&self) -> anyhow::Result<Option<String>> {
        pick_local_vault_path()
    }

    pub fn read_snapshot(&self, path: &str) -> std::io::Result<LocalFileSnapshot> {
        let bytes = std::fs::read(path)?;
        let metadata = std::fs::metadata(path)?;
        Ok(LocalFileSnapshot {
            fingerprint: fingerprint_for_bytes(&bytes, &metadata),
            bytes,
        })
    }

    pub fn write(&self, path: &str, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, bytes)
    }
}

#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
fn decode_picker_stdout(stdout: Vec<u8>) -> anyhow::Result<Option<String>> {
    let path = String::from_utf8(stdout)
        .map_err(|_| anyhow::anyhow!("local vault picker returned non-UTF-8 output"))?;
    let path = path
        .strip_suffix("\r\n")
        .or_else(|| path.strip_suffix('\n'))
        .unwrap_or(&path)
        .to_owned();

    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
}

#[cfg(target_os = "macos")]
const MACOS_PICKER_SCRIPT: &str = r#"try
    set selectedVault to choose file with prompt "Select a KeePass vault" of type {"kdbx"} invisibles true multiple selections allowed false showing package contents false
    return POSIX path of selectedVault
on error number -128
    return ""
end try"#;

#[cfg(target_os = "macos")]
fn pick_macos_local_vault_path_with(
    runner: impl FnOnce(&mut std::process::Command) -> std::io::Result<std::process::Output>,
) -> anyhow::Result<Option<String>> {
    let mut command = std::process::Command::new("/usr/bin/osascript");
    command.args(["-e", MACOS_PICKER_SCRIPT]);
    let output = runner(&mut command).map_err(anyhow::Error::from)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            anyhow::bail!("failed to open macOS local vault picker: {}", output.status);
        }
        anyhow::bail!("failed to open macOS local vault picker: {stderr}");
    }

    decode_picker_stdout(output.stdout)
}

fn fingerprint_for_bytes(bytes: &[u8], metadata: &std::fs::Metadata) -> VaultSourceFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let content_sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let modified_at = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_secs());

    VaultSourceFingerprint {
        content_sha256,
        size_bytes: bytes.len() as u64,
        modified_at,
    }
}

#[cfg(windows)]
fn pick_local_vault_path() -> anyhow::Result<Option<String>> {
    let script = r#"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Filter = 'KeePass Vault (*.kdbx)|*.kdbx|All Files (*.*)|*.*'
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  Write-Output $dialog.FileName
}
"#;

    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-STA", "-Command", script])
        .output()
        .map_err(anyhow::Error::from)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("failed to open local vault picker: {}", stderr.trim());
    }

    decode_picker_stdout(output.stdout)
}

#[cfg(target_os = "macos")]
fn pick_local_vault_path() -> anyhow::Result<Option<String>> {
    pick_macos_local_vault_path_with(std::process::Command::output)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn pick_local_vault_path() -> anyhow::Result<Option<String>> {
    anyhow::bail!("local vault picker is only implemented on Windows and macOS")
}

#[cfg(test)]
mod tests {
    use super::decode_picker_stdout;
    #[cfg(target_os = "macos")]
    use super::{MACOS_PICKER_SCRIPT, pick_macos_local_vault_path_with};
    #[cfg(target_os = "macos")]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(target_os = "macos")]
    use std::process::{ExitStatus, Output};

    #[cfg(target_os = "macos")]
    fn command_output(exit_code: i32, stdout: &[u8], stderr: &[u8]) -> Output {
        Output {
            status: ExitStatus::from_raw(exit_code << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn picker_stdout_preserves_unicode_and_spaces_while_removing_one_crlf() {
        let path =
            decode_picker_stdout("C:\\Users\\Example\\Desktop\\ 测试 vault.kdbx \r\n".into())
                .expect("decode picker stdout");

        assert_eq!(
            path,
            Some("C:\\Users\\Example\\Desktop\\ 测试 vault.kdbx ".to_owned())
        );
    }

    #[test]
    fn picker_stdout_removes_only_one_line_ending() {
        assert_eq!(
            decode_picker_stdout(b"/tmp/vault.kdbx\n\n".to_vec()).expect("decode picker stdout"),
            Some("/tmp/vault.kdbx\n".to_owned())
        );
        assert_eq!(
            decode_picker_stdout(b"/tmp/vault.kdbx\r\n\r\n".to_vec())
                .expect("decode picker stdout"),
            Some("/tmp/vault.kdbx\r\n".to_owned())
        );
    }

    #[test]
    fn picker_stdout_maps_empty_output_to_none() {
        assert_eq!(
            decode_picker_stdout(Vec::new()).expect("decode picker stdout"),
            None
        );
        assert_eq!(
            decode_picker_stdout(b"\n".to_vec()).expect("decode picker stdout"),
            None
        );
    }

    #[test]
    fn picker_stdout_rejects_non_utf8_paths_instead_of_corrupting_them() {
        let gb2312_path = b"C:\\Users\\Example\\Desktop\\\xb2\xe2\xca\xd4.kdbx\r\n".to_vec();

        let error = decode_picker_stdout(gb2312_path).expect_err("non-UTF-8 should fail");

        assert!(error.to_string().contains("non-UTF-8"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_picker_runner_uses_osascript_and_static_picker_script() {
        let path = pick_macos_local_vault_path_with(|command| {
            assert_eq!(command.get_program(), "/usr/bin/osascript");
            let args = command
                .get_args()
                .map(|arg| arg.to_str().expect("UTF-8 command argument"))
                .collect::<Vec<_>>();
            assert_eq!(args, ["-e", MACOS_PICKER_SCRIPT]);
            assert!(MACOS_PICKER_SCRIPT.contains("of type {\"kdbx\"}"));
            assert!(MACOS_PICKER_SCRIPT.contains("on error number -128"));
            assert!(MACOS_PICKER_SCRIPT.contains(
                "choose file with prompt \"Select a KeePass vault\" of type {\"kdbx\"} invisibles true multiple selections allowed false showing package contents false"
            ));
            assert!(MACOS_PICKER_SCRIPT.contains("return POSIX path"));

            Ok(command_output(
                0,
                "/Users/Example/测试 vault.kdbx\n".as_bytes(),
                b"",
            ))
        })
        .expect("run macOS picker");

        assert_eq!(path, Some("/Users/Example/测试 vault.kdbx".to_owned()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_picker_reports_failed_child_stderr() {
        let error = pick_macos_local_vault_path_with(|_| {
            Ok(command_output(
                7,
                b"",
                b"37:42: execution error: picker failed (-2700)\n",
            ))
        })
        .expect_err("failed picker should be reported");

        assert_eq!(
            error.to_string(),
            "failed to open macOS local vault picker: 37:42: execution error: picker failed (-2700)"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_picker_reports_exit_status_when_stderr_is_empty() {
        let error = pick_macos_local_vault_path_with(|_| Ok(command_output(7, b"", b" \r\n")))
            .expect_err("failed picker should be reported");

        assert_eq!(
            error.to_string(),
            "failed to open macOS local vault picker: exit status: 7"
        );
    }
}
