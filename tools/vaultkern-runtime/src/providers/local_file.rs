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

#[cfg_attr(not(windows), allow(dead_code))]
fn decode_picker_stdout(stdout: Vec<u8>) -> anyhow::Result<Option<String>> {
    let path = String::from_utf8(stdout)
        .map_err(|_| anyhow::anyhow!("local vault picker returned non-UTF-8 output"))?
        .trim()
        .to_owned();

    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
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

#[cfg(not(windows))]
fn pick_local_vault_path() -> anyhow::Result<Option<String>> {
    anyhow::bail!("local vault picker is only implemented on Windows")
}

#[cfg(test)]
mod tests {
    use super::decode_picker_stdout;

    #[test]
    fn picker_stdout_decodes_utf8_paths_without_corruption() {
        let path = decode_picker_stdout("C:\\Users\\Example\\Desktop\\测试.kdbx\r\n".into())
            .expect("decode picker stdout");

        assert_eq!(
            path,
            Some("C:\\Users\\Example\\Desktop\\测试.kdbx".to_owned())
        );
    }

    #[test]
    fn picker_stdout_rejects_non_utf8_paths_instead_of_corrupting_them() {
        let gb2312_path = b"C:\\Users\\Example\\Desktop\\\xb2\xe2\xca\xd4.kdbx\r\n".to_vec();

        let error = decode_picker_stdout(gb2312_path).expect_err("non-UTF-8 should fail");

        assert!(error.to_string().contains("non-UTF-8"));
    }
}
