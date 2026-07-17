#![cfg(feature = "external-fixtures")]

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use vaultkern_crypto::CompositeKey;
use vaultkern_kdbx::{
    Compression, KdbxCipher, KdbxVersion, SaveKdf, SaveProfile, inspect_kdbx_header, save_kdbx,
};
use vaultkern_model::{Entry, Vault};

const PASSWORD: &str = "vaultkern-writer-interop";
const ENTRY_TITLE: &str = "Writer Interop Sentinel";

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "vaultkern-keepassxc-interop-{}-{label}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir(&path).expect("create interoperability scratch directory");
        Self(path)
    }

    fn database(&self, label: &str) -> PathBuf {
        self.0.join(format!("writer-{label}.kdbx"))
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn keepassxc_cli_decrypts_and_enumerates_v40_writer_output() {
    verify_writer_profile(KdbxVersion::V4_0, "4.0", "semantic-value-v4.0");
}

#[test]
fn keepassxc_cli_decrypts_and_enumerates_v41_writer_output() {
    verify_writer_profile(KdbxVersion::V4_1, "4.1", "semantic-value-v4.1");
}

fn verify_writer_profile(version: KdbxVersion, label: &str, username: &str) {
    let scratch = ScratchDir::new(label);
    let database = scratch.database(label);
    let mut vault = Vault::empty(format!("vaultkern writer {label}"));
    let mut entry = Entry::new(ENTRY_TITLE);
    entry.username = username.into();
    entry.password = "writer-interop-secret".into();
    entry.url = format!("https://interop.vaultkern.test/{label}");
    vault.root.entries.push(entry);

    let mut key = CompositeKey::default();
    key.add_password(PASSWORD);
    let profile = SaveProfile {
        version,
        cipher: KdbxCipher::Aes256,
        compression: Compression::Gzip,
        kdf: SaveKdf::Argon2id {
            iterations: 2,
            memory_kib: 8 * 1024,
            parallelism: 1,
        },
    };
    let bytes = save_kdbx(&vault, &key, &profile).expect("write interoperability database");
    fs::write(&database, &bytes).expect("persist interoperability database");

    let raw_version = u32::from_le_bytes(bytes[8..12].try_into().expect("KDBX version bytes"));
    let expected_raw_version = match version {
        KdbxVersion::V4_0 => 0x0004_0000,
        KdbxVersion::V4_1 => 0x0004_0001,
        _ => panic!("writer interoperability gate only covers KDBX 4.x"),
    };
    assert_eq!(raw_version, expected_raw_version, "raw header for {label}");
    let header = inspect_kdbx_header(&bytes).expect("inspect writer header");
    assert_eq!(header.version, version, "writer header for {label}");

    let listing = run_keepassxc(&[OsStr::new("ls"), database.as_os_str()]);
    assert_success(&listing, "enumerate", &database);
    let listing = String::from_utf8(listing.stdout).expect("KeePassXC listing is UTF-8");
    assert!(
        listing.lines().any(|line| line.trim() == ENTRY_TITLE),
        "KeePassXC listing for {label} omitted {ENTRY_TITLE:?}: {listing:?}"
    );

    let shown = run_keepassxc(&[
        OsStr::new("show"),
        OsStr::new("-a"),
        OsStr::new("UserName"),
        database.as_os_str(),
        OsStr::new(ENTRY_TITLE),
    ]);
    assert_success(&shown, "read semantic value", &database);
    assert_eq!(
        String::from_utf8(shown.stdout)
            .expect("KeePassXC entry output is UTF-8")
            .trim(),
        username,
        "KeePassXC semantic value for {label}"
    );
}

fn run_keepassxc(arguments: &[&OsStr]) -> Output {
    let mut child = Command::new("keepassxc-cli")
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keepassxc-cli must be installed for the interoperability gate");
    child
        .stdin
        .take()
        .expect("KeePassXC password input")
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .expect("write KeePassXC password");
    child.wait_with_output().expect("wait for keepassxc-cli")
}

fn assert_success(output: &Output, operation: &str, database: &Path) {
    assert!(
        output.status.success(),
        "KeePassXC failed to {operation} {} (status: {}, stdout: {:?}, stderr: {:?})",
        database.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
