use vaultkern_core::{
    Attachment, CompositeKey, CustomField, Entry, KeepassCore, SaveProfile, TotpSpec, Vault,
};

fn main() {
    let mut args = std::env::args().skip(1);
    let core = KeepassCore::new();

    match args.next().as_deref() {
        Some("capabilities") => {
            for capability in core.capabilities() {
                println!("{capability}");
            }
        }
        Some("totp") => {
            let Some(uri) = args.next() else {
                eprintln!("usage: vkdbx totp <otpauth-uri> [unix-time]");
                std::process::exit(2);
            };
            let timestamp = args
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_else(current_unix_time);

            match TotpSpec::parse_otpauth(&uri).and_then(|spec| spec.generate_at(timestamp)) {
                Ok(code) => println!("{code}"),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
        Some("inspect-header") => {
            let Some(path) = args.next() else {
                eprintln!("usage: vkdbx inspect-header <file>");
                std::process::exit(2);
            };
            match std::fs::read(&path)
                .map_err(|error| error.to_string())
                .and_then(|bytes| {
                    core.inspect_kdbx_header(&bytes)
                        .map_err(|error| error.to_string())
                }) {
                Ok(summary) => {
                    println!("version={:?}", summary.version);
                    println!("cipher={:?}", summary.cipher);
                    println!("compression={:?}", summary.compression);
                    for (key, value) in summary.public_custom_data {
                        println!(
                            "public_custom_data.{key}={}",
                            String::from_utf8_lossy(&value)
                        );
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
        Some("roundtrip-demo") => {
            let Some(path) = args.next() else {
                eprintln!("usage: vkdbx roundtrip-demo <output-file> [password]");
                std::process::exit(2);
            };
            let password = args.next().unwrap_or_else(|| "demo-password".into());
            let vault = demo_vault();
            let mut key = CompositeKey::default();
            key.add_password(password);

            match core
                .save_kdbx(&vault, &key, SaveProfile::recommended())
                .and_then(|bytes| {
                    std::fs::write(&path, &bytes)
                        .map_err(|error| vaultkern_core::KdbxError::Xml(error.to_string()))?;
                    core.load_kdbx(&bytes, &key)
                }) {
                Ok(loaded) => {
                    println!("vault={}", loaded.name);
                    println!("entries={}", loaded.root.entries.len());
                    println!("attachments={}", loaded.root.entries[0].attachments.len());
                }
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: vkdbx <capabilities|totp|inspect-header|roundtrip-demo>");
            std::process::exit(2);
        }
    }
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn demo_vault() -> Vault {
    let mut vault = Vault::empty("vkdbx-demo");
    vault
        .public_custom_data
        .insert("client".into(), b"vkdbx".to_vec());

    let mut entry = Entry::new("Example");
    entry.username = "alice".into();
    entry.password = "s3cret".into();
    entry.url = "https://example.com".into();
    entry.notes = "demo".into();
    entry.created_at = 1710000000;
    entry.modified_at = 1710000100;
    entry.attributes.insert(
        "Secret".into(),
        CustomField {
            value: "protected-value".into(),
            protected: true,
        },
    );
    entry.attachments.insert(
        "hello.txt".into(),
        Attachment {
            name: "hello.txt".into(),
            data: b"hello attachment".to_vec(),
            protect_in_memory: true,
        },
    );
    entry.totp = TotpSpec::parse_otpauth(
        "otpauth://totp/ACME:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=6&period=30",
    )
    .ok();
    vault.root.entries.push(entry);
    vault
}
