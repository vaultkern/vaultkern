//! Regenerate-and-compare snapshot check for the frozen JSON Schema
//! artifacts under `schemas/` (000, Execution discipline #1: the canonical
//! source of the protocol schema is the Rust types; the generated JSON
//! Schema artifact and its CI snapshot check land in the same freeze).
//!
//! Run with `cargo test -p vaultkern-runtime-protocol --features
//! json-schema`. Regenerate after an intentional (additive) contract change
//! with `VAULTKERN_BLESS=1` and review the diff.
#![cfg(feature = "json-schema")]

use std::path::PathBuf;

use schemars::{JsonSchema, schema_for};
use vaultkern_runtime_protocol::contracts::{
    CacheManifest, JournalOpKind, JournalRecord, PlatformRecordKey, QuickUnlockLedgerEntry,
};

fn schema_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join(name)
}

fn assert_schema_matches<T: JsonSchema>(name: &str) {
    let schema = schema_for!(T);
    let rendered = serde_json::to_string_pretty(&schema).expect("render schema");
    let path = schema_path(name);

    if std::env::var_os("VAULTKERN_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &rendered).unwrap();
        return;
    }

    let golden = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing frozen schema {}: {err}", path.display()));
    assert_eq!(
        rendered.as_bytes(),
        golden.as_bytes(),
        "generated schema for {name} no longer matches the frozen artifact; \
         if the contract change is intentional (and additive), regenerate \
         with VAULTKERN_BLESS=1 and review the diff"
    );
}

#[test]
fn cache_manifest_schema_is_frozen() {
    assert_schema_matches::<CacheManifest>("cache_manifest.schema.json");
}

#[test]
fn journal_record_schema_is_frozen() {
    assert_schema_matches::<JournalRecord>("journal_record.schema.json");
}

#[test]
fn journal_op_kind_schema_is_frozen() {
    // The decrypted plaintext vocabulary of JournalRecord.payload_sealed
    // (003 r9) — a frozen contract in its own right.
    assert_schema_matches::<JournalOpKind>("journal_op_kind.schema.json");
}

#[test]
fn quick_unlock_ledger_entry_schema_is_frozen() {
    assert_schema_matches::<QuickUnlockLedgerEntry>("quick_unlock_ledger_entry.schema.json");
}

#[test]
fn platform_record_key_schema_is_frozen() {
    assert_schema_matches::<PlatformRecordKey>("platform_record_key.schema.json");
}
