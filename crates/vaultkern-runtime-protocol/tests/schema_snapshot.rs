//! Regenerate-and-compare snapshot check for the live JSON Schema artifacts.
//!
//! Run with `cargo test -p vaultkern-runtime-protocol --features
//! json-schema`. Regenerate after an intentional (additive) contract change
//! with `VAULTKERN_BLESS=1` and review the diff.
//!
#![cfg(feature = "json-schema")]

use std::path::PathBuf;

use schemars::{JsonSchema, schema_for};
use vaultkern_runtime_protocol::MergeSummaryDto;

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
        if std::env::var_os("CI").is_some() {
            panic!("VAULTKERN_BLESS is set in CI; schemas are developer-machine only");
        }
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
fn merge_summary_dto_schema_is_frozen() {
    // M2: MergeSummaryDto joins the freeze — it is a protocol DTO, but its
    // two conflict counters are pinned by 001/004 alongside the storage
    // contracts.
    assert_schema_matches::<MergeSummaryDto>("merge_summary_dto.schema.json");
}
