use crate::providers::durable_file::DurableFaultInjector;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vaultkern_runtime_protocol::contracts::{QuickUnlockLedgerEntry, QuickUnlockState};

const LEDGER_SCHEMA_VERSION: u32 = 1;
const KNOWN_ROW_KEYS: [&str; 4] = ["schema_version", "state", "generation", "policy"];

#[derive(Debug)]
pub(crate) enum LedgerStoreError {
    Io(io::Error),
    InvalidData { message: String },
}

impl fmt::Display for LedgerStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "quick unlock ledger I/O failed: {source}"),
            Self::InvalidData { message } => {
                write!(formatter, "quick unlock ledger is invalid: {message}")
            }
        }
    }
}

impl std::error::Error for LedgerStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::InvalidData { .. } => None,
        }
    }
}

impl From<io::Error> for LedgerStoreError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct LedgerDocumentWire {
    schema_version: u32,
    #[serde(default)]
    entries: BTreeMap<String, Value>,
    #[serde(flatten)]
    unknown: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
struct StoredLedgerRow {
    value: QuickUnlockLedgerEntry,
    unknown: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
struct LedgerDocument {
    entries: BTreeMap<String, StoredLedgerRow>,
    unknown: BTreeMap<String, Value>,
}

impl LedgerDocument {
    fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, LedgerStoreError> {
        let wire: LedgerDocumentWire =
            serde_json::from_slice(bytes).map_err(|source| LedgerStoreError::InvalidData {
                message: source.to_string(),
            })?;
        if wire.schema_version != LEDGER_SCHEMA_VERSION {
            return Err(invalid_data(format!(
                "unsupported document schema version {}",
                wire.schema_version
            )));
        }

        let mut entries = BTreeMap::new();
        for (vault_ref_id, row_value) in wire.entries {
            if vault_ref_id.is_empty() {
                return Err(invalid_data("vault_ref_id must not be empty"));
            }
            let mut unknown = row_value
                .as_object()
                .cloned()
                .ok_or_else(|| invalid_data(format!("row {vault_ref_id:?} is not an object")))?;
            let value: QuickUnlockLedgerEntry =
                serde_json::from_value(row_value).map_err(|source| {
                    invalid_data(format!(
                        "row {vault_ref_id:?} could not be decoded: {source}"
                    ))
                })?;
            validate_entry(&value)?;
            for key in KNOWN_ROW_KEYS {
                unknown.remove(key);
            }
            entries.insert(
                vault_ref_id,
                StoredLedgerRow {
                    value,
                    unknown: unknown.into_iter().collect(),
                },
            );
        }

        Ok(Self {
            entries,
            unknown: wire.unknown,
        })
    }

    fn encode_pretty(&self) -> Result<Vec<u8>, LedgerStoreError> {
        let mut document = Map::new();
        document.insert("schema_version".into(), Value::from(LEDGER_SCHEMA_VERSION));
        let mut entries = Map::new();
        for (vault_ref_id, row) in &self.entries {
            let mut value = serde_json::to_value(&row.value)
                .map_err(|source| invalid_data(format!("could not encode row: {source}")))?;
            let object = value
                .as_object_mut()
                .ok_or_else(|| invalid_data("encoded ledger row is not an object"))?;
            for (key, value) in &row.unknown {
                if !object.contains_key(key) {
                    object.insert(key.clone(), value.clone());
                }
            }
            entries.insert(vault_ref_id.clone(), value);
        }
        document.insert("entries".into(), Value::Object(entries));
        for (key, value) in &self.unknown {
            if !document.contains_key(key) {
                document.insert(key.clone(), value.clone());
            }
        }
        serde_json::to_vec_pretty(&Value::Object(document))
            .map_err(|source| invalid_data(format!("could not encode document: {source}")))
    }
}

fn validate_entry(entry: &QuickUnlockLedgerEntry) -> Result<(), LedgerStoreError> {
    if entry.schema_version != QuickUnlockLedgerEntry::SCHEMA_VERSION {
        return Err(invalid_data(format!(
            "unsupported row schema version {}",
            entry.schema_version
        )));
    }
    let policy_is_consistent = match entry.state {
        QuickUnlockState::Disabled => !entry.policy,
        QuickUnlockState::Enrolled | QuickUnlockState::NeedsReenroll { .. } => entry.policy,
    };
    if !policy_is_consistent {
        return Err(invalid_data("row state and policy are inconsistent"));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> LedgerStoreError {
    LedgerStoreError::InvalidData {
        message: message.into(),
    }
}

#[derive(Clone)]
pub(crate) struct QuickUnlockLedgerStore {
    backing: LedgerBacking,
}

#[derive(Clone)]
enum LedgerBacking {
    Memory(Arc<Mutex<LedgerDocument>>),
    Persistent {
        path: PathBuf,
        lock_timeout: Duration,
        faults: DurableFaultInjector,
    },
}

impl QuickUnlockLedgerStore {
    pub(crate) fn in_memory() -> Self {
        Self {
            backing: LedgerBacking::Memory(Arc::new(Mutex::new(LedgerDocument::empty()))),
        }
    }

    pub(crate) fn persistent(path: PathBuf, lock_timeout: Duration) -> Self {
        Self::persistent_inner(path, lock_timeout, DurableFaultInjector::default())
    }

    #[cfg(test)]
    pub(crate) fn persistent_with_faults(
        path: PathBuf,
        lock_timeout: Duration,
        faults: DurableFaultInjector,
    ) -> Self {
        Self::persistent_inner(path, lock_timeout, faults)
    }

    fn persistent_inner(
        path: PathBuf,
        lock_timeout: Duration,
        faults: DurableFaultInjector,
    ) -> Self {
        Self {
            backing: LedgerBacking::Persistent {
                path,
                lock_timeout,
                faults,
            },
        }
    }

    pub(crate) fn get(
        &self,
        vault_ref_id: &str,
    ) -> Result<Option<QuickUnlockLedgerEntry>, LedgerStoreError> {
        if vault_ref_id.is_empty() {
            return Err(invalid_data("vault_ref_id must not be empty"));
        }
        let document = match &self.backing {
            LedgerBacking::Memory(document) => {
                let document = document
                    .lock()
                    .map_err(|_| invalid_data("in-memory ledger lock is poisoned"))?;
                return Ok(document
                    .entries
                    .get(vault_ref_id)
                    .map(|row| row.value.clone()));
            }
            LedgerBacking::Persistent { path, .. } => match fs::read(path) {
                Ok(bytes) => LedgerDocument::decode(&bytes)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => LedgerDocument::empty(),
                Err(error) => return Err(error.into()),
            },
        };
        Ok(document
            .entries
            .get(vault_ref_id)
            .map(|row| row.value.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::{LedgerDocument, QuickUnlockLedgerStore};
    use serde_json::{Value, json};
    use std::fs;
    use std::time::Duration;
    use vaultkern_runtime_protocol::contracts::{QuickUnlockLedgerEntry, QuickUnlockState};

    fn valid_document() -> Value {
        json!({
            "schema_version": 1,
            "entries": {
                "vault-1": {
                    "schema_version": 1,
                    "state": { "kind": "enrolled" },
                    "generation": 7,
                    "policy": true
                }
            }
        })
    }

    fn persistent_store(document: &Value) -> (tempfile::TempDir, QuickUnlockLedgerStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quick-unlock-ledger.json");
        fs::write(&path, serde_json::to_vec_pretty(document).unwrap()).unwrap();
        let store = QuickUnlockLedgerStore::persistent(path, Duration::from_secs(1));
        (dir, store)
    }

    #[test]
    fn decoder_reads_empty_ledger() {
        let (_dir, store) = persistent_store(&json!({
            "schema_version": 1,
            "entries": {}
        }));

        assert_eq!(store.get("vault-1").unwrap(), None);
    }

    #[test]
    fn decoder_reads_enrolled_row() {
        let (_dir, store) = persistent_store(&valid_document());

        assert_eq!(
            store.get("vault-1").unwrap(),
            Some(QuickUnlockLedgerEntry {
                schema_version: QuickUnlockLedgerEntry::SCHEMA_VERSION,
                state: QuickUnlockState::Enrolled,
                generation: 7,
                policy: true,
            })
        );
    }

    #[test]
    fn decoder_rejects_missing_document_schema_version() {
        let (_dir, store) = persistent_store(&json!({ "entries": {} }));

        assert!(store.get("vault-1").is_err());
    }

    #[test]
    fn decoder_rejects_missing_row_schema_version() {
        let mut document = valid_document();
        document["entries"]["vault-1"]
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        let (_dir, store) = persistent_store(&document);

        assert!(store.get("vault-1").is_err());
    }

    #[test]
    fn decoder_rejects_unknown_state() {
        let mut document = valid_document();
        document["entries"]["vault-1"]["state"] = json!({ "kind": "future_state" });
        let (_dir, store) = persistent_store(&document);

        assert!(store.get("vault-1").is_err());
    }

    #[test]
    fn decoder_retains_unknown_top_level_fields() {
        let mut document = valid_document();
        document["future_metadata"] = json!({ "source": "newer-reader" });

        let decoded = LedgerDocument::decode(&serde_json::to_vec(&document).unwrap()).unwrap();

        assert_eq!(
            decoded.unknown.get("future_metadata"),
            Some(&json!({ "source": "newer-reader" }))
        );
    }

    #[test]
    fn decoder_round_trip_retains_unknown_row_fields() {
        let mut document = valid_document();
        document["entries"]["vault-1"]["future_row_field"] = json!([1, 2, 3]);

        let decoded = LedgerDocument::decode(&serde_json::to_vec(&document).unwrap()).unwrap();
        let encoded: Value = serde_json::from_slice(&decoded.encode_pretty().unwrap()).unwrap();

        assert_eq!(
            encoded["entries"]["vault-1"]["future_row_field"],
            json!([1, 2, 3])
        );
    }

    #[test]
    fn decoder_rejects_invalid_versions_empty_ids_and_inconsistent_policy() {
        let mut document_version = valid_document();
        document_version["schema_version"] = json!(2);
        assert!(LedgerDocument::decode(&serde_json::to_vec(&document_version).unwrap()).is_err());

        let mut row_version = valid_document();
        row_version["entries"]["vault-1"]["schema_version"] = json!(2);
        assert!(LedgerDocument::decode(&serde_json::to_vec(&row_version).unwrap()).is_err());

        let mut empty_id = valid_document();
        let row = empty_id["entries"]
            .as_object_mut()
            .unwrap()
            .remove("vault-1")
            .unwrap();
        empty_id["entries"]
            .as_object_mut()
            .unwrap()
            .insert("".into(), row);
        assert!(LedgerDocument::decode(&serde_json::to_vec(&empty_id).unwrap()).is_err());

        let mut inconsistent = valid_document();
        inconsistent["entries"]["vault-1"]["policy"] = json!(false);
        assert!(LedgerDocument::decode(&serde_json::to_vec(&inconsistent).unwrap()).is_err());
    }

    #[test]
    fn decoder_in_memory_store_uses_shared_validated_document() {
        let store = QuickUnlockLedgerStore::in_memory();
        let clone = store.clone();

        assert_eq!(store.get("vault-1").unwrap(), None);
        assert_eq!(clone.get("vault-1").unwrap(), None);
    }
}
