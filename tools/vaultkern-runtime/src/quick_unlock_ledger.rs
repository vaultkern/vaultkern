use crate::providers::durable_file::{
    DurableFaultInjector, DurableFaultPoint, DurableFileIdentity, ExclusiveFileLock,
    TargetExpectation, TempWriteFaultPoints, create_dir_all_durable, opened_file_identity,
    path_file_identity, publish_temp, write_verified_temp,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vaultkern_runtime_protocol::contracts::{QuickUnlockLedgerEntry, QuickUnlockState};

const LEDGER_SCHEMA_VERSION: u32 = 1;
const KNOWN_ROW_KEYS: [&str; 4] = ["schema_version", "state", "generation", "policy"];

#[derive(Debug)]
pub(crate) enum LedgerStoreError {
    Io(io::Error),
    InvalidData { message: String },
    Busy { message: String },
    Conflict { message: String },
    BeforePublish { source: io::Error },
    OutcomeUnknown { source: io::Error },
}

impl fmt::Display for LedgerStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "quick unlock ledger I/O failed: {source}"),
            Self::InvalidData { message } => {
                write!(formatter, "quick unlock ledger is invalid: {message}")
            }
            Self::Busy { message } => write!(formatter, "quick unlock ledger is busy: {message}"),
            Self::Conflict { message } => {
                write!(formatter, "quick unlock ledger write conflict: {message}")
            }
            Self::BeforePublish { source } => {
                write!(
                    formatter,
                    "quick unlock ledger write failed before publish: {source}"
                )
            }
            Self::OutcomeUnknown { source } => write!(
                formatter,
                "quick unlock ledger may have published but durability is unknown: {source}"
            ),
        }
    }
}

impl std::error::Error for LedgerStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::BeforePublish { source } | Self::OutcomeUnknown { source } => Some(source),
            Self::InvalidData { .. } | Self::Busy { .. } | Self::Conflict { .. } => None,
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

#[derive(Debug, Clone, Deserialize)]
struct LedgerRowWire {
    schema_version: u32,
    state: Value,
    #[serde(rename = "generation")]
    _generation: u64,
    #[serde(rename = "policy")]
    _policy: bool,
}

#[derive(Debug, Clone)]
enum StoredLedgerRow {
    Known {
        value: QuickUnlockLedgerEntry,
        unknown: BTreeMap<String, Value>,
    },
    UnknownState {
        kind: String,
        raw: Value,
    },
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
            let row_wire: LedgerRowWire = serde_json::from_value(row_value.clone()).map_err(
                |source| {
                    invalid_data(format!(
                        "row {vault_ref_id:?} could not be decoded: {source}"
                    ))
                },
            )?;
            if row_wire.schema_version != QuickUnlockLedgerEntry::SCHEMA_VERSION {
                return Err(invalid_data(format!(
                    "unsupported row schema version {}",
                    row_wire.schema_version
                )));
            }
            let state_kind = row_wire
                .state
                .as_object()
                .and_then(|state| state.get("kind"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    invalid_data(format!("row {vault_ref_id:?} state has no string kind"))
                })?;
            if !matches!(state_kind, "disabled" | "enrolled" | "needs_reenroll") {
                entries.insert(
                    vault_ref_id,
                    StoredLedgerRow::UnknownState {
                        kind: state_kind.to_owned(),
                        raw: row_value,
                    },
                );
                continue;
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
                StoredLedgerRow::Known {
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
            let value = match row {
                StoredLedgerRow::Known { value, unknown } => {
                    let mut encoded = serde_json::to_value(value)
                        .map_err(|source| invalid_data(format!("could not encode row: {source}")))?;
                    let object = encoded
                        .as_object_mut()
                        .ok_or_else(|| invalid_data("encoded ledger row is not an object"))?;
                    for (key, value) in unknown {
                        if !object.contains_key(key) {
                            object.insert(key.clone(), value.clone());
                        }
                    }
                    encoded
                }
                StoredLedgerRow::UnknownState { raw, .. } => raw.clone(),
            };
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
                return read_entry(&document, vault_ref_id);
            }
            LedgerBacking::Persistent {
                path, lock_timeout, ..
            } => read_persistent_document_locked(path, *lock_timeout)?,
        };
        read_entry(&document, vault_ref_id)
    }

    pub(crate) fn compare_and_swap(
        &self,
        vault_ref_id: &str,
        expected: Option<&QuickUnlockLedgerEntry>,
        next: QuickUnlockLedgerEntry,
    ) -> Result<(), LedgerStoreError> {
        if vault_ref_id.is_empty() {
            return Err(invalid_data("vault_ref_id must not be empty"));
        }
        validate_entry(&next)?;
        match &self.backing {
            LedgerBacking::Memory(document) => {
                let mut document = document
                    .lock()
                    .map_err(|_| invalid_data("in-memory ledger lock is poisoned"))?;
                apply_compare_and_swap(&mut document, vault_ref_id, expected, next)
            }
            LedgerBacking::Persistent {
                path,
                lock_timeout,
                faults,
            } => self.compare_and_swap_persistent(
                path,
                *lock_timeout,
                faults,
                vault_ref_id,
                expected,
                next,
            ),
        }
    }

    fn compare_and_swap_persistent(
        &self,
        path: &Path,
        lock_timeout: Duration,
        faults: &DurableFaultInjector,
        vault_ref_id: &str,
        expected: Option<&QuickUnlockLedgerEntry>,
        next: QuickUnlockLedgerEntry,
    ) -> Result<(), LedgerStoreError> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| invalid_data("persistent ledger path has no parent directory"))?;
        create_dir_all_durable(parent)
            .map_err(|source| LedgerStoreError::BeforePublish { source })?;
        let lock_path = ledger_lock_path(path);
        let _lock = ExclusiveFileLock::acquire_with_timeout(&lock_path, lock_timeout).map_err(
            |source| {
                if source.kind() == io::ErrorKind::WouldBlock {
                    LedgerStoreError::Busy {
                        message: source.to_string(),
                    }
                } else {
                    LedgerStoreError::BeforePublish { source }
                }
            },
        )?;
        let (mut document, target_expectation) =
            read_persistent_document(path).map_err(|error| match error {
                LedgerStoreError::Io(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    LedgerStoreError::Conflict {
                        message: source.to_string(),
                    }
                }
                LedgerStoreError::Io(source) => LedgerStoreError::BeforePublish { source },
                error => error,
            })?;
        apply_compare_and_swap(&mut document, vault_ref_id, expected, next)?;
        let bytes = document.encode_pretty()?;
        let temp = write_verified_temp(
            path,
            &bytes,
            faults,
            TempWriteFaultPoints {
                created: DurableFaultPoint::TempCreated,
                written: DurableFaultPoint::TempWritten,
                synced: DurableFaultPoint::TempSynced,
                verified: DurableFaultPoint::TempReadbackVerified,
            },
        )
        .map_err(|source| LedgerStoreError::BeforePublish { source })?;
        publish_temp(
            temp,
            path,
            target_expectation,
            None,
            faults,
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        )
        .map_err(|error| {
            if error.target_conflict {
                LedgerStoreError::Conflict {
                    message: error.source.to_string(),
                }
            } else if error.published {
                LedgerStoreError::OutcomeUnknown {
                    source: error.source,
                }
            } else {
                LedgerStoreError::BeforePublish {
                    source: error.source,
                }
            }
        })
    }
}

fn apply_compare_and_swap(
    document: &mut LedgerDocument,
    vault_ref_id: &str,
    expected: Option<&QuickUnlockLedgerEntry>,
    next: QuickUnlockLedgerEntry,
) -> Result<(), LedgerStoreError> {
    match document.entries.get_mut(vault_ref_id) {
        Some(StoredLedgerRow::Known { value, .. }) => {
            if expected != Some(&*value) {
                return Err(LedgerStoreError::Conflict {
                    message: format!("row {vault_ref_id:?} no longer matches the expected value"),
                });
            }
            if next.generation < value.generation {
                return Err(LedgerStoreError::Conflict {
                    message: format!(
                        "row {vault_ref_id:?} generation cannot decrease from {} to {}",
                        value.generation, next.generation
                    ),
                });
            }
            *value = next;
        }
        Some(StoredLedgerRow::UnknownState { kind, .. }) => {
            return Err(invalid_data(format!(
                "row {vault_ref_id:?} has unsupported state {kind:?}"
            )));
        }
        None => {
            if expected.is_some() {
                return Err(LedgerStoreError::Conflict {
                    message: format!("row {vault_ref_id:?} does not exist"),
                });
            }
            document.entries.insert(
                vault_ref_id.to_owned(),
                StoredLedgerRow::Known {
                    value: next,
                    unknown: BTreeMap::new(),
                },
            );
        }
    }
    Ok(())
}

fn read_entry(
    document: &LedgerDocument,
    vault_ref_id: &str,
) -> Result<Option<QuickUnlockLedgerEntry>, LedgerStoreError> {
    match document.entries.get(vault_ref_id) {
        Some(StoredLedgerRow::Known { value, .. }) => Ok(Some(value.clone())),
        Some(StoredLedgerRow::UnknownState { kind, .. }) => Err(invalid_data(format!(
            "row {vault_ref_id:?} has unsupported state {kind:?}"
        ))),
        None => Ok(None),
    }
}

fn ledger_lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

fn read_persistent_document_locked(
    path: &Path,
    lock_timeout: Duration,
) -> Result<LedgerDocument, LedgerStoreError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(LedgerDocument::empty());
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let _lock = ExclusiveFileLock::acquire_with_timeout(&ledger_lock_path(path), lock_timeout)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::WouldBlock {
                LedgerStoreError::Busy {
                    message: source.to_string(),
                }
            } else {
                LedgerStoreError::Io(source)
            }
        })?;
    Ok(read_persistent_document(path)?.0)
}

fn read_persistent_document(
    path: &Path,
) -> Result<(LedgerDocument, TargetExpectation), LedgerStoreError> {
    match read_regular_file(path) {
        Ok((bytes, identity)) => Ok((
            LedgerDocument::decode(&bytes)?,
            TargetExpectation::Identity(identity),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok((LedgerDocument::empty(), TargetExpectation::Missing))
        }
        Err(error) => Err(error.into()),
    }
}

fn read_regular_file(path: &Path) -> io::Result<(Vec<u8>, DurableFileIdentity)> {
    let path_metadata = fs::symlink_metadata(path)?;
    validate_regular_file_metadata(&path_metadata)?;
    let expected_identity = path_file_identity(path, &path_metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    validate_regular_file_metadata(&before)?;
    let opened_identity = opened_file_identity(&file, &before)?;
    if opened_identity != expected_identity {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "ledger target changed while opening",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let final_path_metadata = fs::symlink_metadata(path)?;
    validate_regular_file_metadata(&after)?;
    validate_regular_file_metadata(&final_path_metadata)?;
    if opened_file_identity(&file, &after)? != opened_identity
        || path_file_identity(path, &final_path_metadata)? != opened_identity
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "ledger target changed while reading",
        ));
    }
    Ok((bytes, opened_identity))
}

fn validate_regular_file_metadata(metadata: &Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "quick unlock ledger target is not a regular file",
        ));
    }
    reject_reparse_point(metadata)
}

#[cfg(windows)]
fn reject_reparse_point(metadata: &Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "quick unlock ledger target is a reparse point",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_point(_metadata: &Metadata) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        LedgerDocument, LedgerStoreError, QuickUnlockLedgerStore, ledger_lock_path,
    };
    use crate::providers::durable_file::{
        DurableFaultInjector, DurableFaultPoint, ExclusiveFileLock,
    };
    use serde_json::{Value, json};
    use std::fs;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;
    use vaultkern_runtime_protocol::contracts::{
        NeedsReenrollReason, QuickUnlockLedgerEntry, QuickUnlockState,
    };

    fn disabled(generation: u64) -> QuickUnlockLedgerEntry {
        QuickUnlockLedgerEntry {
            schema_version: QuickUnlockLedgerEntry::SCHEMA_VERSION,
            state: QuickUnlockState::Disabled,
            generation,
            policy: false,
        }
    }

    fn enrolled(generation: u64) -> QuickUnlockLedgerEntry {
        QuickUnlockLedgerEntry {
            schema_version: QuickUnlockLedgerEntry::SCHEMA_VERSION,
            state: QuickUnlockState::Enrolled,
            generation,
            policy: true,
        }
    }

    fn needs_reenroll(generation: u64) -> QuickUnlockLedgerEntry {
        QuickUnlockLedgerEntry {
            schema_version: QuickUnlockLedgerEntry::SCHEMA_VERSION,
            state: QuickUnlockState::NeedsReenroll {
                reason: NeedsReenrollReason::BiometryChanged,
            },
            generation,
            policy: true,
        }
    }

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
    fn decoder_scopes_unknown_state_to_its_vault_and_preserves_the_raw_row() {
        let mut document = valid_document();
        let future_row = json!({
            "schema_version": 1,
            "state": { "kind": "future_state", "future_detail": "retained" },
            "generation": 11,
            "policy": true,
            "future_row_field": [1, 2, 3]
        });
        document["entries"]["vault-future"] = future_row.clone();
        let (dir, store) = persistent_store(&document);

        assert_eq!(store.get("vault-1").unwrap(), Some(enrolled(7)));
        assert!(matches!(
            store.get("vault-future"),
            Err(LedgerStoreError::InvalidData { .. })
        ));
        store
            .compare_and_swap("vault-1", Some(&enrolled(7)), enrolled(8))
            .unwrap();

        let published: Value =
            serde_json::from_slice(&fs::read(dir.path().join("quick-unlock-ledger.json")).unwrap())
                .unwrap();
        assert_eq!(published["entries"]["vault-future"], future_row);
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

    #[test]
    fn compare_and_swap_creates_disabled_and_enrolled_rows() {
        let store = QuickUnlockLedgerStore::in_memory();
        let clone = store.clone();

        store
            .compare_and_swap("vault-disabled", None, disabled(0))
            .unwrap();
        store
            .compare_and_swap("vault-enrolled", None, enrolled(1))
            .unwrap();

        assert_eq!(clone.get("vault-disabled").unwrap(), Some(disabled(0)));
        assert_eq!(clone.get("vault-enrolled").unwrap(), Some(enrolled(1)));
    }

    #[test]
    fn compare_and_swap_persists_increment_and_same_generation_reenroll() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger").join("quick-unlock.json");
        let store = QuickUnlockLedgerStore::persistent(path.clone(), Duration::from_secs(1));
        store
            .compare_and_swap("vault-1", None, enrolled(7))
            .unwrap();

        store
            .compare_and_swap("vault-1", Some(&enrolled(7)), enrolled(8))
            .unwrap();
        store
            .compare_and_swap("vault-1", Some(&enrolled(8)), needs_reenroll(8))
            .unwrap();

        let reopened = QuickUnlockLedgerStore::persistent(path, Duration::from_secs(1));
        assert_eq!(reopened.get("vault-1").unwrap(), Some(needs_reenroll(8)));
    }

    #[test]
    fn compare_and_swap_rejects_stale_expected_rows_and_generation_rollback() {
        let store = QuickUnlockLedgerStore::in_memory();
        store
            .compare_and_swap("vault-1", None, enrolled(7))
            .unwrap();

        let stale = store
            .compare_and_swap("vault-1", Some(&enrolled(6)), enrolled(8))
            .unwrap_err();
        let rollback = store
            .compare_and_swap("vault-1", Some(&enrolled(7)), disabled(6))
            .unwrap_err();

        assert!(matches!(stale, LedgerStoreError::Conflict { .. }));
        assert!(matches!(rollback, LedgerStoreError::Conflict { .. }));
        assert_eq!(store.get("vault-1").unwrap(), Some(enrolled(7)));
    }

    #[test]
    fn compare_and_swap_allows_exactly_one_of_two_persistent_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger").join("quick-unlock.json");
        let store = QuickUnlockLedgerStore::persistent(path, Duration::from_secs(1));
        store
            .compare_and_swap("vault-1", None, enrolled(7))
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let spawn = |candidate: QuickUnlockLedgerEntry| {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store.compare_and_swap("vault-1", Some(&enrolled(7)), candidate)
            })
        };
        let first = spawn(enrolled(8));
        let second = spawn(needs_reenroll(7));
        barrier.wait();
        let results = [first.join().unwrap(), second.join().unwrap()];

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(LedgerStoreError::Conflict { .. })))
                .count(),
            1
        );
        let visible = store.get("vault-1").unwrap().unwrap();
        assert!(visible == enrolled(8) || visible == needs_reenroll(7));
    }

    #[test]
    fn compare_and_swap_preserves_unknown_document_and_row_fields() {
        let mut document = valid_document();
        document["future_metadata"] = json!({ "source": "newer-reader" });
        document["entries"]["vault-1"]["future_row_field"] = json!([1, 2, 3]);
        let (dir, store) = persistent_store(&document);

        store
            .compare_and_swap("vault-1", Some(&enrolled(7)), enrolled(8))
            .unwrap();

        let published: Value =
            serde_json::from_slice(&fs::read(dir.path().join("quick-unlock-ledger.json")).unwrap())
                .unwrap();
        assert_eq!(
            published["future_metadata"],
            json!({ "source": "newer-reader" })
        );
        assert_eq!(
            published["entries"]["vault-1"]["future_row_field"],
            json!([1, 2, 3])
        );
    }

    #[test]
    fn compare_and_swap_reports_busy_when_persistent_lock_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("ledger");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("quick-unlock.json");
        let lock_path = parent.join("quick-unlock.json.lock");
        let held = ExclusiveFileLock::acquire(&lock_path).unwrap();
        let store = QuickUnlockLedgerStore::persistent(path, Duration::from_millis(20));

        let error = store
            .compare_and_swap("vault-1", None, disabled(0))
            .unwrap_err();

        assert!(matches!(error, LedgerStoreError::Busy { .. }));
        drop(held);
    }

    #[test]
    fn persistent_get_reports_busy_when_the_ledger_lock_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("ledger");
        let path = parent.join("quick-unlock.json");
        let store = QuickUnlockLedgerStore::persistent(path.clone(), Duration::from_secs(1));
        store
            .compare_and_swap("vault-1", None, enrolled(7))
            .unwrap();
        let held = ExclusiveFileLock::acquire(&ledger_lock_path(&path)).unwrap();
        let reader = QuickUnlockLedgerStore::persistent(path, Duration::from_millis(20));

        let error = reader.get("vault-1").unwrap_err();

        assert!(matches!(error, LedgerStoreError::Busy { .. }));
        drop(held);
    }

    #[test]
    fn publication_faults_recover_a_complete_old_or_new_document() {
        for point in [
            DurableFaultPoint::TempCreated,
            DurableFaultPoint::TempSynced,
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ledger").join("quick-unlock.json");
            let store = QuickUnlockLedgerStore::persistent(path.clone(), Duration::from_secs(1));
            store
                .compare_and_swap("vault-1", None, enrolled(7))
                .unwrap();
            let old_document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let mut new_document = old_document.clone();
            new_document["entries"]["vault-1"]["generation"] = json!(8);

            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "quick_unlock_ledger::tests::subprocess_ledger_crash_child",
                    "--ignored",
                ])
                .env("VAULTKERN_LEDGER_CRASH_PATH", &path)
                .env("VAULTKERN_DURABLE_CRASH_POINT", format!("{point:?}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_was_abruptly_killed(status, point);

            let recovered: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert!(
                recovered == old_document || recovered == new_document,
                "incomplete document recovered after {point:?}: {recovered}"
            );
            let reopened = QuickUnlockLedgerStore::persistent(path, Duration::from_secs(1));
            let entry = reopened.get("vault-1").unwrap().unwrap();
            assert!(entry == enrolled(7) || entry == enrolled(8));
        }
    }

    #[test]
    fn publication_faults_recover_absent_or_complete_new_document_on_first_creation() {
        for point in [
            DurableFaultPoint::TempCreated,
            DurableFaultPoint::TempSynced,
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ledger").join("quick-unlock.json");
            let new_document = json!({
                "schema_version": 1,
                "entries": {
                    "vault-1": {
                        "schema_version": 1,
                        "state": { "kind": "enrolled" },
                        "generation": 1,
                        "policy": true
                    }
                }
            });

            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "quick_unlock_ledger::tests::subprocess_ledger_create_crash_child",
                    "--ignored",
                ])
                .env("VAULTKERN_LEDGER_CRASH_PATH", &path)
                .env("VAULTKERN_DURABLE_CRASH_POINT", format!("{point:?}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_was_abruptly_killed(status, point);

            let reopened = QuickUnlockLedgerStore::persistent(path.clone(), Duration::from_secs(1));
            match fs::read(&path) {
                Ok(bytes) => {
                    let recovered: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(recovered, new_document, "{point:?}");
                    assert_eq!(reopened.get("vault-1").unwrap(), Some(enrolled(1)));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    assert_eq!(reopened.get("vault-1").unwrap(), None);
                }
                Err(error) => panic!("could not reopen ledger after {point:?}: {error}"),
            }
        }
    }

    #[test]
    fn publication_faults_distinguish_pre_publish_and_outcome_unknown() {
        for point in [
            DurableFaultPoint::TempCreated,
            DurableFaultPoint::TempSynced,
            DurableFaultPoint::BeforeTargetReplace,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ledger").join("quick-unlock.json");
            let store = QuickUnlockLedgerStore::persistent(path.clone(), Duration::from_secs(1));
            store
                .compare_and_swap("vault-1", None, enrolled(7))
                .unwrap();
            let faulted = QuickUnlockLedgerStore::persistent_with_faults(
                path,
                Duration::from_secs(1),
                DurableFaultInjector::fail_once(point),
            );

            let error = faulted
                .compare_and_swap("vault-1", Some(&enrolled(7)), enrolled(8))
                .unwrap_err();

            assert!(
                matches!(error, LedgerStoreError::BeforePublish { .. }),
                "{point:?}: {error}"
            );
            assert_eq!(faulted.get("vault-1").unwrap(), Some(enrolled(7)));
        }

        for point in [
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ledger").join("quick-unlock.json");
            let store = QuickUnlockLedgerStore::persistent(path.clone(), Duration::from_secs(1));
            store
                .compare_and_swap("vault-1", None, enrolled(7))
                .unwrap();
            let faulted = QuickUnlockLedgerStore::persistent_with_faults(
                path,
                Duration::from_secs(1),
                DurableFaultInjector::fail_once(point),
            );

            let error = faulted
                .compare_and_swap("vault-1", Some(&enrolled(7)), enrolled(8))
                .unwrap_err();

            assert!(
                matches!(error, LedgerStoreError::OutcomeUnknown { .. }),
                "{point:?}: {error}"
            );
            assert_eq!(faulted.get("vault-1").unwrap(), Some(enrolled(8)));
        }
    }

    #[test]
    fn publication_target_appearing_at_final_check_is_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger").join("quick-unlock.json");
        let external_path = path.clone();
        let store = QuickUnlockLedgerStore::persistent_with_faults(
            path.clone(),
            Duration::from_secs(1),
            DurableFaultInjector::run_once(DurableFaultPoint::BeforeTargetReplace, move || {
                fs::write(&external_path, b"external generation").unwrap();
            }),
        );

        let error = store
            .compare_and_swap("vault-1", None, disabled(0))
            .unwrap_err();

        assert!(matches!(error, LedgerStoreError::Conflict { .. }));
        assert_eq!(fs::read(path).unwrap(), b"external generation");
    }

    #[test]
    #[ignore]
    fn subprocess_ledger_crash_child() {
        let Some(path) = std::env::var_os("VAULTKERN_LEDGER_CRASH_PATH") else {
            return;
        };
        let point = DurableFaultPoint::from_test_name(
            &std::env::var("VAULTKERN_DURABLE_CRASH_POINT").unwrap(),
        )
        .unwrap();
        let store = QuickUnlockLedgerStore::persistent_with_faults(
            path.into(),
            Duration::from_secs(1),
            DurableFaultInjector::crash_once(point),
        );
        let _ = store.compare_and_swap("vault-1", Some(&enrolled(7)), enrolled(8));
        panic!("crash point was not reached: {point:?}");
    }

    #[test]
    #[ignore]
    fn subprocess_ledger_create_crash_child() {
        let Some(path) = std::env::var_os("VAULTKERN_LEDGER_CRASH_PATH") else {
            return;
        };
        let point = DurableFaultPoint::from_test_name(
            &std::env::var("VAULTKERN_DURABLE_CRASH_POINT").unwrap(),
        )
        .unwrap();
        let store = QuickUnlockLedgerStore::persistent_with_faults(
            path.into(),
            Duration::from_secs(1),
            DurableFaultInjector::crash_once(point),
        );
        let _ = store.compare_and_swap("vault-1", None, enrolled(1));
        panic!("crash point was not reached: {point:?}");
    }

    #[cfg(unix)]
    fn assert_was_abruptly_killed(status: std::process::ExitStatus, point: DurableFaultPoint) {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{point:?}");
    }

    #[cfg(windows)]
    fn assert_was_abruptly_killed(status: std::process::ExitStatus, point: DurableFaultPoint) {
        assert_eq!(status.code(), Some(86), "{point:?}");
    }

    #[cfg(not(any(unix, windows)))]
    fn assert_was_abruptly_killed(status: std::process::ExitStatus, point: DurableFaultPoint) {
        assert!(!status.success(), "{point:?}");
    }
}
