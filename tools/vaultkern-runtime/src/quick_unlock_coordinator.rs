use crate::quick_unlock_ledger::{LedgerStoreError, QuickUnlockLedgerStore};
use std::fmt;
use std::sync::Arc;
use vaultkern_runtime_protocol::contracts::{
    NeedsReenrollReason, PlatformRecordKey, QuickUnlockLedgerEntry, QuickUnlockState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuickUnlockOperation {
    Enable,
    Unlock,
    FullCredentialUnlock,
    Disable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuickUnlockError {
    PermanentlyInvalidated,
    TemporarilyUnavailable,
    UserCancelled,
    LockedOut,
    NotEnrolled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuickUnlockOperationResult {
    Success,
    KdfGenerationMismatch,
    Error(QuickUnlockError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReductionDisposition {
    Refused,
    NoChange,
    Commit,
    SealThenCommit,
    CommitThenCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reduction {
    pub(crate) next: QuickUnlockLedgerEntry,
    pub(crate) disposition: ReductionDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReduceError {
    GenerationOverflow,
}

pub(crate) fn reduce(
    current: &QuickUnlockLedgerEntry,
    operation: QuickUnlockOperation,
    result: QuickUnlockOperationResult,
) -> Result<Reduction, ReduceError> {
    let unchanged = |disposition| Reduction {
        next: current.clone(),
        disposition,
    };
    match (&current.state, operation, result) {
        (
            QuickUnlockState::Disabled,
            QuickUnlockOperation::Enable,
            QuickUnlockOperationResult::Success,
        ) => {
            let mut next = current.clone();
            next.state = QuickUnlockState::Enrolled;
            next.generation = next_generation(current.generation)?;
            next.policy = true;
            Ok(Reduction {
                next,
                disposition: ReductionDisposition::SealThenCommit,
            })
        }
        (
            QuickUnlockState::Enrolled,
            QuickUnlockOperation::Unlock,
            QuickUnlockOperationResult::Error(QuickUnlockError::PermanentlyInvalidated),
        ) => {
            let mut next = current.clone();
            next.state = QuickUnlockState::NeedsReenroll {
                reason: NeedsReenrollReason::BiometryChanged,
            };
            Ok(Reduction {
                next,
                disposition: ReductionDisposition::Commit,
            })
        }
        (
            QuickUnlockState::Enrolled,
            QuickUnlockOperation::Unlock,
            QuickUnlockOperationResult::KdfGenerationMismatch,
        ) => {
            let mut next = current.clone();
            next.state = QuickUnlockState::NeedsReenroll {
                reason: NeedsReenrollReason::KdfRotated,
            };
            Ok(Reduction {
                next,
                disposition: ReductionDisposition::Commit,
            })
        }
        (
            QuickUnlockState::Enrolled,
            QuickUnlockOperation::Unlock,
            QuickUnlockOperationResult::Success
            | QuickUnlockOperationResult::Error(
                QuickUnlockError::TemporarilyUnavailable
                | QuickUnlockError::UserCancelled
                | QuickUnlockError::LockedOut,
            ),
        ) => Ok(unchanged(ReductionDisposition::NoChange)),
        (
            QuickUnlockState::NeedsReenroll { .. },
            QuickUnlockOperation::FullCredentialUnlock,
            QuickUnlockOperationResult::Success,
        ) => {
            let mut next = current.clone();
            next.state = QuickUnlockState::Enrolled;
            next.generation = next_generation(current.generation)?;
            Ok(Reduction {
                next,
                disposition: ReductionDisposition::SealThenCommit,
            })
        }
        (_, QuickUnlockOperation::Disable, _) => {
            let mut next = current.clone();
            next.state = QuickUnlockState::Disabled;
            next.generation = next_generation(current.generation)?;
            next.policy = false;
            Ok(Reduction {
                next,
                disposition: ReductionDisposition::CommitThenCleanup,
            })
        }
        _ => Ok(unchanged(ReductionDisposition::Refused)),
    }
}

fn next_generation(generation: u64) -> Result<u64, ReduceError> {
    generation
        .checked_add(1)
        .ok_or(ReduceError::GenerationOverflow)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlatformError {
    pub(crate) domain: String,
    pub(crate) code: i64,
}

impl PlatformError {
    pub(crate) fn new(domain: impl Into<String>, code: i64) -> Self {
        Self {
            domain: domain.into(),
            code,
        }
    }
}

pub(crate) trait QuickUnlockRecordStore: Send + Sync {
    fn seal(&self, key: &PlatformRecordKey, opaque_envelope: &[u8]) -> Result<(), PlatformError>;
    fn unseal(&self, key: &PlatformRecordKey) -> Result<Vec<u8>, PlatformError>;
    fn delete(&self, key: &PlatformRecordKey) -> Result<(), PlatformError>;
}

pub(crate) trait PlatformErrorClassifier: Send + Sync {
    fn classify(&self, operation: QuickUnlockOperation, error: &PlatformError) -> QuickUnlockError;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionUnlockKind {
    Locked,
    PasswordUnlocked,
    QuickUnlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvelopeInspection {
    Valid,
    KdfGenerationMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnableOutcome {
    Enabled,
    PasswordUnlockRequired,
    Refused(QuickUnlockError),
    Failed(QuickUnlockError),
    NoChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FullCredentialOutcome {
    Resealed,
    Failed(QuickUnlockError),
    NoChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnlockOutcome {
    Unlocked(Vec<u8>),
    NeedsReenroll(NeedsReenrollReason),
    Failed(QuickUnlockError),
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CleanupStatus {
    Complete,
    Pending(PlatformError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DisableOutcome {
    pub(crate) cleanup: CleanupStatus,
}

#[derive(Debug)]
pub(crate) enum CoordinatorError {
    Ledger(LedgerStoreError),
    GenerationOverflow,
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ledger(error) => write!(formatter, "{error}"),
            Self::GenerationOverflow => {
                formatter.write_str("quick unlock record generation overflowed")
            }
        }
    }
}

impl std::error::Error for CoordinatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ledger(error) => Some(error),
            Self::GenerationOverflow => None,
        }
    }
}

impl From<LedgerStoreError> for CoordinatorError {
    fn from(error: LedgerStoreError) -> Self {
        Self::Ledger(error)
    }
}

impl From<ReduceError> for CoordinatorError {
    fn from(_: ReduceError) -> Self {
        Self::GenerationOverflow
    }
}

pub(crate) struct QuickUnlockCoordinator {
    ledger: QuickUnlockLedgerStore,
    records: Arc<dyn QuickUnlockRecordStore>,
    classifier: Arc<dyn PlatformErrorClassifier>,
}

impl QuickUnlockCoordinator {
    pub(crate) fn new(
        ledger: QuickUnlockLedgerStore,
        records: Arc<dyn QuickUnlockRecordStore>,
        classifier: Arc<dyn PlatformErrorClassifier>,
    ) -> Self {
        Self {
            ledger,
            records,
            classifier,
        }
    }

    pub(crate) fn enable(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
        session: SessionUnlockKind,
        opaque_envelope: &[u8],
    ) -> Result<EnableOutcome, CoordinatorError> {
        if session != SessionUnlockKind::PasswordUnlocked {
            return Ok(EnableOutcome::PasswordUnlockRequired);
        }
        let (stored, current) = self.current_entry(vault_ref_id)?;
        let reduction = reduce(
            &current,
            QuickUnlockOperation::Enable,
            QuickUnlockOperationResult::Success,
        )?;
        if reduction.disposition != ReductionDisposition::SealThenCommit {
            return Ok(EnableOutcome::NoChange);
        }
        let record_key =
            platform_record_key(identifier_scope, vault_ref_id, reduction.next.generation);
        if let Err(error) = self.records.seal(&record_key, opaque_envelope) {
            let category = self
                .classifier
                .classify(QuickUnlockOperation::Enable, &error);
            return Ok(if category == QuickUnlockError::NotEnrolled {
                EnableOutcome::Refused(category)
            } else {
                EnableOutcome::Failed(category)
            });
        }
        self.ledger
            .compare_and_swap(vault_ref_id, stored.as_ref(), reduction.next)?;
        Ok(EnableOutcome::Enabled)
    }

    pub(crate) fn full_credential_unlocked(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
        opaque_envelope: &[u8],
    ) -> Result<FullCredentialOutcome, CoordinatorError> {
        let (stored, current) = self.current_entry(vault_ref_id)?;
        let reduction = reduce(
            &current,
            QuickUnlockOperation::FullCredentialUnlock,
            QuickUnlockOperationResult::Success,
        )?;
        if reduction.disposition != ReductionDisposition::SealThenCommit {
            return Ok(FullCredentialOutcome::NoChange);
        }
        let record_key =
            platform_record_key(identifier_scope, vault_ref_id, reduction.next.generation);
        if let Err(error) = self.records.seal(&record_key, opaque_envelope) {
            return Ok(FullCredentialOutcome::Failed(
                self.classifier
                    .classify(QuickUnlockOperation::FullCredentialUnlock, &error),
            ));
        }
        self.ledger
            .compare_and_swap(vault_ref_id, stored.as_ref(), reduction.next)?;
        Ok(FullCredentialOutcome::Resealed)
    }

    pub(crate) fn unlock<F>(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
        inspect: F,
    ) -> Result<UnlockOutcome, CoordinatorError>
    where
        F: FnOnce(&[u8]) -> EnvelopeInspection,
    {
        let (stored, current) = self.current_entry(vault_ref_id)?;
        if !matches!(current.state, QuickUnlockState::Enrolled) {
            return Ok(UnlockOutcome::Refused);
        }
        let record_key = platform_record_key(identifier_scope, vault_ref_id, current.generation);
        let opaque_envelope = match self.records.unseal(&record_key) {
            Ok(envelope) => envelope,
            Err(error) => {
                let category = self
                    .classifier
                    .classify(QuickUnlockOperation::Unlock, &error);
                let reduction = reduce(
                    &current,
                    QuickUnlockOperation::Unlock,
                    QuickUnlockOperationResult::Error(category),
                )?;
                if reduction.disposition == ReductionDisposition::Commit {
                    self.ledger.compare_and_swap(
                        vault_ref_id,
                        stored.as_ref(),
                        reduction.next.clone(),
                    )?;
                    return Ok(UnlockOutcome::NeedsReenroll(reenroll_reason(
                        &reduction.next,
                    )));
                }
                return Ok(UnlockOutcome::Failed(category));
            }
        };
        match inspect(&opaque_envelope) {
            EnvelopeInspection::Valid => {
                // Linearize release of the envelope against concurrent disable or rotation.
                self.ledger
                    .compare_and_swap(vault_ref_id, stored.as_ref(), current)?;
                Ok(UnlockOutcome::Unlocked(opaque_envelope))
            }
            EnvelopeInspection::KdfGenerationMismatch => {
                let reduction = reduce(
                    &current,
                    QuickUnlockOperation::Unlock,
                    QuickUnlockOperationResult::KdfGenerationMismatch,
                )?;
                self.ledger.compare_and_swap(
                    vault_ref_id,
                    stored.as_ref(),
                    reduction.next.clone(),
                )?;
                Ok(UnlockOutcome::NeedsReenroll(reenroll_reason(
                    &reduction.next,
                )))
            }
        }
    }

    pub(crate) fn disable(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
    ) -> Result<DisableOutcome, CoordinatorError> {
        let (stored, current) = self.current_entry(vault_ref_id)?;
        let reduction = reduce(
            &current,
            QuickUnlockOperation::Disable,
            QuickUnlockOperationResult::Success,
        )?;
        self.ledger
            .compare_and_swap(vault_ref_id, stored.as_ref(), reduction.next)?;
        let old_key = platform_record_key(identifier_scope, vault_ref_id, current.generation);
        let cleanup = match self.records.delete(&old_key) {
            Ok(()) => CleanupStatus::Complete,
            Err(error) => CleanupStatus::Pending(error),
        };
        Ok(DisableOutcome { cleanup })
    }

    fn current_entry(
        &self,
        vault_ref_id: &str,
    ) -> Result<(Option<QuickUnlockLedgerEntry>, QuickUnlockLedgerEntry), CoordinatorError> {
        let stored = self.ledger.get(vault_ref_id)?;
        let current = stored.clone().unwrap_or_else(initial_entry);
        Ok((stored, current))
    }
}

fn initial_entry() -> QuickUnlockLedgerEntry {
    QuickUnlockLedgerEntry {
        schema_version: QuickUnlockLedgerEntry::SCHEMA_VERSION,
        state: QuickUnlockState::Disabled,
        generation: 0,
        policy: false,
    }
}

fn platform_record_key(
    identifier_scope: &str,
    vault_ref_id: &str,
    record_generation: u64,
) -> PlatformRecordKey {
    PlatformRecordKey {
        identifier_scope: identifier_scope.to_owned(),
        vault_ref_id: vault_ref_id.to_owned(),
        record_generation,
    }
}

fn reenroll_reason(entry: &QuickUnlockLedgerEntry) -> NeedsReenrollReason {
    match entry.state {
        QuickUnlockState::NeedsReenroll { reason } => reason,
        QuickUnlockState::Disabled | QuickUnlockState::Enrolled => {
            unreachable!("commit reduction did not produce NeedsReenroll")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CleanupStatus, CoordinatorError, DisableOutcome, EnableOutcome, EnvelopeInspection,
        FullCredentialOutcome, PlatformError, PlatformErrorClassifier, QuickUnlockCoordinator,
        QuickUnlockError, QuickUnlockOperation, QuickUnlockOperationResult, QuickUnlockRecordStore,
        ReduceError, ReductionDisposition, SessionUnlockKind, UnlockOutcome, reduce,
    };
    use crate::quick_unlock_ledger::{LedgerStoreError, QuickUnlockLedgerStore};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use vaultkern_runtime_protocol::contracts::{
        NeedsReenrollReason, PlatformRecordKey, QuickUnlockLedgerEntry, QuickUnlockState,
    };

    fn entry(state: QuickUnlockState, generation: u64) -> QuickUnlockLedgerEntry {
        let policy = !matches!(state, QuickUnlockState::Disabled);
        QuickUnlockLedgerEntry {
            schema_version: QuickUnlockLedgerEntry::SCHEMA_VERSION,
            state,
            generation,
            policy,
        }
    }

    #[test]
    fn reducer_enables_a_disabled_vault_at_the_next_generation() {
        let current = entry(QuickUnlockState::Disabled, 7);

        let reduction = reduce(
            &current,
            QuickUnlockOperation::Enable,
            QuickUnlockOperationResult::Success,
        )
        .unwrap();

        assert_eq!(reduction.disposition, ReductionDisposition::SealThenCommit);
        assert_eq!(reduction.next.state, QuickUnlockState::Enrolled);
        assert_eq!(reduction.next.generation, 8);
        assert!(reduction.next.policy);
    }

    #[test]
    fn reducer_enumerates_the_complete_state_operation_result_product() {
        let states = [
            QuickUnlockState::Disabled,
            QuickUnlockState::Enrolled,
            QuickUnlockState::NeedsReenroll {
                reason: NeedsReenrollReason::BiometryChanged,
            },
        ];
        let operations = [
            QuickUnlockOperation::Enable,
            QuickUnlockOperation::Unlock,
            QuickUnlockOperation::FullCredentialUnlock,
            QuickUnlockOperation::Disable,
        ];
        let results = [
            QuickUnlockOperationResult::Success,
            QuickUnlockOperationResult::KdfGenerationMismatch,
            QuickUnlockOperationResult::Error(QuickUnlockError::PermanentlyInvalidated),
            QuickUnlockOperationResult::Error(QuickUnlockError::TemporarilyUnavailable),
            QuickUnlockOperationResult::Error(QuickUnlockError::UserCancelled),
            QuickUnlockOperationResult::Error(QuickUnlockError::LockedOut),
            QuickUnlockOperationResult::Error(QuickUnlockError::NotEnrolled),
        ];
        let mut visited = 0;

        for state in &states {
            for &operation in &operations {
                for &result in &results {
                    let current = entry(state.clone(), 12);
                    let reduction = reduce(&current, operation, result).unwrap();
                    visited += 1;

                    let expected = match (state, operation, result) {
                        (
                            QuickUnlockState::Disabled,
                            QuickUnlockOperation::Enable,
                            QuickUnlockOperationResult::Success,
                        ) => ReductionDisposition::SealThenCommit,
                        (
                            QuickUnlockState::Enrolled,
                            QuickUnlockOperation::Unlock,
                            QuickUnlockOperationResult::Error(
                                QuickUnlockError::PermanentlyInvalidated,
                            ),
                        )
                        | (
                            QuickUnlockState::Enrolled,
                            QuickUnlockOperation::Unlock,
                            QuickUnlockOperationResult::KdfGenerationMismatch,
                        ) => ReductionDisposition::Commit,
                        (
                            QuickUnlockState::Enrolled,
                            QuickUnlockOperation::Unlock,
                            QuickUnlockOperationResult::Success
                            | QuickUnlockOperationResult::Error(
                                QuickUnlockError::TemporarilyUnavailable
                                | QuickUnlockError::UserCancelled
                                | QuickUnlockError::LockedOut,
                            ),
                        ) => ReductionDisposition::NoChange,
                        (
                            QuickUnlockState::NeedsReenroll { .. },
                            QuickUnlockOperation::FullCredentialUnlock,
                            QuickUnlockOperationResult::Success,
                        ) => ReductionDisposition::SealThenCommit,
                        (_, QuickUnlockOperation::Disable, _) => {
                            ReductionDisposition::CommitThenCleanup
                        }
                        _ => ReductionDisposition::Refused,
                    };
                    assert_eq!(
                        reduction.disposition, expected,
                        "state={state:?}, operation={operation:?}, result={result:?}"
                    );
                    let expected_next = match (state, operation, result) {
                        (
                            QuickUnlockState::Disabled,
                            QuickUnlockOperation::Enable,
                            QuickUnlockOperationResult::Success,
                        )
                        | (
                            QuickUnlockState::NeedsReenroll { .. },
                            QuickUnlockOperation::FullCredentialUnlock,
                            QuickUnlockOperationResult::Success,
                        ) => entry(QuickUnlockState::Enrolled, 13),
                        (
                            QuickUnlockState::Enrolled,
                            QuickUnlockOperation::Unlock,
                            QuickUnlockOperationResult::Error(
                                QuickUnlockError::PermanentlyInvalidated,
                            ),
                        ) => entry(
                            QuickUnlockState::NeedsReenroll {
                                reason: NeedsReenrollReason::BiometryChanged,
                            },
                            12,
                        ),
                        (
                            QuickUnlockState::Enrolled,
                            QuickUnlockOperation::Unlock,
                            QuickUnlockOperationResult::KdfGenerationMismatch,
                        ) => entry(
                            QuickUnlockState::NeedsReenroll {
                                reason: NeedsReenrollReason::KdfRotated,
                            },
                            12,
                        ),
                        (_, QuickUnlockOperation::Disable, _) => {
                            entry(QuickUnlockState::Disabled, 13)
                        }
                        _ => current.clone(),
                    };
                    assert_eq!(reduction.next, expected_next);
                }
            }
        }

        assert_eq!(visited, states.len() * operations.len() * results.len());
        assert_eq!(visited, 84);
    }

    #[test]
    fn reducer_maps_permanent_and_kdf_failures_to_the_required_reenroll_reasons() {
        let current = entry(QuickUnlockState::Enrolled, 4);

        let permanent = reduce(
            &current,
            QuickUnlockOperation::Unlock,
            QuickUnlockOperationResult::Error(QuickUnlockError::PermanentlyInvalidated),
        )
        .unwrap();
        let kdf = reduce(
            &current,
            QuickUnlockOperation::Unlock,
            QuickUnlockOperationResult::KdfGenerationMismatch,
        )
        .unwrap();

        assert_eq!(
            permanent.next.state,
            QuickUnlockState::NeedsReenroll {
                reason: NeedsReenrollReason::BiometryChanged
            }
        );
        assert_eq!(
            kdf.next.state,
            QuickUnlockState::NeedsReenroll {
                reason: NeedsReenrollReason::KdfRotated
            }
        );
    }

    #[test]
    fn reducer_generation_overflow_never_wraps() {
        let current = entry(QuickUnlockState::Disabled, u64::MAX);

        assert_eq!(
            reduce(
                &current,
                QuickUnlockOperation::Enable,
                QuickUnlockOperationResult::Success,
            ),
            Err(ReduceError::GenerationOverflow)
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RecordCall {
        Seal(PlatformRecordKey, Vec<u8>),
        Unseal(PlatformRecordKey),
        Delete(PlatformRecordKey),
    }

    struct FakeRecordStore {
        records: Mutex<Vec<(PlatformRecordKey, Vec<u8>)>>,
        calls: Mutex<Vec<RecordCall>>,
        seal_error: Mutex<Option<PlatformError>>,
        unseal_error: Mutex<Option<PlatformError>>,
        delete_error: Mutex<Option<PlatformError>>,
        after_seal_cas: Mutex<Option<ForcedCas>>,
        after_unseal_cas: Mutex<Option<ForcedCas>>,
        seal_barrier: Option<Arc<Barrier>>,
        delete_observer: Mutex<Option<DeleteObserver>>,
    }

    struct ForcedCas {
        ledger: QuickUnlockLedgerStore,
        vault_ref_id: String,
        expected: QuickUnlockLedgerEntry,
        next: QuickUnlockLedgerEntry,
    }

    struct DeleteObserver {
        ledger: QuickUnlockLedgerStore,
        vault_ref_id: String,
        observed: Arc<Mutex<Option<QuickUnlockLedgerEntry>>>,
    }

    impl FakeRecordStore {
        fn new() -> Self {
            Self {
                records: Mutex::new(Vec::new()),
                calls: Mutex::new(Vec::new()),
                seal_error: Mutex::new(None),
                unseal_error: Mutex::new(None),
                delete_error: Mutex::new(None),
                after_seal_cas: Mutex::new(None),
                after_unseal_cas: Mutex::new(None),
                seal_barrier: None,
                delete_observer: Mutex::new(None),
            }
        }

        fn with_barrier(barrier: Arc<Barrier>) -> Self {
            Self {
                seal_barrier: Some(barrier),
                ..Self::new()
            }
        }

        fn insert(&self, key: PlatformRecordKey, bytes: &[u8]) {
            self.records.lock().unwrap().push((key, bytes.to_vec()));
        }

        fn record(&self, generation: u64) -> Option<Vec<u8>> {
            self.records
                .lock()
                .unwrap()
                .iter()
                .find(|(key, _)| key.record_generation == generation)
                .map(|(_, bytes)| bytes.clone())
        }
    }

    impl QuickUnlockRecordStore for FakeRecordStore {
        fn seal(
            &self,
            key: &PlatformRecordKey,
            opaque_envelope: &[u8],
        ) -> Result<(), PlatformError> {
            self.calls
                .lock()
                .unwrap()
                .push(RecordCall::Seal(key.clone(), opaque_envelope.to_vec()));
            if let Some(error) = self.seal_error.lock().unwrap().clone() {
                return Err(error);
            }
            self.records
                .lock()
                .unwrap()
                .push((key.clone(), opaque_envelope.to_vec()));
            if let Some(forced) = self.after_seal_cas.lock().unwrap().take() {
                forced
                    .ledger
                    .compare_and_swap(&forced.vault_ref_id, Some(&forced.expected), forced.next)
                    .unwrap();
            }
            if let Some(barrier) = &self.seal_barrier {
                barrier.wait();
            }
            Ok(())
        }

        fn unseal(&self, key: &PlatformRecordKey) -> Result<Vec<u8>, PlatformError> {
            self.calls
                .lock()
                .unwrap()
                .push(RecordCall::Unseal(key.clone()));
            if let Some(error) = self.unseal_error.lock().unwrap().clone() {
                return Err(error);
            }
            let envelope = self
                .records
                .lock()
                .unwrap()
                .iter()
                .find(|(stored, _)| stored == key)
                .map(|(_, bytes)| bytes.clone())
                .ok_or_else(|| PlatformError::new("fake", 404))?;
            if let Some(forced) = self.after_unseal_cas.lock().unwrap().take() {
                forced
                    .ledger
                    .compare_and_swap(&forced.vault_ref_id, Some(&forced.expected), forced.next)
                    .unwrap();
            }
            Ok(envelope)
        }

        fn delete(&self, key: &PlatformRecordKey) -> Result<(), PlatformError> {
            self.calls
                .lock()
                .unwrap()
                .push(RecordCall::Delete(key.clone()));
            if let Some(observer) = self.delete_observer.lock().unwrap().as_ref() {
                *observer.observed.lock().unwrap() =
                    observer.ledger.get(&observer.vault_ref_id).unwrap();
            }
            if let Some(error) = self.delete_error.lock().unwrap().clone() {
                return Err(error);
            }
            self.records
                .lock()
                .unwrap()
                .retain(|(stored, _)| stored != key);
            Ok(())
        }
    }

    struct FakeClassifier;

    impl PlatformErrorClassifier for FakeClassifier {
        fn classify(
            &self,
            _operation: QuickUnlockOperation,
            error: &PlatformError,
        ) -> QuickUnlockError {
            match error.code {
                1 => QuickUnlockError::PermanentlyInvalidated,
                2 => QuickUnlockError::TemporarilyUnavailable,
                3 => QuickUnlockError::UserCancelled,
                4 => QuickUnlockError::LockedOut,
                5 => QuickUnlockError::NotEnrolled,
                code => panic!("unmapped fake platform error {code}"),
            }
        }
    }

    fn coordinator(
        ledger: QuickUnlockLedgerStore,
        records: Arc<FakeRecordStore>,
    ) -> QuickUnlockCoordinator {
        QuickUnlockCoordinator::new(ledger, records, Arc::new(FakeClassifier))
    }

    fn key(scope: &str, vault: &str, generation: u64) -> PlatformRecordKey {
        PlatformRecordKey {
            identifier_scope: scope.to_owned(),
            vault_ref_id: vault.to_owned(),
            record_generation: generation,
        }
    }

    #[test]
    fn enable_requires_a_password_unlocked_session_and_refuses_not_enrolled() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let records = Arc::new(FakeRecordStore::new());
        let coordinator = coordinator(ledger.clone(), Arc::clone(&records));

        let locked = coordinator
            .enable("scope", "vault", SessionUnlockKind::Locked, b"opaque")
            .unwrap();
        assert_eq!(locked, EnableOutcome::PasswordUnlockRequired);
        assert_eq!(ledger.get("vault").unwrap(), None);
        assert!(records.calls.lock().unwrap().is_empty());

        *records.seal_error.lock().unwrap() = Some(PlatformError::new("fake", 5));
        let not_enrolled = coordinator
            .enable(
                "scope",
                "vault",
                SessionUnlockKind::PasswordUnlocked,
                b"opaque",
            )
            .unwrap();
        assert_eq!(
            not_enrolled,
            EnableOutcome::Refused(QuickUnlockError::NotEnrolled)
        );
        assert_eq!(ledger.get("vault").unwrap(), None);
    }

    #[test]
    fn missing_rows_start_disabled_at_generation_zero_and_enable_at_one() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let records = Arc::new(FakeRecordStore::new());
        let coordinator = coordinator(ledger.clone(), Arc::clone(&records));

        assert_eq!(
            coordinator
                .enable(
                    "extension-scope",
                    "vault-1",
                    SessionUnlockKind::PasswordUnlocked,
                    b"opaque-envelope",
                )
                .unwrap(),
            EnableOutcome::Enabled
        );

        assert_eq!(
            ledger.get("vault-1").unwrap(),
            Some(entry(QuickUnlockState::Enrolled, 1))
        );
        assert_eq!(records.record(1), Some(b"opaque-envelope".to_vec()));
        assert_eq!(
            records.calls.lock().unwrap()[0],
            RecordCall::Seal(
                key("extension-scope", "vault-1", 1),
                b"opaque-envelope".to_vec()
            )
        );
    }

    #[test]
    fn failed_seal_and_generation_overflow_leave_the_ledger_unchanged() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Disabled, 9))
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        *records.seal_error.lock().unwrap() = Some(PlatformError::new("fake", 2));
        let coordinator = coordinator(ledger.clone(), Arc::clone(&records));

        assert_eq!(
            coordinator
                .enable(
                    "scope",
                    "vault",
                    SessionUnlockKind::PasswordUnlocked,
                    b"new",
                )
                .unwrap(),
            EnableOutcome::Failed(QuickUnlockError::TemporarilyUnavailable)
        );
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Disabled, 9))
        );

        let overflow = entry(QuickUnlockState::Disabled, u64::MAX);
        ledger
            .compare_and_swap("overflow", None, overflow.clone())
            .unwrap();
        assert!(matches!(
            coordinator.enable(
                "scope",
                "overflow",
                SessionUnlockKind::PasswordUnlocked,
                b"never-sealed",
            ),
            Err(CoordinatorError::GenerationOverflow)
        ));
        assert_eq!(ledger.get("overflow").unwrap(), Some(overflow));
    }

    #[test]
    fn seal_then_cas_conflict_leaves_an_orphan_without_overwriting_the_old_generation() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let old = entry(QuickUnlockState::Disabled, 7);
        ledger.compare_and_swap("vault", None, old.clone()).unwrap();
        let records = Arc::new(FakeRecordStore::new());
        records.insert(key("scope", "vault", 7), b"old-envelope");
        *records.after_seal_cas.lock().unwrap() = Some(ForcedCas {
            ledger: ledger.clone(),
            vault_ref_id: "vault".to_owned(),
            expected: old.clone(),
            next: entry(QuickUnlockState::Disabled, 8),
        });
        let coordinator = coordinator(ledger.clone(), Arc::clone(&records));

        let error = coordinator
            .enable(
                "scope",
                "vault",
                SessionUnlockKind::PasswordUnlocked,
                b"orphan-envelope",
            )
            .unwrap_err();

        assert!(matches!(
            error,
            CoordinatorError::Ledger(LedgerStoreError::Conflict { .. })
        ));
        assert_eq!(records.record(7), Some(b"old-envelope".to_vec()));
        assert_eq!(records.record(8), Some(b"orphan-envelope".to_vec()));
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Disabled, 8))
        );
    }

    #[test]
    fn disable_commits_before_best_effort_delete_and_never_rolls_back_cleanup_failure() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Enrolled, 7))
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        records.insert(key("scope", "vault", 7), b"old");
        let observed = Arc::new(Mutex::new(None));
        *records.delete_observer.lock().unwrap() = Some(DeleteObserver {
            ledger: ledger.clone(),
            vault_ref_id: "vault".to_owned(),
            observed: Arc::clone(&observed),
        });
        let cleanup_error = PlatformError::new("fake-delete", 99);
        *records.delete_error.lock().unwrap() = Some(cleanup_error.clone());
        let coordinator = coordinator(ledger.clone(), Arc::clone(&records));

        let outcome = coordinator.disable("scope", "vault").unwrap();

        assert_eq!(
            outcome,
            DisableOutcome {
                cleanup: CleanupStatus::Pending(cleanup_error)
            }
        );
        let disabled = entry(QuickUnlockState::Disabled, 8);
        assert_eq!(ledger.get("vault").unwrap(), Some(disabled.clone()));
        assert_eq!(*observed.lock().unwrap(), Some(disabled));
        assert_eq!(records.record(7), Some(b"old".to_vec()));
    }

    #[test]
    fn unlock_transitions_only_permanent_and_kdf_failures() {
        for (platform_code, expected) in [
            (2, QuickUnlockError::TemporarilyUnavailable),
            (3, QuickUnlockError::UserCancelled),
            (4, QuickUnlockError::LockedOut),
        ] {
            let ledger = QuickUnlockLedgerStore::in_memory();
            let enrolled = entry(QuickUnlockState::Enrolled, 3);
            ledger
                .compare_and_swap("vault", None, enrolled.clone())
                .unwrap();
            let records = Arc::new(FakeRecordStore::new());
            *records.unseal_error.lock().unwrap() = Some(PlatformError::new("fake", platform_code));

            assert_eq!(
                coordinator(ledger.clone(), records)
                    .unlock("scope", "vault", |_| EnvelopeInspection::Valid)
                    .unwrap(),
                UnlockOutcome::Failed(expected)
            );
            assert_eq!(ledger.get("vault").unwrap(), Some(enrolled));
        }

        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Enrolled, 3))
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        *records.unseal_error.lock().unwrap() = Some(PlatformError::new("fake", 1));
        assert_eq!(
            coordinator(ledger.clone(), records)
                .unlock("scope", "vault", |_| EnvelopeInspection::Valid)
                .unwrap(),
            UnlockOutcome::NeedsReenroll(NeedsReenrollReason::BiometryChanged)
        );

        ledger
            .compare_and_swap(
                "vault",
                ledger.get("vault").unwrap().as_ref(),
                entry(QuickUnlockState::Enrolled, 4),
            )
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        records.insert(key("scope", "vault", 4), b"opaque");
        assert_eq!(
            coordinator(ledger.clone(), records)
                .unlock("scope", "vault", |_| {
                    EnvelopeInspection::KdfGenerationMismatch
                })
                .unwrap(),
            UnlockOutcome::NeedsReenroll(NeedsReenrollReason::KdfRotated)
        );
    }

    #[test]
    fn needs_reenroll_reseals_after_the_next_full_credential_unlock() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap(
                "vault",
                None,
                entry(
                    QuickUnlockState::NeedsReenroll {
                        reason: NeedsReenrollReason::KdfRotated,
                    },
                    10,
                ),
            )
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());

        assert_eq!(
            coordinator(ledger.clone(), Arc::clone(&records))
                .full_credential_unlocked("scope", "vault", b"replacement")
                .unwrap(),
            FullCredentialOutcome::Resealed
        );
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Enrolled, 11))
        );
        assert_eq!(records.record(11), Some(b"replacement".to_vec()));
    }

    #[test]
    fn unlock_never_returns_an_envelope_after_a_concurrent_ledger_revocation() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let enrolled = entry(QuickUnlockState::Enrolled, 7);
        ledger
            .compare_and_swap("vault", None, enrolled.clone())
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        records.insert(key("scope", "vault", 7), b"stale-envelope");
        *records.after_unseal_cas.lock().unwrap() = Some(ForcedCas {
            ledger: ledger.clone(),
            vault_ref_id: "vault".to_owned(),
            expected: enrolled,
            next: entry(QuickUnlockState::Disabled, 8),
        });

        let outcome = coordinator(ledger.clone(), records)
            .unlock("scope", "vault", |_| EnvelopeInspection::Valid);

        assert!(matches!(
            outcome,
            Err(CoordinatorError::Ledger(LedgerStoreError::Conflict { .. }))
        ));
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Disabled, 8))
        );
    }

    #[test]
    fn concurrent_enables_surface_one_exact_row_cas_conflict_without_retry() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let barrier = Arc::new(Barrier::new(2));
        let records = Arc::new(FakeRecordStore::with_barrier(barrier));
        let coordinator = Arc::new(coordinator(ledger.clone(), records));

        let spawn = |payload: &'static [u8]| {
            let coordinator = Arc::clone(&coordinator);
            thread::spawn(move || {
                coordinator.enable(
                    "scope",
                    "vault",
                    SessionUnlockKind::PasswordUnlocked,
                    payload,
                )
            })
        };
        let first = spawn(b"first");
        let second = spawn(b"second");
        let results = [first.join().unwrap(), second.join().unwrap()];

        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(EnableOutcome::Enabled)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(CoordinatorError::Ledger(LedgerStoreError::Conflict { .. }))
                ))
                .count(),
            1
        );
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Enrolled, 1))
        );
    }
}
