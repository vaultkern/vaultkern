use crate::quick_unlock_ledger::{LedgerStoreError, QuickUnlockLedgerStore};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};
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
        (_, QuickUnlockOperation::Disable, QuickUnlockOperationResult::Success) => {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealOutcome {
    Created,
    AlreadyExists,
}

pub(crate) trait QuickUnlockRecordStore: Send + Sync {
    /// Returns generations present in physical storage, without inferring lifecycle state.
    fn record_generations(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
    ) -> Result<Vec<u64>, PlatformError>;
    /// Atomically creates a new key; an existing key must never be replaced.
    fn seal(
        &self,
        key: &PlatformRecordKey,
        opaque_envelope: &[u8],
    ) -> Result<SealOutcome, PlatformError>;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnableOutcome {
    Enabled { cleanup: CleanupStatus },
    PasswordUnlockRequired,
    Refused(QuickUnlockError),
    Failed(QuickUnlockError),
    NoChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FullCredentialOutcome {
    Resealed { cleanup: CleanupStatus },
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
pub(crate) enum CleanupInspection {
    Complete,
    Pending,
    Unavailable(PlatformError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DisableOutcome {
    pub(crate) cleanup: CleanupStatus,
}

#[derive(Debug)]
pub(crate) enum CoordinatorError {
    Ledger(LedgerStoreError),
    GenerationOverflow,
    InvalidIdentifierScope,
    InvalidVaultRefId,
    RecordConflict,
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ledger(error) => write!(formatter, "{error}"),
            Self::GenerationOverflow => {
                formatter.write_str("quick unlock record generation overflowed")
            }
            Self::InvalidIdentifierScope => {
                formatter.write_str("quick unlock identifier_scope must not be empty")
            }
            Self::InvalidVaultRefId => {
                formatter.write_str("quick unlock vault_ref_id must not be empty")
            }
            Self::RecordConflict => {
                formatter.write_str("quick unlock platform record already exists")
            }
        }
    }
}

impl std::error::Error for CoordinatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ledger(error) => Some(error),
            Self::GenerationOverflow
            | Self::InvalidIdentifierScope
            | Self::InvalidVaultRefId
            | Self::RecordConflict => None,
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
    transition_lock: Mutex<()>,
}

enum NextGenerationError {
    Platform(PlatformError),
    Overflow,
}

enum CleanupRange {
    Before(u64),
    Through(u64),
}

impl CleanupRange {
    fn contains(&self, generation: u64) -> bool {
        match self {
            Self::Before(boundary) => generation < *boundary,
            Self::Through(boundary) => generation <= *boundary,
        }
    }
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
            transition_lock: Mutex::new(()),
        }
    }

    pub(crate) fn enable(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
        session: SessionUnlockKind,
        opaque_envelope: &[u8],
    ) -> Result<EnableOutcome, CoordinatorError> {
        validate_record_identity(identifier_scope, vault_ref_id)?;
        let _transition_guard = self.lock_transitions();
        if session != SessionUnlockKind::PasswordUnlocked {
            return Ok(EnableOutcome::PasswordUnlockRequired);
        }
        let (stored, current) = self.current_entry(vault_ref_id)?;
        let mut reduction = reduce(
            &current,
            QuickUnlockOperation::Enable,
            QuickUnlockOperationResult::Success,
        )?;
        if reduction.disposition != ReductionDisposition::SealThenCommit {
            return Ok(EnableOutcome::NoChange);
        }
        reduction.next.generation = match self.next_available_generation(
            identifier_scope,
            vault_ref_id,
            current.generation,
        ) {
            Ok(generation) => generation,
            Err(NextGenerationError::Overflow) => {
                return Err(CoordinatorError::GenerationOverflow);
            }
            Err(NextGenerationError::Platform(error)) => {
                let category = self
                    .classifier
                    .classify(QuickUnlockOperation::Enable, &error);
                return Ok(if category == QuickUnlockError::NotEnrolled {
                    EnableOutcome::Refused(category)
                } else {
                    EnableOutcome::Failed(category)
                });
            }
        };
        let record_key =
            platform_record_key(identifier_scope, vault_ref_id, reduction.next.generation);
        match self.records.seal(&record_key, opaque_envelope) {
            Ok(SealOutcome::Created) => {}
            Ok(SealOutcome::AlreadyExists) => return Err(CoordinatorError::RecordConflict),
            Err(error) => {
                let category = self
                    .classifier
                    .classify(QuickUnlockOperation::Enable, &error);
                return Ok(if category == QuickUnlockError::NotEnrolled {
                    EnableOutcome::Refused(category)
                } else {
                    EnableOutcome::Failed(category)
                });
            }
        }
        let active_generation = reduction.next.generation;
        self.ledger
            .compare_and_swap(vault_ref_id, stored.as_ref(), reduction.next)?;
        let cleanup = self.cleanup_records(
            identifier_scope,
            vault_ref_id,
            CleanupRange::Before(active_generation),
        );
        Ok(EnableOutcome::Enabled { cleanup })
    }

    pub(crate) fn full_credential_unlocked(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
        opaque_envelope: &[u8],
    ) -> Result<FullCredentialOutcome, CoordinatorError> {
        validate_record_identity(identifier_scope, vault_ref_id)?;
        let _transition_guard = self.lock_transitions();
        let (stored, current) = self.current_entry(vault_ref_id)?;
        let mut reduction = reduce(
            &current,
            QuickUnlockOperation::FullCredentialUnlock,
            QuickUnlockOperationResult::Success,
        )?;
        if reduction.disposition != ReductionDisposition::SealThenCommit {
            return Ok(FullCredentialOutcome::NoChange);
        }
        reduction.next.generation = match self.next_available_generation(
            identifier_scope,
            vault_ref_id,
            current.generation,
        ) {
            Ok(generation) => generation,
            Err(NextGenerationError::Overflow) => {
                return Err(CoordinatorError::GenerationOverflow);
            }
            Err(NextGenerationError::Platform(error)) => {
                return Ok(FullCredentialOutcome::Failed(
                    self.classifier
                        .classify(QuickUnlockOperation::FullCredentialUnlock, &error),
                ));
            }
        };
        let record_key =
            platform_record_key(identifier_scope, vault_ref_id, reduction.next.generation);
        match self.records.seal(&record_key, opaque_envelope) {
            Ok(SealOutcome::Created) => {}
            Ok(SealOutcome::AlreadyExists) => return Err(CoordinatorError::RecordConflict),
            Err(error) => {
                return Ok(FullCredentialOutcome::Failed(
                    self.classifier
                        .classify(QuickUnlockOperation::FullCredentialUnlock, &error),
                ));
            }
        }
        let active_generation = reduction.next.generation;
        self.ledger
            .compare_and_swap(vault_ref_id, stored.as_ref(), reduction.next)?;
        let cleanup = self.cleanup_records(
            identifier_scope,
            vault_ref_id,
            CleanupRange::Before(active_generation),
        );
        Ok(FullCredentialOutcome::Resealed { cleanup })
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
        validate_record_identity(identifier_scope, vault_ref_id)?;
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
                self.ledger.assert_current(vault_ref_id, &current)?;
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
        validate_record_identity(identifier_scope, vault_ref_id)?;
        let _transition_guard = self.lock_transitions();
        let (stored, current) = self.current_entry(vault_ref_id)?;
        let reduction = reduce(
            &current,
            QuickUnlockOperation::Disable,
            QuickUnlockOperationResult::Success,
        )?;
        let disabled_generation = reduction.next.generation;
        self.ledger
            .compare_and_swap(vault_ref_id, stored.as_ref(), reduction.next)?;
        let cleanup = self.cleanup_records(
            identifier_scope,
            vault_ref_id,
            CleanupRange::Through(disabled_generation),
        );
        Ok(DisableOutcome { cleanup })
    }

    pub(crate) fn inspect_cleanup(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
    ) -> Result<CleanupInspection, CoordinatorError> {
        validate_record_identity(identifier_scope, vault_ref_id)?;
        let _transition_guard = self.lock_transitions();
        let (stored, current) = self.current_entry(vault_ref_id)?;
        let generations = match self
            .records
            .record_generations(identifier_scope, vault_ref_id)
        {
            Ok(generations) => generations,
            Err(error) => {
                self.ledger.assert_snapshot(vault_ref_id, stored.as_ref())?;
                return Ok(CleanupInspection::Unavailable(error));
            }
        };
        let cleanup_range = cleanup_range(&current);
        let pending = generations
            .into_iter()
            .any(|generation| cleanup_range.contains(generation));
        let inspection = if pending {
            CleanupInspection::Pending
        } else {
            CleanupInspection::Complete
        };
        self.ledger.assert_snapshot(vault_ref_id, stored.as_ref())?;
        Ok(inspection)
    }

    pub(crate) fn recover_pending_cleanup(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
    ) -> Result<CleanupStatus, CoordinatorError> {
        validate_record_identity(identifier_scope, vault_ref_id)?;
        let _transition_guard = self.lock_transitions();
        let (stored, current) = self.current_entry(vault_ref_id)?;
        let cleanup = self.cleanup_records(identifier_scope, vault_ref_id, cleanup_range(&current));
        self.ledger.assert_snapshot(vault_ref_id, stored.as_ref())?;
        Ok(cleanup)
    }

    fn current_entry(
        &self,
        vault_ref_id: &str,
    ) -> Result<(Option<QuickUnlockLedgerEntry>, QuickUnlockLedgerEntry), CoordinatorError> {
        let stored = self.ledger.get(vault_ref_id)?;
        let current = stored.clone().unwrap_or_else(initial_entry);
        Ok((stored, current))
    }

    fn lock_transitions(&self) -> std::sync::MutexGuard<'_, ()> {
        self.transition_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn next_available_generation(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
        ledger_generation: u64,
    ) -> Result<u64, NextGenerationError> {
        let highest = self
            .records
            .record_generations(identifier_scope, vault_ref_id)
            .map_err(NextGenerationError::Platform)?
            .into_iter()
            .fold(ledger_generation, u64::max);
        highest.checked_add(1).ok_or(NextGenerationError::Overflow)
    }

    fn cleanup_records(
        &self,
        identifier_scope: &str,
        vault_ref_id: &str,
        cleanup_range: CleanupRange,
    ) -> CleanupStatus {
        let generations = match self
            .records
            .record_generations(identifier_scope, vault_ref_id)
        {
            Ok(generations) => generations,
            Err(error) => return CleanupStatus::Pending(error),
        };
        let mut first_error = None;
        for generation in generations.into_iter().collect::<BTreeSet<_>>() {
            if !cleanup_range.contains(generation) {
                continue;
            }
            let key = platform_record_key(identifier_scope, vault_ref_id, generation);
            if let Err(error) = self.records.delete(&key) {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => CleanupStatus::Pending(error),
            None => CleanupStatus::Complete,
        }
    }
}

fn validate_identifier_scope(identifier_scope: &str) -> Result<(), CoordinatorError> {
    if identifier_scope.is_empty() {
        Err(CoordinatorError::InvalidIdentifierScope)
    } else {
        Ok(())
    }
}

fn validate_record_identity(
    identifier_scope: &str,
    vault_ref_id: &str,
) -> Result<(), CoordinatorError> {
    validate_identifier_scope(identifier_scope)?;
    if vault_ref_id.is_empty() {
        Err(CoordinatorError::InvalidVaultRefId)
    } else {
        Ok(())
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

fn cleanup_range(entry: &QuickUnlockLedgerEntry) -> CleanupRange {
    match entry.state {
        QuickUnlockState::Disabled => CleanupRange::Through(entry.generation),
        QuickUnlockState::Enrolled | QuickUnlockState::NeedsReenroll { .. } => {
            CleanupRange::Before(entry.generation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CleanupInspection, CleanupStatus, CoordinatorError, DisableOutcome, EnableOutcome,
        EnvelopeInspection, FullCredentialOutcome, PlatformError, PlatformErrorClassifier,
        QuickUnlockCoordinator, QuickUnlockError, QuickUnlockOperation, QuickUnlockOperationResult,
        QuickUnlockRecordStore, ReduceError, ReductionDisposition, SealOutcome, SessionUnlockKind,
        UnlockOutcome, reduce,
    };
    use crate::providers::durable_file::{DurableFaultInjector, DurableFaultPoint};
    use crate::quick_unlock_ledger::{LedgerStoreError, QuickUnlockLedgerStore};
    use std::sync::{Arc, Barrier, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;
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
                        (_, QuickUnlockOperation::Disable, QuickUnlockOperationResult::Success) => {
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
                        (_, QuickUnlockOperation::Disable, QuickUnlockOperationResult::Success) => {
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
        generation_error: Mutex<Option<PlatformError>>,
        after_seal_cas: Mutex<Option<ForcedCas>>,
        after_unseal_cas: Mutex<Option<ForcedCas>>,
        seal_gate: Option<SealGate>,
        generation_gate: Option<GenerationGate>,
        first_generation_pause: Option<GenerationPause>,
        generation_calls: Mutex<Vec<(String, String)>>,
        delete_observer: Mutex<Option<DeleteObserver>>,
    }

    struct SealGate {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    struct GenerationGate {
        barrier: Arc<Barrier>,
        entered: Mutex<u8>,
    }

    struct GenerationPause {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        pending: Mutex<bool>,
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
                generation_error: Mutex::new(None),
                after_seal_cas: Mutex::new(None),
                after_unseal_cas: Mutex::new(None),
                seal_gate: None,
                generation_gate: None,
                first_generation_pause: None,
                generation_calls: Mutex::new(Vec::new()),
                delete_observer: Mutex::new(None),
            }
        }

        fn with_seal_gate(entered: mpsc::Sender<()>, release: mpsc::Receiver<()>) -> Self {
            Self {
                seal_gate: Some(SealGate {
                    entered,
                    release: Mutex::new(release),
                }),
                ..Self::new()
            }
        }

        fn with_generation_barrier(barrier: Arc<Barrier>) -> Self {
            Self {
                generation_gate: Some(GenerationGate {
                    barrier,
                    entered: Mutex::new(0),
                }),
                ..Self::new()
            }
        }

        fn with_first_generation_pause(
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
        ) -> Self {
            Self {
                first_generation_pause: Some(GenerationPause {
                    entered,
                    release: Mutex::new(release),
                    pending: Mutex::new(true),
                }),
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
        fn record_generations(
            &self,
            identifier_scope: &str,
            vault_ref_id: &str,
        ) -> Result<Vec<u64>, PlatformError> {
            self.generation_calls
                .lock()
                .unwrap()
                .push((identifier_scope.to_owned(), vault_ref_id.to_owned()));
            if let Some(pause) = &self.first_generation_pause {
                let should_pause = {
                    let mut pending = pause.pending.lock().unwrap();
                    let should_pause = *pending;
                    *pending = false;
                    should_pause
                };
                if should_pause {
                    pause.entered.send(()).unwrap();
                    pause.release.lock().unwrap().recv().unwrap();
                }
            }
            if let Some(error) = self.generation_error.lock().unwrap().clone() {
                return Err(error);
            }
            let generations = self
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| {
                    key.identifier_scope == identifier_scope && key.vault_ref_id == vault_ref_id
                })
                .map(|(key, _)| key.record_generation)
                .collect();
            if let Some(gate) = &self.generation_gate {
                let should_wait = {
                    let mut entered = gate.entered.lock().unwrap();
                    let should_wait = *entered < 2;
                    *entered += 1;
                    should_wait
                };
                if should_wait {
                    gate.barrier.wait();
                }
            }
            Ok(generations)
        }

        fn seal(
            &self,
            key: &PlatformRecordKey,
            opaque_envelope: &[u8],
        ) -> Result<SealOutcome, PlatformError> {
            self.calls
                .lock()
                .unwrap()
                .push(RecordCall::Seal(key.clone(), opaque_envelope.to_vec()));
            if let Some(error) = self.seal_error.lock().unwrap().clone() {
                return Err(error);
            }
            {
                let mut records = self.records.lock().unwrap();
                if records.iter().any(|(stored, _)| stored == key) {
                    return Ok(SealOutcome::AlreadyExists);
                }
                records.push((key.clone(), opaque_envelope.to_vec()));
            }
            if let Some(forced) = self.after_seal_cas.lock().unwrap().take() {
                forced
                    .ledger
                    .compare_and_swap(&forced.vault_ref_id, Some(&forced.expected), forced.next)
                    .unwrap();
            }
            if let Some(gate) = &self.seal_gate {
                gate.entered.send(()).unwrap();
                gate.release.lock().unwrap().recv().unwrap();
            }
            Ok(SealOutcome::Created)
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
    fn empty_identifier_scope_is_rejected_before_either_store_is_touched() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let enrolled = entry(QuickUnlockState::Enrolled, 7);
        ledger
            .compare_and_swap("vault", None, enrolled.clone())
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        let coordinator = coordinator(ledger.clone(), Arc::clone(&records));

        assert!(matches!(
            coordinator.disable("", "vault"),
            Err(CoordinatorError::InvalidIdentifierScope)
        ));
        assert_eq!(ledger.get("vault").unwrap(), Some(enrolled));
        assert!(records.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn empty_vault_ref_id_is_rejected_before_either_store_is_touched() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let records = Arc::new(FakeRecordStore::new());
        let coordinator = coordinator(ledger.clone(), Arc::clone(&records));

        assert!(matches!(
            coordinator.enable("scope", "", SessionUnlockKind::PasswordUnlocked, b"opaque"),
            Err(CoordinatorError::InvalidVaultRefId)
        ));
        assert!(matches!(
            coordinator.full_credential_unlocked("scope", "", b"opaque"),
            Err(CoordinatorError::InvalidVaultRefId)
        ));
        assert!(matches!(
            coordinator.unlock("scope", "", |_| EnvelopeInspection::Valid),
            Err(CoordinatorError::InvalidVaultRefId)
        ));
        assert!(matches!(
            coordinator.disable("scope", ""),
            Err(CoordinatorError::InvalidVaultRefId)
        ));
        assert!(matches!(
            coordinator.inspect_cleanup("scope", ""),
            Err(CoordinatorError::InvalidVaultRefId)
        ));
        assert!(matches!(
            coordinator.recover_pending_cleanup("scope", ""),
            Err(CoordinatorError::InvalidVaultRefId)
        ));

        assert!(records.calls.lock().unwrap().is_empty());
        assert!(records.generation_calls.lock().unwrap().is_empty());
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
            EnableOutcome::Enabled {
                cleanup: CleanupStatus::Complete
            }
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
    fn retry_after_a_crash_skips_and_cleans_the_orphaned_generation() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let disabled = entry(QuickUnlockState::Disabled, 7);
        ledger.compare_and_swap("vault", None, disabled).unwrap();
        let records = Arc::new(FakeRecordStore::new());
        records.insert(key("scope", "vault", 7), b"old-envelope");
        records.insert(key("scope", "vault", 8), b"crash-orphan");

        let outcome = coordinator(ledger.clone(), Arc::clone(&records))
            .enable(
                "scope",
                "vault",
                SessionUnlockKind::PasswordUnlocked,
                b"replacement",
            )
            .unwrap();

        assert_eq!(
            outcome,
            EnableOutcome::Enabled {
                cleanup: CleanupStatus::Complete
            }
        );
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Enrolled, 9))
        );
        assert_eq!(records.record(7), None);
        assert_eq!(records.record(8), None);
        assert_eq!(records.record(9), Some(b"replacement".to_vec()));
    }

    #[test]
    fn successful_enroll_exposes_incomplete_orphan_cleanup() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Disabled, 7))
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        records.insert(key("scope", "vault", 7), b"old-envelope");
        records.insert(key("scope", "vault", 8), b"crash-orphan");
        let cleanup_error = PlatformError::new("fake-delete", 99);
        *records.delete_error.lock().unwrap() = Some(cleanup_error.clone());

        let outcome = coordinator(ledger.clone(), records)
            .enable(
                "scope",
                "vault",
                SessionUnlockKind::PasswordUnlocked,
                b"replacement",
            )
            .unwrap();

        assert_eq!(
            outcome,
            EnableOutcome::Enabled {
                cleanup: CleanupStatus::Pending(cleanup_error)
            }
        );
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Enrolled, 9))
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
    fn disable_reports_complete_only_after_all_generations_are_deleted() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Enrolled, 3))
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        for generation in 1..=3 {
            records.insert(
                key("scope", "vault", generation),
                format!("generation-{generation}").as_bytes(),
            );
        }

        let outcome = coordinator(ledger.clone(), Arc::clone(&records))
            .disable("scope", "vault")
            .unwrap();

        assert_eq!(
            outcome,
            DisableOutcome {
                cleanup: CleanupStatus::Complete
            }
        );
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Disabled, 4))
        );
        for generation in 1..=3 {
            assert_eq!(records.record(generation), None);
        }
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
            FullCredentialOutcome::Resealed {
                cleanup: CleanupStatus::Complete
            }
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
    fn successful_unlock_does_not_publish_an_unchanged_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quick-unlock.json");
        let initial = QuickUnlockLedgerStore::persistent(path.clone(), Duration::from_secs(1));
        initial
            .compare_and_swap("vault", None, entry(QuickUnlockState::Enrolled, 7))
            .unwrap();
        let ledger = QuickUnlockLedgerStore::persistent_with_faults(
            path,
            Duration::from_secs(1),
            DurableFaultInjector::fail_once(DurableFaultPoint::BeforeTargetReplace),
        );
        let records = Arc::new(FakeRecordStore::new());
        records.insert(key("scope", "vault", 7), b"opaque-envelope");

        let outcome = coordinator(ledger.clone(), records)
            .unlock("scope", "vault", |_| EnvelopeInspection::Valid)
            .unwrap();

        assert_eq!(
            outcome,
            UnlockOutcome::Unlocked(b"opaque-envelope".to_vec())
        );
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Enrolled, 7))
        );
    }

    #[test]
    fn concurrent_enables_do_not_seal_two_envelopes_to_the_same_generation() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let records = Arc::new(FakeRecordStore::with_seal_gate(entered_tx, release_rx));
        let coordinator = Arc::new(coordinator(ledger.clone(), Arc::clone(&records)));

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
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let second_coordinator = Arc::clone(&coordinator);
        let second = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            second_coordinator.enable(
                "scope",
                "vault",
                SessionUnlockKind::PasswordUnlocked,
                b"second",
            )
        });
        ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let second_entered = entered_rx.recv_timeout(Duration::from_secs(1)).is_ok();
        release_tx.send(()).unwrap();
        if second_entered {
            release_tx.send(()).unwrap();
        }
        let results = [first.join().unwrap(), second.join().unwrap()];

        assert!(
            !second_entered,
            "both operations reached seal for generation 1"
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(EnableOutcome::Enabled { .. })))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(EnableOutcome::NoChange)))
                .count(),
            1
        );
        assert_eq!(
            records
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| matches!(call, RecordCall::Seal(_, _)))
                .count(),
            1
        );
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Enrolled, 1))
        );
    }

    #[test]
    fn independent_coordinators_cannot_overwrite_the_same_record_key() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        let records = Arc::new(FakeRecordStore::with_generation_barrier(Arc::new(
            Barrier::new(2),
        )));
        let first_coordinator = coordinator(ledger.clone(), Arc::clone(&records));
        let second_coordinator = coordinator(ledger.clone(), Arc::clone(&records));

        let first = thread::spawn(move || {
            first_coordinator.enable(
                "scope",
                "vault",
                SessionUnlockKind::PasswordUnlocked,
                b"first",
            )
        });
        let second = thread::spawn(move || {
            second_coordinator.enable(
                "scope",
                "vault",
                SessionUnlockKind::PasswordUnlocked,
                b"second",
            )
        });
        let results = [first.join().unwrap(), second.join().unwrap()];

        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(EnableOutcome::Enabled { .. })))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(CoordinatorError::RecordConflict)))
                .count(),
            1
        );
        assert_eq!(
            records
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|(stored, _)| stored == &key("scope", "vault", 1))
                .count(),
            1
        );
    }

    #[test]
    fn delayed_disable_cleanup_does_not_delete_a_newly_enrolled_generation() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Enrolled, 1))
            .unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let records = Arc::new(FakeRecordStore::with_first_generation_pause(
            entered_tx, release_rx,
        ));
        records.insert(key("scope", "vault", 1), b"old");

        let disabling = coordinator(ledger.clone(), Arc::clone(&records));
        let disable = thread::spawn(move || disabling.disable("scope", "vault"));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let enable = coordinator(ledger.clone(), Arc::clone(&records))
            .enable(
                "scope",
                "vault",
                SessionUnlockKind::PasswordUnlocked,
                b"new",
            )
            .unwrap();
        assert_eq!(
            enable,
            EnableOutcome::Enabled {
                cleanup: CleanupStatus::Complete
            }
        );
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Enrolled, 3))
        );

        release_tx.send(()).unwrap();
        disable.join().unwrap().unwrap();

        assert_eq!(records.record(3), Some(b"new".to_vec()));
    }

    #[test]
    fn interrupted_reseal_cleanup_can_be_recovered_from_persisted_state() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Enrolled, 9))
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        records.insert(key("scope", "vault", 7), b"old");
        records.insert(key("scope", "vault", 8), b"orphan");
        records.insert(key("scope", "vault", 9), b"current");

        let coordinator = coordinator(ledger, Arc::clone(&records));
        assert_eq!(
            coordinator.inspect_cleanup("scope", "vault").unwrap(),
            CleanupInspection::Pending
        );

        let cleanup = coordinator
            .recover_pending_cleanup("scope", "vault")
            .unwrap();

        assert_eq!(cleanup, CleanupStatus::Complete);
        assert_eq!(
            coordinator.inspect_cleanup("scope", "vault").unwrap(),
            CleanupInspection::Complete
        );
        assert_eq!(records.record(7), None);
        assert_eq!(records.record(8), None);
        assert_eq!(records.record(9), Some(b"current".to_vec()));
    }

    #[test]
    fn disabled_cleanup_recovery_preserves_future_generations() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Disabled, 8))
            .unwrap();
        let records = Arc::new(FakeRecordStore::new());
        records.insert(key("scope", "vault", 7), b"old");
        records.insert(key("scope", "vault", 8), b"disabled-orphan");
        records.insert(key("scope", "vault", 9), b"future");

        let cleanup = coordinator(ledger.clone(), Arc::clone(&records))
            .recover_pending_cleanup("scope", "vault")
            .unwrap();

        assert_eq!(cleanup, CleanupStatus::Complete);
        assert_eq!(records.record(7), None);
        assert_eq!(records.record(8), None);
        assert_eq!(records.record(9), Some(b"future".to_vec()));
        assert_eq!(
            coordinator(ledger, records)
                .inspect_cleanup("scope", "vault")
                .unwrap(),
            CleanupInspection::Complete
        );
    }

    #[test]
    fn cleanup_inspection_rejects_a_concurrently_changed_ledger_snapshot() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Enrolled, 1))
            .unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let records = Arc::new(FakeRecordStore::with_first_generation_pause(
            entered_tx, release_rx,
        ));
        records.insert(key("scope", "vault", 1), b"current");
        *records.delete_error.lock().unwrap() = Some(PlatformError::new("fake-delete", 99));

        let inspecting = coordinator(ledger.clone(), Arc::clone(&records));
        let inspection = thread::spawn(move || inspecting.inspect_cleanup("scope", "vault"));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        coordinator(ledger.clone(), Arc::clone(&records))
            .disable("scope", "vault")
            .unwrap();
        assert_eq!(
            ledger.get("vault").unwrap(),
            Some(entry(QuickUnlockState::Disabled, 2))
        );
        release_tx.send(()).unwrap();

        assert!(matches!(
            inspection.join().unwrap(),
            Err(CoordinatorError::Ledger(LedgerStoreError::Conflict { .. }))
        ));
    }

    #[test]
    fn unavailable_cleanup_inspection_rejects_a_changed_ledger_snapshot() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Enrolled, 1))
            .unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let records = Arc::new(FakeRecordStore::with_first_generation_pause(
            entered_tx, release_rx,
        ));
        *records.generation_error.lock().unwrap() = Some(PlatformError::new("fake-list", 99));

        let inspecting = coordinator(ledger.clone(), Arc::clone(&records));
        let inspection = thread::spawn(move || inspecting.inspect_cleanup("scope", "vault"));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        coordinator(ledger.clone(), Arc::clone(&records))
            .disable("scope", "vault")
            .unwrap();
        release_tx.send(()).unwrap();

        assert!(matches!(
            inspection.join().unwrap(),
            Err(CoordinatorError::Ledger(LedgerStoreError::Conflict { .. }))
        ));
    }

    #[test]
    fn cleanup_recovery_rejects_a_concurrently_changed_ledger_snapshot() {
        let ledger = QuickUnlockLedgerStore::in_memory();
        ledger
            .compare_and_swap("vault", None, entry(QuickUnlockState::Enrolled, 1))
            .unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let records = Arc::new(FakeRecordStore::with_first_generation_pause(
            entered_tx, release_rx,
        ));
        records.insert(key("scope", "vault", 1), b"current");
        *records.delete_error.lock().unwrap() = Some(PlatformError::new("fake-delete", 99));

        let recovering = coordinator(ledger.clone(), Arc::clone(&records));
        let recovery = thread::spawn(move || recovering.recover_pending_cleanup("scope", "vault"));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        coordinator(ledger.clone(), Arc::clone(&records))
            .disable("scope", "vault")
            .unwrap();
        release_tx.send(()).unwrap();

        assert!(matches!(
            recovery.join().unwrap(),
            Err(CoordinatorError::Ledger(LedgerStoreError::Conflict { .. }))
        ));
    }
}
