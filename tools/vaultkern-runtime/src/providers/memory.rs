use super::provider::{
    Provider, ProviderCommit, ProviderConflictCopy, ProviderError, ProviderRevision,
    ProviderSnapshot,
};
use std::sync::Mutex;

struct InMemoryProviderState {
    bytes: Vec<u8>,
    revision: u64,
    conflict_copies: Vec<(String, Vec<u8>)>,
}

pub struct InMemoryProvider {
    state: Mutex<InMemoryProviderState>,
}

impl InMemoryProvider {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            state: Mutex::new(InMemoryProviderState {
                bytes,
                revision: 1,
                conflict_copies: Vec::new(),
            }),
        }
    }

    pub fn replace_externally(&self, bytes: Vec<u8>) {
        let mut state = self.state.lock().expect("in-memory Provider lock");
        state.bytes = bytes;
        state.revision = state.revision.saturating_add(1);
    }

    pub fn conflict_copy_bytes(&self, identity: &str) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("in-memory Provider lock")
            .conflict_copies
            .iter()
            .find(|(candidate, _)| candidate == identity)
            .map(|(_, bytes)| bytes.clone())
    }

    fn revision(revision: u64) -> ProviderRevision {
        ProviderRevision::from_opaque_bytes(format!("memory:v1:{revision}").into_bytes())
    }
}

impl Provider for InMemoryProvider {
    fn read(&mut self) -> Result<ProviderSnapshot, ProviderError> {
        let state = self.state.lock().expect("in-memory Provider lock");
        Ok(ProviderSnapshot {
            bytes: state.bytes.clone(),
            revision: Self::revision(state.revision),
        })
    }

    fn publish(
        &mut self,
        expected: &ProviderRevision,
        bytes: &[u8],
    ) -> Result<ProviderCommit, ProviderError> {
        let mut state = self.state.lock().expect("in-memory Provider lock");
        if expected != &Self::revision(state.revision) {
            return Err(ProviderError::StaleRevision {
                message: "the in-memory snapshot advanced".into(),
            });
        }
        state.bytes = bytes.to_vec();
        state.revision = state.revision.saturating_add(1);
        Ok(ProviderCommit {
            revision: Self::revision(state.revision),
            warnings: Vec::new(),
        })
    }

    fn preserve_conflict_copy(
        &mut self,
        bytes: &[u8],
    ) -> Result<ProviderConflictCopy, ProviderError> {
        let mut state = self.state.lock().expect("in-memory Provider lock");
        let identity = format!("memory-conflict-{}", state.conflict_copies.len() + 1);
        state
            .conflict_copies
            .push((identity.clone(), bytes.to_vec()));
        Ok(ProviderConflictCopy {
            display_name: identity.clone(),
            identity,
            warnings: Vec::new(),
        })
    }
}
