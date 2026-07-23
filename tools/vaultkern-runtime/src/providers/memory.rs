use super::provider::{
    Provider, ProviderCommit, ProviderError, ProviderRevision, ProviderSnapshot,
};
use std::sync::Mutex;

struct InMemoryProviderState {
    bytes: Vec<u8>,
    revision: u64,
}

pub struct InMemoryProvider {
    state: Mutex<InMemoryProviderState>,
}

impl InMemoryProvider {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            state: Mutex::new(InMemoryProviderState { bytes, revision: 1 }),
        }
    }

    pub fn replace_externally(&self, bytes: Vec<u8>) {
        let mut state = self.state.lock().expect("in-memory Provider lock");
        state.bytes = bytes;
        state.revision = state.revision.saturating_add(1);
    }

    fn revision(revision: u64) -> ProviderRevision {
        ProviderRevision::from_opaque_bytes(format!("memory:v1:{revision}").into_bytes())
    }
}

impl Provider for InMemoryProvider {
    fn read(&self) -> Result<ProviderSnapshot, ProviderError> {
        let state = self.state.lock().expect("in-memory Provider lock");
        Ok(ProviderSnapshot {
            bytes: state.bytes.clone(),
            revision: Self::revision(state.revision),
        })
    }

    fn publish(
        &self,
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
}
