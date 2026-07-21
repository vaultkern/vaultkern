use std::sync::{Mutex, MutexGuard};

pub(crate) type PluginOperationId = [u8; 16];

#[derive(Clone, Copy)]
struct ActiveOperation {
    id: PluginOperationId,
    cancelled: bool,
}

#[derive(Default)]
pub(crate) struct PluginOperationState {
    active: Mutex<Option<ActiveOperation>>,
}

impl PluginOperationState {
    pub(crate) fn begin(&self, id: PluginOperationId) -> bool {
        let mut active = self.active();
        if active.is_some() {
            return false;
        }
        *active = Some(ActiveOperation {
            id,
            cancelled: false,
        });
        true
    }

    pub(crate) fn cancel(&self, id: PluginOperationId) -> bool {
        let mut active = self.active();
        let Some(operation) = active.as_mut().filter(|operation| operation.id == id) else {
            return false;
        };
        operation.cancelled = true;
        true
    }

    pub(crate) fn is_cancelled(&self, id: PluginOperationId) -> bool {
        self.active()
            .as_ref()
            .is_some_and(|operation| operation.id == id && operation.cancelled)
    }

    pub(crate) fn end(&self, id: PluginOperationId) {
        let mut active = self.active();
        if active.as_ref().is_some_and(|operation| operation.id == id) {
            *active = None;
        }
    }

    fn active(&self) -> MutexGuard<'_, Option<ActiveOperation>> {
        self.active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::PluginOperationState;

    #[test]
    fn cancellation_only_marks_the_matching_active_plugin_transaction() {
        let operations = PluginOperationState::default();
        let first = [1; 16];
        let other = [2; 16];

        assert!(operations.begin(first));
        assert!(!operations.begin(other));
        assert!(!operations.cancel(other));
        assert!(!operations.is_cancelled(first));
        assert!(operations.cancel(first));
        assert!(operations.is_cancelled(first));

        operations.end(other);
        assert!(operations.is_cancelled(first));
        operations.end(first);
        assert!(!operations.is_cancelled(first));
        assert!(operations.begin(other));
    }
}
