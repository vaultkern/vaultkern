use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use vaultkern_runtime::{
    PlatformPasskeyAssertionInput, PlatformPasskeyAssertionOutput, PlatformPasskeyCredential,
    PlatformPasskeyRegistrationInput, PlatformPasskeyRegistrationOutput,
    QuickUnlockReconciliationCredentials, Runtime, RuntimeProtocolDispatch, RuntimeProtocolSession,
};
use vaultkern_runtime_protocol::{ErrorDto, ProtocolEnvelope, RuntimeCommand, RuntimeResponse};

#[derive(Clone)]
pub struct RuntimeBridge {
    requests: Sender<RuntimeRequest>,
    reconciliation_notifier: Arc<Mutex<Option<SyncSender<SettingsReconciliationRequest>>>>,
    desktop_protocol_session: Arc<Mutex<RuntimeProtocolSession>>,
}

pub struct SettingsReconciliationRequest {
    pub quick_unlock_credentials: Option<QuickUnlockReconciliationCredentials>,
    pub quick_unlock_completion: Option<Sender<Result<(), String>>>,
}

struct RuntimeProtocolResponse {
    response: RuntimeResponse,
    quick_unlock_credentials: Option<QuickUnlockReconciliationCredentials>,
}

enum RuntimeRequest {
    #[cfg(test)]
    PanicAfterMutation {
        response: Sender<Result<(), String>>,
    },
    SetParentWindowHandle {
        parent_window: Option<usize>,
        response: Option<Sender<()>>,
    },
    SetIdleLockTimeout {
        timeout: Option<Duration>,
        response: Sender<()>,
    },
    Protocol {
        command: RuntimeCommand,
        cancelled: Arc<AtomicBool>,
        execution_started: Arc<AtomicBool>,
        browser_client: bool,
        parent_window: Option<usize>,
        response: Sender<RuntimeProtocolResponse>,
    },
    PlatformPasskeyIsUnlocked {
        response: Sender<bool>,
    },
    PreparePlatformPasskeyOperation {
        operation_id: Vec<u8>,
        parent_window: Option<usize>,
        response: Sender<Result<(Vec<PlatformPasskeyCredential>, bool), String>>,
    },
    EndPlatformPasskeyOperation {
        operation_id: Vec<u8>,
    },
    ReconcileQuickUnlock {
        enabled: bool,
        credentials: Option<QuickUnlockReconciliationCredentials>,
        response: Sender<Result<bool, String>>,
    },
    ListPlatformPasskeyCredentials {
        response: Sender<Result<Vec<PlatformPasskeyCredential>, String>>,
    },
    RegisterPlatformPasskey {
        operation_id: Vec<u8>,
        input: PlatformPasskeyRegistrationInput,
        response: Sender<Result<PlatformPasskeyRegistrationOutput, String>>,
    },
    CommitPlatformPasskeyRegistration {
        operation_id: Vec<u8>,
        response: Sender<Result<(), String>>,
    },
    CreatePlatformPasskeyAssertion {
        operation_id: Vec<u8>,
        input: PlatformPasskeyAssertionInput,
        response: Sender<Result<PlatformPasskeyAssertionOutput, String>>,
    },
    #[cfg(test)]
    TestMutation {
        cancelled: Arc<AtomicBool>,
        started: Sender<()>,
        release: mpsc::Receiver<()>,
        committed: Arc<AtomicBool>,
        response: Sender<Value>,
    },
}

struct ResidentIdleLock {
    timeout: Option<Duration>,
    last_activity: Instant,
}

impl ResidentIdleLock {
    fn new() -> Self {
        Self {
            timeout: Some(Duration::from_secs(10 * 60)),
            last_activity: Instant::now(),
        }
    }

    fn wait_duration(&self, unlocked: bool) -> Option<Duration> {
        if !unlocked {
            return None;
        }
        self.timeout
            .map(|timeout| (self.last_activity + timeout).saturating_duration_since(Instant::now()))
    }

    fn deadline_reached(&self, unlocked: bool) -> bool {
        unlocked
            && self
                .timeout
                .is_some_and(|timeout| self.last_activity.elapsed() >= timeout)
    }

    fn record_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
        self.record_activity();
    }
}

impl RuntimeBridge {
    pub fn new() -> Self {
        Self::spawn(Runtime::new)
    }

    pub fn new_for_tests() -> Self {
        Self::spawn(Runtime::for_tests)
    }

    pub fn new_for_tests_with_quick_unlock() -> Self {
        Self::spawn(Runtime::for_tests_with_quick_unlock)
    }

    fn spawn(factory: impl FnOnce() -> Runtime + Send + 'static) -> Self {
        let (requests, receiver) = mpsc::channel::<RuntimeRequest>();
        std::thread::Builder::new()
            .name("vaultkern-runtime".to_owned())
            .spawn(move || {
                let mut runtime = factory();
                let mut idle_lock = ResidentIdleLock::new();
                loop {
                    let unlocked = runtime.platform_passkey_is_unlocked();
                    if idle_lock.deadline_reached(unlocked) {
                        runtime.lock_session();
                        idle_lock.record_activity();
                        continue;
                    }
                    let request = match idle_lock.wait_duration(unlocked) {
                        Some(wait) => match receiver.recv_timeout(wait) {
                            Ok(request) => request,
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                runtime.lock_session();
                                idle_lock.record_activity();
                                continue;
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        },
                        None => match receiver.recv() {
                            Ok(request) => request,
                            Err(_) => break,
                        },
                    };
                    match request {
                        #[cfg(test)]
                        RuntimeRequest::PanicAfterMutation { response } => {
                            let result = runtime_result(|| -> Result<(), String> {
                                runtime.set_parent_window_handle(Some(1));
                                panic!("injected runtime panic after mutation");
                            });
                            let _ = response.send(result);
                        }
                        RuntimeRequest::SetParentWindowHandle {
                            parent_window,
                            response,
                        } => {
                            runtime.set_parent_window_handle(parent_window);
                            if let Some(response) = response {
                                let _ = response.send(());
                            }
                        }
                        RuntimeRequest::SetIdleLockTimeout { timeout, response } => {
                            idle_lock.set_timeout(timeout);
                            let _ = response.send(());
                        }
                        RuntimeRequest::Protocol {
                            command,
                            cancelled,
                            execution_started,
                            browser_client,
                            parent_window,
                            response,
                        } => {
                            let records_activity = matches!(
                                &command,
                                RuntimeCommand::RecordUserActivity
                                    | RuntimeCommand::UnlockCurrentVaultWithPassword { .. }
                                    | RuntimeCommand::UnlockCurrentVault { .. }
                                    | RuntimeCommand::UnlockCurrentVaultWithQuickUnlock
                                    | RuntimeCommand::UnlockWithPassword { .. }
                                    | RuntimeCommand::UnlockVault { .. }
                            );
                            execution_started.store(true, Ordering::Release);
                            let (value, quick_unlock_credentials) =
                                if cancelled.load(Ordering::Acquire) {
                                    (cancelled_response(), None)
                                } else {
                                    let previous_parent = browser_client.then(|| {
                                        runtime.replace_parent_window_handle(parent_window)
                                    });
                                    let result = if browser_client {
                                        runtime
                                            .handle_browser_command_cancellable_with_quick_unlock_handoff(
                                                command,
                                                cancelled.as_ref(),
                                            )
                                    } else {
                                        runtime.handle_with_quick_unlock_handoff(command)
                                    };
                                    if let Some(previous_parent) = previous_parent {
                                        runtime.set_parent_window_handle(previous_parent);
                                    }
                                    match result {
                                        Ok((response, credentials)) => (response, credentials),
                                        Err(error)
                                            if error.to_string()
                                                == "browser request was cancelled" =>
                                        {
                                            (cancelled_response(), None)
                                        }
                                        Err(error) => (
                                            error_response(
                                                "runtime_error",
                                                format!("{error:#}"),
                                            ),
                                            None,
                                        ),
                                    }
                                };
                            if records_activity
                                && !matches!(&value, RuntimeResponse::Error(_))
                            {
                                idle_lock.record_activity();
                            }
                            let _ = response.send(RuntimeProtocolResponse {
                                response: value,
                                quick_unlock_credentials,
                            });
                        }
                        RuntimeRequest::PlatformPasskeyIsUnlocked { response } => {
                            let unlocked = runtime.platform_passkey_is_unlocked();
                            let _ = response.send(unlocked);
                        }
                        RuntimeRequest::PreparePlatformPasskeyOperation {
                            operation_id,
                            parent_window,
                            response,
                        } => {
                            let result = runtime_result(|| {
                                runtime
                                    .prepare_platform_passkey_operation(operation_id, parent_window)
                            });
                            if result
                                .as_ref()
                                .is_ok_and(|(_, freshly_unlocked)| *freshly_unlocked)
                            {
                                idle_lock.record_activity();
                            }
                            let _ = response.send(result);
                        }
                        RuntimeRequest::EndPlatformPasskeyOperation { operation_id } => {
                            runtime.end_platform_passkey_operation(&operation_id);
                        }
                        RuntimeRequest::ReconcileQuickUnlock {
                            enabled,
                            credentials,
                            response,
                        } => {
                            let result = runtime_result(|| {
                                runtime.reconcile_quick_unlock(enabled, credentials)
                            });
                            let _ = response.send(result);
                        }
                        RuntimeRequest::ListPlatformPasskeyCredentials { response } => {
                            let result =
                                runtime_result(|| runtime.list_platform_passkey_credentials());
                            let _ = response.send(result);
                        }
                        RuntimeRequest::RegisterPlatformPasskey {
                            operation_id,
                            input,
                            response,
                        } => {
                            let result = runtime_result(|| {
                                runtime
                                    .register_platform_passkey_for_operation(&operation_id, input)
                            });
                            let _ = response.send(result);
                        }
                        RuntimeRequest::CommitPlatformPasskeyRegistration {
                            operation_id,
                            response,
                        } => {
                            let result = runtime_result(|| {
                                runtime
                                    .commit_platform_passkey_registration_operation(&operation_id)
                            });
                            let _ = response.send(result);
                        }
                        RuntimeRequest::CreatePlatformPasskeyAssertion {
                            operation_id,
                            input,
                            response,
                        } => {
                            let result = runtime_result(|| {
                                runtime.create_platform_passkey_assertion_for_operation(
                                    &operation_id,
                                    input,
                                )
                            });
                            let _ = response.send(result);
                        }
                        #[cfg(test)]
                        RuntimeRequest::TestMutation {
                            cancelled,
                            started,
                            release,
                            committed,
                            response,
                        } => {
                            if cancelled.load(Ordering::Acquire) {
                                let _ = response.send(response_value(cancelled_response()));
                                continue;
                            }
                            let _ = started.send(());
                            let _ = release.recv();
                            committed.store(true, Ordering::Release);
                            let _ = response
                                .send(serde_json::json!({ "type": "test_mutation_committed" }));
                        }
                    }
                }
            })
            .expect("failed to start the VaultKern runtime thread");

        Self {
            requests,
            reconciliation_notifier: Arc::new(Mutex::new(None)),
            desktop_protocol_session: Arc::new(Mutex::new(RuntimeProtocolSession::resident_app())),
        }
    }

    #[cfg(test)]
    pub fn request(&self, message: Value) -> Value {
        self.request_cancellable(message, Arc::new(AtomicBool::new(false)))
    }

    pub fn request_cancellable(&self, message: Value, cancelled: Arc<AtomicBool>) -> Value {
        self.request_value(
            message,
            cancelled,
            Arc::new(AtomicBool::new(false)),
            false,
            None,
        )
    }

    pub fn request_browser_cancellable(
        &self,
        envelope: ProtocolEnvelope,
        cancelled: Arc<AtomicBool>,
        execution_started: Arc<AtomicBool>,
        parent_window: Option<usize>,
    ) -> RuntimeResponse {
        if cancelled.load(Ordering::Acquire) {
            return cancelled_response();
        }
        self.request_protocol(envelope, cancelled, execution_started, true, parent_window)
    }

    fn request_value(
        &self,
        message: Value,
        cancelled: Arc<AtomicBool>,
        execution_started: Arc<AtomicBool>,
        browser_client: bool,
        parent_window: Option<usize>,
    ) -> Value {
        if cancelled.load(Ordering::Acquire) {
            return response_value(cancelled_response());
        }
        let envelope = match serde_json::from_value::<ProtocolEnvelope>(message) {
            Ok(envelope) => envelope,
            Err(error) => {
                return response_value(error_response(
                    "invalid_request",
                    format!("invalid runtime request: {error}"),
                ));
            }
        };
        response_value(self.request_protocol(
            envelope,
            cancelled,
            execution_started,
            browser_client,
            parent_window,
        ))
    }

    pub fn request_envelope(&self, envelope: ProtocolEnvelope) -> RuntimeResponse {
        if envelope.version != vaultkern_runtime_protocol::PROTOCOL_VERSION {
            return error_response(
                "unsupported_version",
                format!("unsupported runtime protocol version: {}", envelope.version),
            );
        }
        let dispatch = match self.desktop_protocol_session.lock() {
            Ok(mut session) => session.accept(envelope.command),
            Err(_) => {
                return error_response(
                    "runtime_unavailable",
                    "the Tauri protocol session is unavailable",
                );
            }
        };
        let command = match dispatch {
            RuntimeProtocolDispatch::Respond(response) => return response,
            RuntimeProtocolDispatch::Dispatch(command) => command,
        };
        self.request_protocol(
            ProtocolEnvelope::new(command),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            false,
            None,
        )
    }

    fn request_protocol(
        &self,
        envelope: ProtocolEnvelope,
        cancelled: Arc<AtomicBool>,
        execution_started: Arc<AtomicBool>,
        browser_client: bool,
        parent_window: Option<usize>,
    ) -> RuntimeResponse {
        match envelope.version {
            1 => {}
            version => {
                return error_response(
                    "unsupported_version",
                    format!("unsupported runtime protocol version: {version}"),
                );
            }
        }

        let command = envelope.command;
        let reconciliation_reasons = reconciliation_reasons(&command);
        let (response, receiver) = mpsc::channel();
        if self
            .requests
            .send(RuntimeRequest::Protocol {
                command,
                cancelled,
                execution_started,
                browser_client,
                parent_window,
                response,
            })
            .is_err()
        {
            return error_response(
                "runtime_unavailable",
                "the in-process runtime is unavailable",
            );
        }

        let RuntimeProtocolResponse {
            response: value,
            quick_unlock_credentials,
        } = match receiver.recv() {
            Ok(response) => response,
            Err(_) => {
                return error_response(
                    "runtime_unavailable",
                    "the in-process runtime stopped responding",
                );
            }
        };
        if let Some(credentials) = quick_unlock_credentials {
            let _ = self.reconcile_with_quick_unlock_credentials(credentials);
        } else if response_schedules_reconciliation(reconciliation_reasons, &value) {
            self.notify_reconciliation();
        }
        value
    }

    pub fn set_parent_window_handle(&self, parent_window: Option<usize>) -> Result<(), String> {
        let (response, receiver) = mpsc::channel();
        self.requests
            .send(RuntimeRequest::SetParentWindowHandle {
                parent_window,
                response: Some(response),
            })
            .map_err(|_| "the in-process runtime is unavailable".to_owned())?;
        receiver
            .recv()
            .map_err(|_| "the in-process runtime stopped responding".to_owned())
    }

    pub fn set_idle_lock_timeout(&self, timeout: Option<Duration>) -> Result<(), String> {
        let (response, receiver) = mpsc::channel();
        self.requests
            .send(RuntimeRequest::SetIdleLockTimeout { timeout, response })
            .map_err(|_| "the in-process runtime is unavailable".to_owned())?;
        receiver
            .recv()
            .map_err(|_| "the in-process runtime stopped responding".to_owned())
    }

    pub fn queue_parent_window_handle(&self, parent_window: Option<usize>) -> Result<(), String> {
        self.requests
            .send(RuntimeRequest::SetParentWindowHandle {
                parent_window,
                response: None,
            })
            .map_err(|_| "the in-process runtime is unavailable".to_owned())
    }

    pub fn platform_passkey_is_unlocked(&self) -> bool {
        let (response, receiver) = mpsc::channel();
        if self
            .requests
            .send(RuntimeRequest::PlatformPasskeyIsUnlocked { response })
            .is_err()
        {
            return false;
        }
        receiver.recv().unwrap_or(false)
    }

    pub fn prepare_platform_passkey_operation(
        &self,
        operation_id: Vec<u8>,
        parent_window: Option<usize>,
    ) -> Result<(Vec<PlatformPasskeyCredential>, bool), String> {
        let result =
            self.request_platform(|response| RuntimeRequest::PreparePlatformPasskeyOperation {
                operation_id,
                parent_window,
                response,
            });
        if result
            .as_ref()
            .is_ok_and(|(_, freshly_unlocked)| *freshly_unlocked)
        {
            self.notify_reconciliation();
        }
        result
    }

    pub fn end_platform_passkey_operation(&self, operation_id: Vec<u8>) {
        let _ = self
            .requests
            .send(RuntimeRequest::EndPlatformPasskeyOperation { operation_id });
    }

    pub fn reconcile_quick_unlock(
        &self,
        enabled: bool,
        credentials: Option<QuickUnlockReconciliationCredentials>,
    ) -> Result<bool, String> {
        self.request_platform(|response| RuntimeRequest::ReconcileQuickUnlock {
            enabled,
            credentials,
            response,
        })
    }

    pub fn queue_quick_unlock_enrollment(
        &self,
        credentials: QuickUnlockReconciliationCredentials,
    ) -> Result<(), String> {
        self.reconcile_with_quick_unlock_credentials(credentials)
    }

    pub fn list_platform_passkey_credentials(
        &self,
    ) -> Result<Vec<PlatformPasskeyCredential>, String> {
        self.request_platform(|response| RuntimeRequest::ListPlatformPasskeyCredentials {
            response,
        })
    }

    pub fn register_platform_passkey(
        &self,
        operation_id: Vec<u8>,
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<PlatformPasskeyRegistrationOutput, String> {
        self.request_platform(|response| RuntimeRequest::RegisterPlatformPasskey {
            operation_id,
            input,
            response,
        })
    }

    pub fn commit_platform_passkey_registration(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<(), String> {
        let result =
            self.request_platform(
                |response| RuntimeRequest::CommitPlatformPasskeyRegistration {
                    operation_id,
                    response,
                },
            );
        if result.is_ok() {
            self.notify_reconciliation();
        }
        result
    }

    pub fn create_platform_passkey_assertion(
        &self,
        operation_id: Vec<u8>,
        input: PlatformPasskeyAssertionInput,
    ) -> Result<PlatformPasskeyAssertionOutput, String> {
        self.request_platform(|response| RuntimeRequest::CreatePlatformPasskeyAssertion {
            operation_id,
            input,
            response,
        })
    }

    fn request_platform<T>(
        &self,
        request: impl FnOnce(Sender<Result<T, String>>) -> RuntimeRequest,
    ) -> Result<T, String> {
        let (response, receiver) = mpsc::channel();
        self.requests
            .send(request(response))
            .map_err(|_| "the in-process runtime is unavailable".to_owned())?;
        receiver
            .recv()
            .map_err(|_| "the in-process runtime stopped responding".to_owned())?
    }

    #[cfg(test)]
    fn request_test_mutation_cancellable(
        &self,
        cancelled: Arc<AtomicBool>,
        started: Sender<()>,
        release: mpsc::Receiver<()>,
        committed: Arc<AtomicBool>,
    ) -> Value {
        let (response, receiver) = mpsc::channel();
        if self
            .requests
            .send(RuntimeRequest::TestMutation {
                cancelled,
                started,
                release,
                committed,
                response,
            })
            .is_err()
        {
            return response_value(error_response(
                "runtime_unavailable",
                "the in-process runtime is unavailable",
            ));
        }
        receiver.recv().unwrap_or_else(|_| {
            response_value(error_response(
                "runtime_unavailable",
                "the in-process runtime stopped responding",
            ))
        })
    }

    pub fn set_reconciliation_notifier(
        &self,
        notifier: SyncSender<SettingsReconciliationRequest>,
    ) -> Result<(), String> {
        let mut slot = self
            .reconciliation_notifier
            .lock()
            .map_err(|_| "settings reconciliation notifier is unavailable".to_owned())?;
        *slot = Some(notifier);
        Ok(())
    }

    pub fn schedule_reconciliation(&self) {
        self.notify_reconciliation();
    }

    fn notify_reconciliation(&self) {
        let notifier = self
            .reconciliation_notifier
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        if let Some(notifier) = notifier {
            let request = SettingsReconciliationRequest {
                quick_unlock_credentials: None,
                quick_unlock_completion: None,
            };
            match notifier.try_send(request) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    if let Ok(mut slot) = self.reconciliation_notifier.lock() {
                        *slot = None;
                    }
                }
            }
        }
    }

    fn reconcile_with_quick_unlock_credentials(
        &self,
        credentials: QuickUnlockReconciliationCredentials,
    ) -> Result<(), String> {
        let notifier = self
            .reconciliation_notifier
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .ok_or_else(|| "settings reconciliation is unavailable".to_owned())?;
        let (completion, completed) = mpsc::channel();
        let request = SettingsReconciliationRequest {
            quick_unlock_credentials: Some(credentials),
            quick_unlock_completion: Some(completion),
        };
        if let Err(error) = notifier.send(request) {
            drop(error);
            if let Ok(mut slot) = self.reconciliation_notifier.lock() {
                *slot = None;
            }
            return Err("settings reconciliation is unavailable".to_owned());
        }
        completed.recv().map_err(|_| {
            "settings reconciliation stopped before acknowledging credentials".to_owned()
        })?
    }
}

fn command_unlocks_vault(command: &RuntimeCommand) -> bool {
    matches!(
        command,
        RuntimeCommand::UnlockCurrentVaultWithPassword { .. }
            | RuntimeCommand::UnlockCurrentVault { .. }
            | RuntimeCommand::UnlockCurrentVaultWithQuickUnlock
            | RuntimeCommand::UnlockWithPassword { .. }
            | RuntimeCommand::UnlockVault { .. }
    )
}

fn response_commits_active_vault(value: &RuntimeResponse) -> bool {
    let status = match value {
        RuntimeResponse::SaveVaultResult(result) => Some(&result.status),
        RuntimeResponse::DatabaseSettingsCommitResult(result) => Some(&result.save_result.status),
        _ => None,
    };
    matches!(
        status,
        Some(
            vaultkern_runtime_protocol::SaveVaultStatusDto::Saved
                | vaultkern_runtime_protocol::SaveVaultStatusDto::Merged
                | vaultkern_runtime_protocol::SaveVaultStatusDto::SavedToCache
        )
    )
}

fn reconciliation_reasons(command: &RuntimeCommand) -> (bool, bool) {
    (
        command_unlocks_vault(command),
        matches!(command, RuntimeCommand::RetryVaultSourceSync { .. }),
    )
}

fn response_schedules_reconciliation(
    (reconcile_after_unlock, reconcile_after_source_retry): (bool, bool),
    value: &RuntimeResponse,
) -> bool {
    let unlocked = reconcile_after_unlock
        && matches!(value, RuntimeResponse::SessionState(state) if state.unlocked);
    let source_retried = reconcile_after_source_retry
        && matches!(
            value,
            RuntimeResponse::VaultSourceStatus(status)
                if status.remote_state == "online"
        );
    unlocked || source_retried || response_commits_active_vault(value)
}

#[cfg(test)]
mod tests {
    use super::{
        ResidentIdleLock, RuntimeBridge, RuntimeRequest, reconciliation_reasons,
        response_schedules_reconciliation,
    };
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use vaultkern_runtime_protocol::{
        ProtocolEnvelope, RuntimeCommand, RuntimeResponse, VaultSourceStatusDto,
    };

    fn response(value: serde_json::Value) -> RuntimeResponse {
        serde_json::from_value(value).expect("deserialize test runtime response")
    }

    #[test]
    fn tauri_runtime_transport_requires_its_own_resident_session_handshake() {
        let bridge = RuntimeBridge::new_for_tests();

        let RuntimeResponse::Error(error) =
            bridge.request_envelope(ProtocolEnvelope::new(RuntimeCommand::GetSessionState))
        else {
            panic!("business commands before the Tauri handshake must be rejected");
        };
        assert_eq!(error.code, "protocol_handshake_required");

        let RuntimeResponse::Handshake(handshake) =
            bridge.request_envelope(ProtocolEnvelope::new(RuntimeCommand::Handshake {
                protocol_version: vaultkern_runtime_protocol::PROTOCOL_VERSION,
                capabilities: vec![
                    "runtime-core".into(),
                    "resident-app".into(),
                    "quick-unlock".into(),
                ],
            }))
        else {
            panic!("Tauri handshake must be handled by its protocol session");
        };
        assert!(handshake.capabilities.contains(&"resident-app".into()));
        assert!(!handshake.capabilities.contains(&"browser-extension".into()));
        assert!(matches!(
            bridge.request_envelope(ProtocolEnvelope::new(RuntimeCommand::GetSessionState)),
            RuntimeResponse::SessionState(_)
        ));
    }

    #[test]
    fn an_elapsed_resident_idle_deadline_is_detected_before_queued_work() {
        let mut idle_lock = ResidentIdleLock::new();
        idle_lock.set_timeout(Some(Duration::from_millis(1)));
        idle_lock.last_activity = Instant::now() - Duration::from_secs(1);

        assert!(idle_lock.deadline_reached(true));
        assert!(!idle_lock.deadline_reached(false));
    }

    #[test]
    fn panic_after_runtime_mutation_makes_the_bridge_permanently_unavailable() {
        let bridge = RuntimeBridge::new_for_tests();
        let (response, receiver) = mpsc::channel();
        bridge
            .requests
            .send(RuntimeRequest::PanicAfterMutation { response })
            .expect("inject runtime panic");
        let _ = receiver.recv();

        for _ in 0..2 {
            let response = bridge.request(json!({
                "version": 1,
                "command": { "type": "get_session_state" }
            }));
            assert_eq!(response["type"], "error");
            assert_eq!(response["code"], "runtime_unavailable");
        }
    }

    #[test]
    fn cancelled_protocol_request_is_not_dispatched_to_the_runtime() {
        let bridge = RuntimeBridge::new_for_tests();
        let cancelled = Arc::new(AtomicBool::new(true));

        let response = bridge.request_cancellable(
            json!({
                "version": 1,
                "command": { "type": "get_session_state" }
            }),
            cancelled,
        );

        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "request_cancelled");
    }

    #[test]
    fn browser_secret_request_uses_the_fresh_verification_runtime_entrypoint() {
        let bridge = RuntimeBridge::new_for_tests();
        let response = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::GetEntryDetail {
                vault_id: "missing-vault".into(),
                entry_id: "missing-entry".into(),
            }),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            None,
        );

        let RuntimeResponse::Error(error) = response else {
            panic!("expected browser verification error");
        };
        assert_eq!(error.code, "runtime_error");
        assert!(
            error
                .message
                .contains("fresh browser request verification failed")
        );
    }

    #[test]
    fn cancellation_after_execution_starts_returns_the_real_mutation_outcome() {
        let bridge = RuntimeBridge::new_for_tests();
        let cancelled = Arc::new(AtomicBool::new(false));
        let committed = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let request_bridge = bridge.clone();
        let request_cancelled = cancelled.clone();
        let request_committed = committed.clone();
        let request = std::thread::spawn(move || {
            request_bridge.request_test_mutation_cancellable(
                request_cancelled,
                started_tx,
                release_rx,
                request_committed,
            )
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mutation reached the runtime thread");
        cancelled.store(true, Ordering::Release);
        release_tx.send(()).expect("release mutation");

        let response = request.join().expect("mutation response");
        assert!(committed.load(Ordering::Acquire));
        assert_eq!(response["type"], "test_mutation_committed");
    }

    #[test]
    fn successful_source_retry_schedules_desired_state_reconciliation() {
        assert!(response_schedules_reconciliation(
            reconciliation_reasons(&RuntimeCommand::RetryVaultSourceSync {
                vault_id: "vault-1".into(),
            }),
            &RuntimeResponse::VaultSourceStatus(VaultSourceStatusDto {
                source_kind: "onedrive".into(),
                remote_state: "online".into(),
                last_sync_at: None,
                cached_at: None,
                last_error: None,
            }),
        ));
        assert!(!response_schedules_reconciliation(
            reconciliation_reasons(&RuntimeCommand::RetryVaultSourceSync {
                vault_id: "vault-1".into(),
            }),
            &response(json!({ "type": "error", "code": "sync_failed", "message": "failed" })),
        ));
        assert!(!response_schedules_reconciliation(
            reconciliation_reasons(&RuntimeCommand::RetryVaultSourceSync {
                vault_id: "vault-1".into(),
            }),
            &RuntimeResponse::VaultSourceStatus(VaultSourceStatusDto {
                source_kind: "onedrive".into(),
                remote_state: "pending_sync".into(),
                last_sync_at: None,
                cached_at: None,
                last_error: None,
            }),
        ));
    }
}

impl Default for RuntimeBridge {
    fn default() -> Self {
        Self::new()
    }
}

fn response_value(response: RuntimeResponse) -> Value {
    serde_json::to_value(response).unwrap_or_else(|error| {
        serde_json::to_value(error_response(
            "response_serialization_failed",
            format!("failed to serialize runtime response: {error}"),
        ))
        .expect("runtime error responses are serializable")
    })
}

fn cancelled_response() -> RuntimeResponse {
    error_response("request_cancelled", "the runtime request was cancelled")
}

fn runtime_result<T, E>(operation: impl FnOnce() -> Result<T, E>) -> Result<T, String>
where
    E: std::fmt::Display,
{
    operation().map_err(|error| error.to_string())
}

fn error_response(code: impl Into<String>, message: impl Into<String>) -> RuntimeResponse {
    RuntimeResponse::Error(ErrorDto {
        code: code.into(),
        message: message.into(),
    })
}
