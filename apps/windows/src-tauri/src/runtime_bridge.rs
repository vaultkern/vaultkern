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
use vaultkern_runtime_protocol::{
    BrowserIntegrationSettingsDto, ErrorDto, ProtocolEnvelope, ResidentAppRouteDto, RuntimeCommand,
    RuntimeResponse, SessionStateDto,
};

#[derive(Clone)]
pub struct RuntimeBridge {
    requests: Sender<RuntimeRequest>,
    reconciliation_notifier: Arc<Mutex<Option<SyncSender<SettingsReconciliationRequest>>>>,
    session_state_notifier: Arc<Mutex<Option<Sender<SessionStateDto>>>>,
    resident_activation_notifier: Arc<Mutex<Option<Sender<ResidentAppRouteDto>>>>,
    pending_resident_route: Arc<Mutex<Option<ResidentAppRouteDto>>>,
    browser_integration_settings: Arc<Mutex<BrowserIntegrationSettingsDto>>,
    quick_unlock_enabled: Arc<AtomicBool>,
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
    BindQuickUnlockCredentials {
        credentials: QuickUnlockReconciliationCredentials,
        expected_vault_ref_id: String,
        response: Sender<Result<QuickUnlockReconciliationCredentials, String>>,
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

    fn wait_duration(
        &self,
        unlocked: bool,
        platform_passkey_operation_active: bool,
    ) -> Option<Duration> {
        if !unlocked || platform_passkey_operation_active {
            return None;
        }
        self.timeout
            .map(|timeout| (self.last_activity + timeout).saturating_duration_since(Instant::now()))
    }

    fn deadline_reached(&self, unlocked: bool, platform_passkey_operation_active: bool) -> bool {
        unlocked
            && !platform_passkey_operation_active
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
        let bridge = Self::spawn(Runtime::for_tests_with_quick_unlock);
        bridge.set_quick_unlock_enabled(true);
        bridge
    }

    fn spawn(factory: impl FnOnce() -> Runtime + Send + 'static) -> Self {
        let (requests, receiver) = mpsc::channel::<RuntimeRequest>();
        let reconciliation_notifier = Arc::new(Mutex::new(None));
        let session_state_notifier = Arc::new(Mutex::new(None));
        let resident_activation_notifier = Arc::new(Mutex::new(None));
        let quick_unlock_enabled = Arc::new(AtomicBool::new(false));
        let browser_integration_settings = Arc::new(Mutex::new(BrowserIntegrationSettingsDto {
            language: "en".into(),
            autofill_on_page_load_enabled: false,
            browser_passkey_proxy_enabled: false,
        }));
        let worker_session_state_notifier = Arc::clone(&session_state_notifier);
        let worker_quick_unlock_enabled = Arc::clone(&quick_unlock_enabled);
        let worker_browser_integration_settings = Arc::clone(&browser_integration_settings);
        std::thread::Builder::new()
            .name("vaultkern-runtime".to_owned())
            .spawn(move || {
                let mut runtime = factory();
                runtime.bind_quick_unlock_policy_gate(worker_quick_unlock_enabled);
                let mut idle_lock = ResidentIdleLock::new();
                loop {
                    let unlocked = runtime.platform_passkey_is_unlocked();
                    let platform_passkey_operation_active =
                        runtime.has_active_platform_passkey_operations();
                    if idle_lock.deadline_reached(
                        unlocked,
                        platform_passkey_operation_active,
                    ) {
                        runtime.lock_session();
                        publish_session_state(
                            &worker_session_state_notifier,
                            runtime.session_state(),
                        );
                        idle_lock.record_activity();
                        continue;
                    }
                    let request = match idle_lock
                        .wait_duration(unlocked, platform_passkey_operation_active)
                    {
                        Some(wait) => match receiver.recv_timeout(wait) {
                            Ok(request) => request,
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                runtime.lock_session();
                                publish_session_state(
                                    &worker_session_state_notifier,
                                    runtime.session_state(),
                                );
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
                            browser_client,
                            parent_window,
                            response,
                        } => {
                            if browser_client
                                && browser_passkey_proxy_must_be_enabled(&command)
                                && !worker_browser_integration_settings
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .browser_passkey_proxy_enabled
                            {
                                let _ = response.send(RuntimeProtocolResponse {
                                    response: error_response(
                                        "browser_passkey_proxy_disabled",
                                        "browser passkey handling is disabled in resident settings",
                                    ),
                                    quick_unlock_credentials: None,
                                });
                                continue;
                            }
                            let publishes_session_state =
                                command_can_change_session_state(&command);
                            let records_activity = matches!(
                                &command,
                                RuntimeCommand::RecordUserActivity
                                    | RuntimeCommand::UnlockCurrentVaultWithPassword { .. }
                                    | RuntimeCommand::UnlockCurrentVault { .. }
                                    | RuntimeCommand::UnlockCurrentVaultWithQuickUnlock
                                    | RuntimeCommand::UnlockWithPassword { .. }
                                    | RuntimeCommand::UnlockVault { .. }
                            );
                            let (value, quick_unlock_credentials) =
                                if cancelled.load(Ordering::Acquire) {
                                    (cancelled_response(), None)
                                } else if let Some(error) =
                                    platform_passkey_operation_preflight_error(
                                        runtime.has_active_platform_passkey_operations(),
                                        &command,
                                    )
                                {
                                    (error, None)
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
                            if publishes_session_state
                                && !matches!(&value, RuntimeResponse::Error(_))
                            {
                                publish_session_state(
                                    &worker_session_state_notifier,
                                    runtime.session_state(),
                                );
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
                            let previous_state = runtime.session_state();
                            let result = runtime_result(|| {
                                runtime
                                    .prepare_platform_passkey_operation(operation_id, parent_window)
                            });
                            if result.is_ok() {
                                idle_lock.record_activity();
                            }
                            if result.is_ok() {
                                let next_state = runtime.session_state();
                                if next_state != previous_state {
                                    publish_session_state(
                                        &worker_session_state_notifier,
                                        next_state,
                                    );
                                }
                            }
                            let _ = response.send(result);
                        }
                        RuntimeRequest::EndPlatformPasskeyOperation { operation_id } => {
                            let previous_state = runtime.session_state();
                            runtime.end_platform_passkey_operation(&operation_id);
                            let next_state = runtime.session_state();
                            if next_state != previous_state {
                                publish_session_state(
                                    &worker_session_state_notifier,
                                    next_state,
                                );
                            }
                        }
                        RuntimeRequest::BindQuickUnlockCredentials {
                            credentials,
                            expected_vault_ref_id,
                            response,
                        } => {
                            let result = runtime_result(|| {
                                runtime.bind_quick_unlock_reconciliation_credentials(
                                    credentials,
                                    &expected_vault_ref_id,
                                )
                            });
                            let _ = response.send(result);
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
            reconciliation_notifier,
            session_state_notifier,
            resident_activation_notifier,
            pending_resident_route: Arc::new(Mutex::new(None)),
            browser_integration_settings,
            quick_unlock_enabled,
            desktop_protocol_session: Arc::new(Mutex::new(RuntimeProtocolSession::resident_app())),
        }
    }

    #[cfg(test)]
    pub fn request(&self, message: Value) -> Value {
        self.request_cancellable(message, Arc::new(AtomicBool::new(false)))
    }

    pub fn request_cancellable(&self, message: Value, cancelled: Arc<AtomicBool>) -> Value {
        self.request_value(message, cancelled, false, None)
    }

    pub fn request_browser_cancellable(
        &self,
        envelope: ProtocolEnvelope,
        cancelled: Arc<AtomicBool>,
        parent_window: Option<usize>,
    ) -> RuntimeResponse {
        if cancelled.load(Ordering::Acquire) {
            return cancelled_response();
        }
        if envelope.version == vaultkern_runtime_protocol::PROTOCOL_VERSION
            && browser_passkey_proxy_must_be_enabled(&envelope.command)
            && !self
                .browser_integration_settings
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .browser_passkey_proxy_enabled
        {
            return error_response(
                "browser_passkey_proxy_disabled",
                "browser passkey handling is disabled in resident settings",
            );
        }
        if envelope.version == vaultkern_runtime_protocol::PROTOCOL_VERSION
            && let RuntimeCommand::ActivateResidentApp { route } = &envelope.command
        {
            return self.activate_resident_app(*route);
        }
        if envelope.version == vaultkern_runtime_protocol::PROTOCOL_VERSION
            && matches!(
                &envelope.command,
                RuntimeCommand::GetBrowserIntegrationSettings
            )
        {
            return RuntimeResponse::BrowserIntegrationSettings(
                self.browser_integration_settings
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone(),
            );
        }
        self.request_protocol(envelope, cancelled, true, parent_window)
    }

    fn activate_resident_app(&self, route: ResidentAppRouteDto) -> RuntimeResponse {
        let notifier = self
            .resident_activation_notifier
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        let Some(notifier) = notifier else {
            return error_response(
                "runtime_unavailable",
                "the resident app activation channel is unavailable",
            );
        };
        if notifier.send(route).is_err() {
            return error_response(
                "runtime_unavailable",
                "the resident app activation channel stopped responding",
            );
        }
        RuntimeResponse::ResidentAppActivated
    }

    fn request_value(
        &self,
        message: Value,
        cancelled: Arc<AtomicBool>,
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
        response_value(self.request_protocol(envelope, cancelled, browser_client, parent_window))
    }

    pub fn request_envelope(&self, envelope: ProtocolEnvelope) -> RuntimeResponse {
        if envelope.version != vaultkern_runtime_protocol::PROTOCOL_VERSION {
            return error_response(
                "unsupported_version",
                format!("unsupported runtime protocol version: {}", envelope.version),
            );
        }
        let ProtocolEnvelope {
            version,
            request_id,
            command,
        } = envelope;
        let dispatch = match self.desktop_protocol_session.lock() {
            Ok(mut session) => session.accept(command),
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
            ProtocolEnvelope {
                version,
                request_id,
                command,
            },
            Arc::new(AtomicBool::new(false)),
            false,
            None,
        )
    }

    fn request_protocol(
        &self,
        envelope: ProtocolEnvelope,
        cancelled: Arc<AtomicBool>,
        browser_client: bool,
        parent_window: Option<usize>,
    ) -> RuntimeResponse {
        if envelope.version != vaultkern_runtime_protocol::PROTOCOL_VERSION {
            return error_response(
                "unsupported_version",
                format!("unsupported runtime protocol version: {}", envelope.version),
            );
        }

        let command = envelope.command;
        let reconciliation_reasons = reconciliation_reasons(&command);
        let (response, receiver) = mpsc::channel();
        if self
            .requests
            .send(RuntimeRequest::Protocol {
                command,
                cancelled,
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
        expected_vault_ref_id: String,
    ) -> Result<(), String> {
        let credentials =
            self.request_platform(|response| RuntimeRequest::BindQuickUnlockCredentials {
                credentials,
                expected_vault_ref_id,
                response,
            })?;
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

    pub fn set_session_state_notifier(
        &self,
        notifier: Sender<SessionStateDto>,
    ) -> Result<(), String> {
        let mut slot = self
            .session_state_notifier
            .lock()
            .map_err(|_| "session-state notifier is unavailable".to_owned())?;
        *slot = Some(notifier);
        Ok(())
    }

    pub fn set_resident_activation_notifier(
        &self,
        notifier: Sender<ResidentAppRouteDto>,
    ) -> Result<(), String> {
        let mut slot = self
            .resident_activation_notifier
            .lock()
            .map_err(|_| "resident activation notifier is unavailable".to_owned())?;
        *slot = Some(notifier);
        Ok(())
    }

    pub fn queue_pending_resident_route(&self, route: ResidentAppRouteDto) {
        *self
            .pending_resident_route
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(route);
    }

    pub fn take_pending_resident_route(&self) -> Option<ResidentAppRouteDto> {
        self.pending_resident_route
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }

    pub fn set_browser_integration_settings(&self, settings: &BrowserIntegrationSettingsDto) {
        *self
            .browser_integration_settings
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = settings.clone();
    }

    pub fn set_quick_unlock_enabled(&self, enabled: bool) {
        self.quick_unlock_enabled.store(enabled, Ordering::Release);
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

fn browser_passkey_proxy_must_be_enabled(command: &RuntimeCommand) -> bool {
    // Query/reconcile/unknown-delivery/abort commands remain available so a
    // disabled proxy can clean up an interrupted ceremony without progressing it.
    if let RuntimeCommand::AdvancePasskeyCeremonyPhase { next_phase, .. } = command {
        return !matches!(
            next_phase,
            vaultkern_runtime_protocol::PasskeyCeremonyPhaseDto::ClosedAborted
                | vaultkern_runtime_protocol::PasskeyCeremonyPhaseDto::ClosedDelivered
                | vaultkern_runtime_protocol::PasskeyCeremonyPhaseDto::ClosedFailed
        );
    }
    matches!(
        command,
        RuntimeCommand::GetPasskeyUserVerificationCapability
            | RuntimeCommand::VerifyPasskeyUser { .. }
            | RuntimeCommand::ListPasskeyCredentials { .. }
            | RuntimeCommand::RegisterPasskeyCeremony { .. }
            | RuntimeCommand::BindPasskeyCeremonyVault { .. }
            | RuntimeCommand::CreatePasskeyAssertion { .. }
            | RuntimeCommand::CreatePasskeyRegistration { .. }
            | RuntimeCommand::SavePasskeyRegistration { .. }
            | RuntimeCommand::CommitPasskeyRegistration { .. }
            | RuntimeCommand::PasskeyCredentialStatus { .. }
            | RuntimeCommand::PasskeyCredentialStatusBatch { .. }
    )
}

fn publish_session_state(
    notifier: &Arc<Mutex<Option<Sender<SessionStateDto>>>>,
    state: SessionStateDto,
) {
    let sender = notifier.lock().ok().and_then(|slot| slot.clone());
    if sender.is_some_and(|sender| sender.send(state).is_err())
        && let Ok(mut slot) = notifier.lock()
    {
        *slot = None;
    }
}

fn command_can_invalidate_platform_operation(command: &RuntimeCommand) -> bool {
    matches!(
        command,
        RuntimeCommand::PreloadCurrentVault
            | RuntimeCommand::RetryVaultSourceSync { .. }
            | RuntimeCommand::AddLocalVaultReference { .. }
            | RuntimeCommand::AddOneDriveVaultReference { .. }
            | RuntimeCommand::SetCurrentVault { .. }
            | RuntimeCommand::DeleteVaultReference { .. }
            | RuntimeCommand::UnlockCurrentVaultWithPassword { .. }
            | RuntimeCommand::UnlockCurrentVault { .. }
            | RuntimeCommand::UnlockCurrentVaultWithQuickUnlock
            | RuntimeCommand::OpenLocalVault { .. }
            | RuntimeCommand::LockSession
            | RuntimeCommand::UnlockWithPassword { .. }
            | RuntimeCommand::UnlockVault { .. }
    )
}

fn platform_passkey_operation_preflight_error(
    operation_active: bool,
    command: &RuntimeCommand,
) -> Option<RuntimeResponse> {
    (operation_active && command_can_invalidate_platform_operation(command)).then(|| {
        error_response(
            "platform_operation_active",
            "finish the active Windows passkey operation before changing the resident session",
        )
    })
}

fn command_can_change_session_state(command: &RuntimeCommand) -> bool {
    matches!(
        command,
        RuntimeCommand::AddLocalVaultReference { .. }
            | RuntimeCommand::AddOneDriveVaultReference { .. }
            | RuntimeCommand::SetCurrentVault { .. }
            | RuntimeCommand::DeleteVaultReference { .. }
            | RuntimeCommand::UnlockCurrentVaultWithPassword { .. }
            | RuntimeCommand::UnlockCurrentVault { .. }
            | RuntimeCommand::UnlockCurrentVaultWithQuickUnlock
            | RuntimeCommand::OpenLocalVault { .. }
            | RuntimeCommand::LockSession
            | RuntimeCommand::UnlockWithPassword { .. }
            | RuntimeCommand::UnlockVault { .. }
    )
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
    if matches!(value, RuntimeResponse::EntryMutationResult(_)) {
        return true;
    }
    let status = match value {
        RuntimeResponse::PublicationResult(result) => Some(&result.status),
        RuntimeResponse::DatabaseSettingsCommitResult(result) => Some(&result.publication.status),
        RuntimeResponse::VaultMutationResult(result) => Some(&result.publication.status),
        _ => None,
    };
    matches!(
        status,
        Some(
            vaultkern_runtime_protocol::PublicationStatusDto::Published
                | vaultkern_runtime_protocol::PublicationStatusDto::Reconciled
                | vaultkern_runtime_protocol::PublicationStatusDto::Pending
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
        CommitStatusDto, EntryMutationResultDto, ProtocolEnvelope, PublicationResultDto,
        PublicationStatusDto, ResidentAppRouteDto, RuntimeCommand, RuntimeResponse,
        VaultMutationResultDto, VaultSourceStatusDto,
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

        assert!(idle_lock.deadline_reached(true, false));
        assert!(!idle_lock.deadline_reached(false, false));
    }

    #[test]
    fn an_active_platform_passkey_operation_defers_the_idle_deadline() {
        let mut idle_lock = ResidentIdleLock::new();
        idle_lock.set_timeout(Some(Duration::from_millis(1)));
        idle_lock.last_activity = Instant::now() - Duration::from_secs(1);

        assert!(!idle_lock.deadline_reached(true, true));
        assert_eq!(idle_lock.wait_duration(true, true), None);
        assert!(
            super::platform_passkey_operation_preflight_error(true, &RuntimeCommand::LockSession,)
                .is_some()
        );
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
                "version": 3,
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
                "version": 3,
                "command": { "type": "get_session_state" }
            }),
            cancelled,
        );

        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "request_cancelled");
    }

    #[test]
    fn browser_vault_management_is_rejected_before_any_verification_prompt() {
        let bridge = RuntimeBridge::new_for_tests();
        let response = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::GetEntryDetail {
                vault_id: "missing-vault".into(),
                entry_id: "missing-entry".into(),
            }),
            Arc::new(AtomicBool::new(false)),
            None,
        );

        let RuntimeResponse::Error(error) = response else {
            panic!("expected browser command-boundary error");
        };
        assert_eq!(error.code, "runtime_error");
        assert!(error.message.contains("browser command forbidden"));
    }

    #[test]
    fn browser_activation_is_forwarded_to_the_resident_window_without_runtime_dispatch() {
        let bridge = RuntimeBridge::new_for_tests();
        let (notifier, notifications) = mpsc::channel();
        bridge
            .set_resident_activation_notifier(notifier)
            .expect("install resident activation notifier");

        let response = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::ActivateResidentApp {
                route: ResidentAppRouteDto::Settings,
            }),
            Arc::new(AtomicBool::new(false)),
            None,
        );

        assert!(matches!(response, RuntimeResponse::ResidentAppActivated));
        assert_eq!(
            notifications
                .recv_timeout(Duration::from_secs(1))
                .expect("resident route notification"),
            ResidentAppRouteDto::Settings
        );
    }

    #[test]
    fn resident_activation_route_waits_for_the_webview_to_take_it() {
        let bridge = RuntimeBridge::new_for_tests();

        bridge.queue_pending_resident_route(ResidentAppRouteDto::Settings);
        bridge.queue_pending_resident_route(ResidentAppRouteDto::Vaults);

        assert_eq!(
            bridge.take_pending_resident_route(),
            Some(ResidentAppRouteDto::Vaults)
        );
        assert_eq!(bridge.take_pending_resident_route(), None);
    }

    #[test]
    fn browser_integration_settings_are_read_from_resident_desired_state() {
        let bridge = RuntimeBridge::new_for_tests();
        let desired = crate::DesktopDesiredState::from_settings(&json!({
            "language": "zh-CN",
            "autofillOnPageLoadEnabled": true,
            "browserPasskeyProxyEnabled": true
        }));
        bridge.set_browser_integration_settings(&desired.browser_integration);

        let response = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::GetBrowserIntegrationSettings),
            Arc::new(AtomicBool::new(false)),
            None,
        );

        let RuntimeResponse::BrowserIntegrationSettings(settings) = response else {
            panic!("expected browser integration settings");
        };
        let serialized = serde_json::to_value(&settings).expect("serialize browser settings");
        assert!(serialized.get("clearClipboardSeconds").is_none());
        assert_eq!(settings.language, "zh-CN");
        assert!(settings.autofill_on_page_load_enabled);
        assert!(settings.browser_passkey_proxy_enabled);
    }

    #[test]
    fn resident_policy_rejects_browser_passkey_work_while_proxy_is_disabled() {
        let bridge = RuntimeBridge::new_for_tests();

        let disabled = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::GetPasskeyUserVerificationCapability),
            Arc::new(AtomicBool::new(false)),
            None,
        );
        let RuntimeResponse::Error(error) = disabled else {
            panic!("expected disabled browser passkey proxy error");
        };
        assert_eq!(error.code, "browser_passkey_proxy_disabled");

        let assertion = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::CreatePasskeyAssertion {
                ceremony_token: "ceremony".into(),
                expected_phase:
                    vaultkern_runtime_protocol::PasskeyCeremonyPhaseDto::CompletionAndMutation,
                vault_id: "vault".into(),
                relying_party: "example.com".into(),
                origin: "https://example.com".into(),
                credential_id: None,
                discoverable: true,
                user_presence_verified: true,
                related_origin_verified: false,
                client_data_json_base64url: "client-data".into(),
            }),
            Arc::new(AtomicBool::new(false)),
            None,
        );
        let RuntimeResponse::Error(error) = assertion else {
            panic!("expected disabled browser assertion rejection");
        };
        assert_eq!(error.code, "browser_passkey_proxy_disabled");

        let cleanup = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::AdvancePasskeyCeremonyPhase {
                ceremony_token: "missing-cleanup-ceremony".into(),
                expected_phase:
                    vaultkern_runtime_protocol::PasskeyCeremonyPhaseDto::UserAuthorization,
                next_phase: vaultkern_runtime_protocol::PasskeyCeremonyPhaseDto::ClosedFailed,
                related_origin_verified: false,
            }),
            Arc::new(AtomicBool::new(false)),
            None,
        );
        let RuntimeResponse::Error(error) = cleanup else {
            panic!("missing cleanup ceremony should reach the runtime ledger");
        };
        assert_eq!(error.code, "runtime_error");
        assert!(error.message.contains("passkey ceremony not registered"));

        let forward_progress = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::AdvancePasskeyCeremonyPhase {
                ceremony_token: "disabled-progress-ceremony".into(),
                expected_phase:
                    vaultkern_runtime_protocol::PasskeyCeremonyPhaseDto::UserAuthorization,
                next_phase:
                    vaultkern_runtime_protocol::PasskeyCeremonyPhaseDto::CredentialResolution,
                related_origin_verified: false,
            }),
            Arc::new(AtomicBool::new(false)),
            None,
        );
        let RuntimeResponse::Error(error) = forward_progress else {
            panic!("disabled browser passkey progress must be rejected");
        };
        assert_eq!(error.code, "browser_passkey_proxy_disabled");

        let desired = crate::DesktopDesiredState::from_settings(&json!({
            "browserPasskeyProxyEnabled": true
        }));
        bridge.set_browser_integration_settings(&desired.browser_integration);
        let enabled = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::GetPasskeyUserVerificationCapability),
            Arc::new(AtomicBool::new(false)),
            None,
        );
        assert!(matches!(
            enabled,
            RuntimeResponse::PasskeyUserVerificationCapability(_)
        ));

        let desired = crate::DesktopDesiredState::from_settings(&json!({
            "windowsPasskeyProviderEnabled": true,
            "browserPasskeyProxyEnabled": true
        }));
        bridge.set_browser_integration_settings(&desired.browser_integration);
        let system_provider_selected = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::GetPasskeyUserVerificationCapability),
            Arc::new(AtomicBool::new(false)),
            None,
        );
        let RuntimeResponse::Error(error) = system_provider_selected else {
            panic!("expected system-provider browser proxy rejection");
        };
        assert_eq!(error.code, "browser_passkey_proxy_disabled");
    }

    #[test]
    fn queued_browser_passkey_work_rechecks_the_committed_policy_before_execution() {
        let bridge = RuntimeBridge::new_for_tests();
        let enabled = crate::DesktopDesiredState::from_settings(&json!({
            "browserPasskeyProxyEnabled": true
        }));
        bridge.set_browser_integration_settings(&enabled.browser_integration);

        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let blocker_bridge = bridge.clone();
        let blocker = std::thread::spawn(move || {
            blocker_bridge.request_test_mutation_cancellable(
                Arc::new(AtomicBool::new(false)),
                started_tx,
                release_rx,
                Arc::new(AtomicBool::new(false)),
            )
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("runtime worker is blocked before the browser request");

        let (response_tx, response_rx) = mpsc::channel();
        bridge
            .requests
            .send(RuntimeRequest::Protocol {
                command: RuntimeCommand::GetPasskeyUserVerificationCapability,
                cancelled: Arc::new(AtomicBool::new(false)),
                browser_client: true,
                parent_window: None,
                response: response_tx,
            })
            .expect("queue browser passkey work");

        let disabled = crate::DesktopDesiredState::from_settings(&json!({
            "browserPasskeyProxyEnabled": false
        }));
        bridge.set_browser_integration_settings(&disabled.browser_integration);
        release_tx.send(()).expect("release runtime worker");
        blocker.join().expect("blocking request completes");

        let response = response_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("queued browser request completes")
            .response;
        let RuntimeResponse::Error(error) = response else {
            panic!("queued passkey work must observe the committed disabled policy");
        };
        assert_eq!(error.code, "browser_passkey_proxy_disabled");
    }

    #[test]
    fn legacy_system_provider_preference_cannot_leave_browser_passkeys_enabled() {
        let bridge = RuntimeBridge::new_for_tests();
        let desired = crate::DesktopDesiredState::from_settings(&json!({
            "passkeyProviderEnabled": true,
            "browserPasskeyProxyEnabled": true
        }));
        bridge.set_browser_integration_settings(&desired.browser_integration);

        let response = bridge.request_browser_cancellable(
            ProtocolEnvelope::new(RuntimeCommand::GetPasskeyUserVerificationCapability),
            Arc::new(AtomicBool::new(false)),
            None,
        );

        let RuntimeResponse::Error(error) = response else {
            panic!("expected the legacy system-provider preference to disable browser passkeys");
        };
        assert_eq!(error.code, "browser_passkey_proxy_disabled");
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
    fn session_state_changes_are_published_to_the_resident_ui() {
        let bridge = RuntimeBridge::new_for_tests();
        let (notifier, notifications) = mpsc::channel();
        bridge
            .set_session_state_notifier(notifier)
            .expect("install session-state notifier");

        let response = bridge.request(json!({
            "version": 3,
            "command": { "type": "lock_session" }
        }));

        assert_eq!(response["type"], "session_state");
        let published = notifications
            .recv_timeout(Duration::from_secs(1))
            .expect("resident UI receives the changed state");
        assert!(!published.unlocked);
    }

    #[test]
    fn conflict_copy_recovers_edits_without_reconciling_live_vault_metadata() {
        let response = RuntimeResponse::PublicationResult(PublicationResultDto {
            status: PublicationStatusDto::ConflictSplit,
            reconciliation_summary: None,
            conflict_copy_path: Some("vault-1.conflict.kdbx".into()),
        });

        assert!(!super::response_commits_active_vault(&response));
    }

    #[test]
    fn vault_mutation_commit_updates_resident_persistence_state() {
        let response = RuntimeResponse::VaultMutationResult(VaultMutationResultDto {
            commit: CommitStatusDto::Committed,
            publication: PublicationResultDto {
                status: PublicationStatusDto::Pending,
                reconciliation_summary: None,
                conflict_copy_path: None,
            },
            created_group_id: Some("group-created".into()),
        });

        assert!(super::response_commits_active_vault(&response));
    }

    #[test]
    fn entry_mutation_commit_updates_resident_credential_metadata() {
        for (status, expected) in [
            (PublicationStatusDto::Published, true),
            (PublicationStatusDto::Reconciled, true),
            (PublicationStatusDto::Pending, true),
            (PublicationStatusDto::ConflictSplit, true),
        ] {
            let response = RuntimeResponse::EntryMutationResult(EntryMutationResultDto {
                commit: CommitStatusDto::Committed,
                publication: PublicationResultDto {
                    status: status.clone(),
                    reconciliation_summary: None,
                    conflict_copy_path: None,
                },
                entry: None,
            });

            assert_eq!(
                super::response_commits_active_vault(&response),
                expected,
                "unexpected reconciliation decision for {status:?}"
            );
        }
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
