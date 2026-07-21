use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};

use serde_json::Value;
use vaultkern_runtime::{
    PlatformPasskeyAssertionInput, PlatformPasskeyAssertionOutput, PlatformPasskeyCredential,
    PlatformPasskeyRegistrationInput, PlatformPasskeyRegistrationOutput, Runtime,
};
use vaultkern_runtime_protocol::{ErrorDto, ProtocolEnvelope, RuntimeCommand, RuntimeResponse};

#[derive(Clone)]
pub struct RuntimeBridge {
    requests: Sender<RuntimeRequest>,
}

enum RuntimeRequest {
    SetParentWindowHandle {
        parent_window: Option<usize>,
        response: Option<Sender<()>>,
    },
    Protocol {
        command: RuntimeCommand,
        cancelled: Arc<AtomicBool>,
        execution_started: Arc<AtomicBool>,
        browser_client: bool,
        parent_window: Option<usize>,
        response: Sender<Value>,
    },
    PlatformPasskeyIsUnlocked {
        response: Sender<bool>,
    },
    ListPlatformPasskeyCredentials {
        response: Sender<Result<Vec<PlatformPasskeyCredential>, String>>,
    },
    ListPlatformPasskeyCredentialsForSync {
        response: Sender<Result<Vec<PlatformPasskeyCredential>, String>>,
    },
    RegisterPlatformPasskey {
        input: PlatformPasskeyRegistrationInput,
        response: Sender<Result<PlatformPasskeyRegistrationOutput, String>>,
    },
    CreatePlatformPasskeyAssertion {
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

impl RuntimeBridge {
    pub fn new() -> Self {
        Self::spawn(Runtime::new)
    }

    pub fn new_for_tests() -> Self {
        Self::spawn(Runtime::for_tests)
    }

    fn spawn(factory: impl FnOnce() -> Runtime + Send + 'static) -> Self {
        let (requests, receiver) = mpsc::channel::<RuntimeRequest>();
        std::thread::Builder::new()
            .name("vaultkern-runtime".to_owned())
            .spawn(move || {
                let mut runtime = factory();
                let mut default_parent_window = None;
                while let Ok(request) = receiver.recv() {
                    match request {
                        RuntimeRequest::SetParentWindowHandle {
                            parent_window,
                            response,
                        } => {
                            default_parent_window = parent_window;
                            runtime.set_parent_window_handle(parent_window);
                            if let Some(response) = response {
                                let _ = response.send(());
                            }
                        }
                        RuntimeRequest::Protocol {
                            command,
                            cancelled,
                            execution_started,
                            browser_client,
                            parent_window,
                            response,
                        } => {
                            execution_started.store(true, Ordering::Release);
                            let value = if cancelled.load(Ordering::Acquire) {
                                cancelled_value()
                            } else {
                                let request_parent_window =
                                    protocol_parent_window_override(browser_client, parent_window);
                                if let Some(parent_window) = request_parent_window {
                                    runtime.set_parent_window_handle(parent_window);
                                }
                                let value = match catch_unwind(AssertUnwindSafe(|| {
                                    if browser_client {
                                        runtime.handle_browser_command_cancellable(
                                            command,
                                            cancelled.as_ref(),
                                        )
                                    } else {
                                        runtime.handle(command)
                                    }
                                })) {
                                    Ok(Ok(response)) => response_value(response),
                                    Ok(Err(error)) => {
                                        error_value("runtime_error", format!("{error:#}"))
                                    }
                                    Err(_) => error_value(
                                        "runtime_panic",
                                        "the in-process runtime recovered from an unexpected failure",
                                    ),
                                };
                                if request_parent_window.is_some() {
                                    runtime.set_parent_window_handle(default_parent_window);
                                }
                                value
                            };
                            let _ = response.send(value);
                        }
                        RuntimeRequest::PlatformPasskeyIsUnlocked { response } => {
                            let unlocked = catch_unwind(AssertUnwindSafe(|| {
                                runtime.platform_passkey_is_unlocked()
                            }))
                            .unwrap_or(false);
                            let _ = response.send(unlocked);
                        }
                        RuntimeRequest::ListPlatformPasskeyCredentials { response } => {
                            let result = catch_runtime_result(|| {
                                runtime.list_platform_passkey_credentials()
                            });
                            let _ = response.send(result);
                        }
                        RuntimeRequest::ListPlatformPasskeyCredentialsForSync { response } => {
                            let result = catch_runtime_result(|| {
                                if runtime.platform_passkey_is_unlocked() {
                                    runtime.list_platform_passkey_credentials()
                                } else {
                                    Ok(Vec::new())
                                }
                            });
                            let _ = response.send(result);
                        }
                        RuntimeRequest::RegisterPlatformPasskey { input, response } => {
                            let result =
                                catch_runtime_result(|| runtime.register_platform_passkey(input));
                            let _ = response.send(result);
                        }
                        RuntimeRequest::CreatePlatformPasskeyAssertion { input, response } => {
                            let result = catch_runtime_result(|| {
                                runtime.create_platform_passkey_assertion(input)
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
                                let _ = response.send(cancelled_value());
                                continue;
                            }
                            let _ = started.send(());
                            let _ = release.recv();
                            committed.store(true, Ordering::Release);
                            let value =
                                serde_json::json!({ "type": "test_mutation_committed" });
                            let _ = response.send(value);
                        }
                    }
                }
            })
            .expect("failed to start the VaultKern runtime thread");

        Self { requests }
    }

    pub fn request(&self, message: Value) -> Value {
        self.request_cancellable(message, Arc::new(AtomicBool::new(false)))
    }

    pub fn request_cancellable(&self, message: Value, cancelled: Arc<AtomicBool>) -> Value {
        self.request_with_client(
            message,
            cancelled,
            Arc::new(AtomicBool::new(false)),
            false,
            None,
        )
    }

    pub fn request_browser_cancellable(
        &self,
        message: Value,
        cancelled: Arc<AtomicBool>,
        execution_started: Arc<AtomicBool>,
        parent_window: Option<usize>,
    ) -> Value {
        self.request_with_client(message, cancelled, execution_started, true, parent_window)
    }

    fn request_with_client(
        &self,
        message: Value,
        cancelled: Arc<AtomicBool>,
        execution_started: Arc<AtomicBool>,
        browser_client: bool,
        parent_window: Option<usize>,
    ) -> Value {
        if cancelled.load(Ordering::Acquire) {
            return cancelled_value();
        }
        let envelope = match serde_json::from_value::<ProtocolEnvelope>(message) {
            Ok(envelope) if envelope.version == 1 => envelope,
            Ok(envelope) => {
                return error_value(
                    "unsupported_version",
                    format!("unsupported runtime protocol version: {}", envelope.version),
                );
            }
            Err(error) => {
                return error_value(
                    "invalid_request",
                    format!("invalid runtime request: {error}"),
                );
            }
        };

        let (response, receiver) = mpsc::channel();
        let wait_cancelled = cancelled.clone();
        if self
            .requests
            .send(RuntimeRequest::Protocol {
                command: envelope.command,
                cancelled,
                execution_started,
                browser_client,
                parent_window,
                response,
            })
            .is_err()
        {
            return error_value(
                "runtime_unavailable",
                "the in-process runtime is unavailable",
            );
        }

        wait_for_runtime_response(receiver, wait_cancelled)
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

    pub fn list_platform_passkey_credentials(
        &self,
    ) -> Result<Vec<PlatformPasskeyCredential>, String> {
        self.request_platform(|response| RuntimeRequest::ListPlatformPasskeyCredentials {
            response,
        })
    }

    pub fn list_platform_passkey_credentials_for_sync(
        &self,
    ) -> Result<Vec<PlatformPasskeyCredential>, String> {
        self.request_platform(
            |response| RuntimeRequest::ListPlatformPasskeyCredentialsForSync { response },
        )
    }

    pub fn register_platform_passkey(
        &self,
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<PlatformPasskeyRegistrationOutput, String> {
        self.request_platform(|response| RuntimeRequest::RegisterPlatformPasskey {
            input,
            response,
        })
    }

    pub fn create_platform_passkey_assertion(
        &self,
        input: PlatformPasskeyAssertionInput,
    ) -> Result<PlatformPasskeyAssertionOutput, String> {
        self.request_platform(|response| RuntimeRequest::CreatePlatformPasskeyAssertion {
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
                cancelled: cancelled.clone(),
                started,
                release,
                committed,
                response,
            })
            .is_err()
        {
            return error_value(
                "runtime_unavailable",
                "the in-process runtime is unavailable",
            );
        }
        wait_for_runtime_response(receiver, cancelled)
    }
}

impl Default for RuntimeBridge {
    fn default() -> Self {
        Self::new()
    }
}

fn response_value(response: RuntimeResponse) -> Value {
    serde_json::to_value(response).unwrap_or_else(|error| {
        error_value(
            "response_serialization_failed",
            format!("failed to serialize runtime response: {error}"),
        )
    })
}

fn catch_runtime_result<T, E>(operation: impl FnOnce() -> Result<T, E>) -> Result<T, String>
where
    E: std::fmt::Display,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("the in-process runtime recovered from an unexpected failure".into()),
    }
}

fn error_value(code: impl Into<String>, message: impl Into<String>) -> Value {
    serde_json::to_value(RuntimeResponse::Error(ErrorDto {
        code: code.into(),
        message: message.into(),
    }))
    .expect("runtime error responses are serializable")
}

fn cancelled_value() -> Value {
    error_value("request_cancelled", "the runtime request was cancelled")
}

fn wait_for_runtime_response(receiver: mpsc::Receiver<Value>, cancelled: Arc<AtomicBool>) -> Value {
    let _ = cancelled;
    receiver.recv().unwrap_or_else(|_| {
        error_value(
            "runtime_unavailable",
            "the in-process runtime stopped responding",
        )
    })
}

fn protocol_parent_window_override(
    browser_client: bool,
    parent_window: Option<usize>,
) -> Option<Option<usize>> {
    browser_client.then_some(parent_window)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use serde_json::json;

    use super::{RuntimeBridge, protocol_parent_window_override};

    #[test]
    fn headless_browser_request_explicitly_clears_the_resident_window_parent() {
        assert_eq!(
            protocol_parent_window_override(true, Some(0x1234)),
            Some(Some(0x1234))
        );
        assert_eq!(protocol_parent_window_override(true, None), Some(None));
        assert_eq!(protocol_parent_window_override(false, None), None);
    }

    #[test]
    fn cancelled_protocol_request_is_not_dispatched_to_the_runtime() {
        let bridge = RuntimeBridge::new_for_tests();
        let cancelled = Arc::new(AtomicBool::new(false));
        cancelled.store(true, Ordering::Release);

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
            json!({
                "version": 1,
                "command": {
                    "type": "get_entry_detail",
                    "vault_id": "missing-vault",
                    "entry_id": "missing-entry"
                }
            }),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Some(0x1234),
        );

        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "runtime_error");
        assert!(
            response["message"]
                .as_str()
                .unwrap_or_default()
                .contains("fresh browser request verification failed")
        );
    }

    #[test]
    fn sync_snapshot_cannot_overtake_a_mutation_after_the_caller_is_cancelled() {
        let bridge = RuntimeBridge::new_for_tests();
        let cancelled = Arc::new(AtomicBool::new(false));
        let committed = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mutation_bridge = bridge.clone();
        let mutation_cancelled = cancelled.clone();
        let mutation_committed = committed.clone();
        let mutation = std::thread::spawn(move || {
            mutation_bridge.request_test_mutation_cancellable(
                mutation_cancelled,
                started_tx,
                release_rx,
                mutation_committed,
            )
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mutation reached the runtime thread");
        cancelled.store(true, Ordering::Release);

        let sync_bridge = bridge.clone();
        let sync_committed = committed.clone();
        let (sync_tx, sync_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = sync_bridge.list_platform_passkey_credentials_for_sync();
            let _ = sync_tx.send((result, sync_committed.load(Ordering::Acquire)));
        });
        assert!(
            sync_rx.recv_timeout(Duration::from_millis(75)).is_err(),
            "the sync request must remain queued behind the active mutation"
        );

        release_tx.send(()).expect("release mutation");
        let response = mutation.join().expect("completed mutation caller");
        assert_eq!(response["type"], "test_mutation_committed");
        let (result, committed_before_sync_returned) = sync_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("sync completes after mutation");
        result.expect("sync snapshot");
        assert!(committed_before_sync_returned);
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
}
