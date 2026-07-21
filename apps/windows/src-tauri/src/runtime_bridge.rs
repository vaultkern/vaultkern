use std::panic::{AssertUnwindSafe, catch_unwind};
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
        response: Sender<Value>,
    },
    PlatformPasskeyIsUnlocked {
        response: Sender<bool>,
    },
    ListPlatformPasskeyCredentials {
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
                while let Ok(request) = receiver.recv() {
                    match request {
                        RuntimeRequest::SetParentWindowHandle {
                            parent_window,
                            response,
                        } => {
                            runtime.set_parent_window_handle(parent_window);
                            if let Some(response) = response {
                                let _ = response.send(());
                            }
                        }
                        RuntimeRequest::Protocol { command, response } => {
                            let value = match catch_unwind(AssertUnwindSafe(|| {
                                runtime.handle(command)
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
                    }
                }
            })
            .expect("failed to start the VaultKern runtime thread");

        Self { requests }
    }

    pub fn request(&self, message: Value) -> Value {
        let envelope = match serde_json::from_value::<ProtocolEnvelope>(message) {
            Ok(envelope) => envelope,
            Err(error) => {
                return error_value(
                    "invalid_request",
                    format!("invalid runtime request: {error}"),
                );
            }
        };
        self.request_envelope(envelope)
    }

    pub fn request_envelope(&self, envelope: ProtocolEnvelope) -> Value {
        match envelope.version {
            1 => {}
            version => {
                return error_value(
                    "unsupported_version",
                    format!("unsupported runtime protocol version: {version}"),
                );
            }
        }

        let (response, receiver) = mpsc::channel();
        if self
            .requests
            .send(RuntimeRequest::Protocol {
                command: envelope.command,
                response,
            })
            .is_err()
        {
            return error_value(
                "runtime_unavailable",
                "the in-process runtime is unavailable",
            );
        }

        receiver.recv().unwrap_or_else(|_| {
            error_value(
                "runtime_unavailable",
                "the in-process runtime stopped responding",
            )
        })
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
