use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};
use vaultkern_runtime_protocol::{
    ErrorDto, HandshakeDto, ProtocolEnvelope, RuntimeCommand, RuntimeResponse,
};
use zeroize::Zeroizing;

use crate::Runtime;
use crate::runtime::{ResidentBrowserRequestCanceled, required_command_capabilities};

pub const MAX_RESIDENT_PROTOCOL_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 256;
const BROWSER_CAPABILITIES: &[&str] = &[
    "runtime-core",
    "browser-extension",
    "database-settings",
    "one-drive",
    "passkey-ceremonies",
];

#[derive(Default)]
pub struct ResidentProtocolSession {
    negotiated_capabilities: Option<Vec<String>>,
}

impl std::fmt::Debug for ResidentProtocolSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentProtocolSession")
            .field("negotiated", &self.negotiated_capabilities.is_some())
            .finish()
    }
}

impl ResidentProtocolSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handle_message(
        &mut self,
        runtime: &mut Runtime,
        payload: Zeroizing<Vec<u8>>,
        canceled: &AtomicBool,
    ) -> Zeroizing<Vec<u8>> {
        let request_id = request_id_from_payload(&payload);
        if payload.len() > MAX_RESIDENT_PROTOCOL_MESSAGE_BYTES {
            return encode_response(
                error_response(
                    "invalid_request",
                    "resident protocol message exceeds the hard size limit",
                ),
                request_id.as_deref(),
            );
        }

        let envelope = match serde_json::from_slice::<ProtocolEnvelope>(&payload) {
            Ok(envelope) => envelope,
            Err(error) => {
                return encode_response(
                    error_response(
                        "invalid_request",
                        &format!("failed to decode resident protocol message: {error}"),
                    ),
                    request_id.as_deref(),
                );
            }
        };
        let request_id = match envelope.request_id {
            Some(request_id) if request_id.len() <= MAX_REQUEST_ID_BYTES => Some(request_id),
            Some(_) => {
                return encode_response(
                    error_response("invalid_request", "request ID exceeds the hard size limit"),
                    None,
                );
            }
            None => None,
        };
        if envelope.version != vaultkern_runtime_protocol::PROTOCOL_VERSION {
            return encode_response(
                error_response(
                    "unsupported_version",
                    &format!("unsupported runtime protocol version: {}", envelope.version),
                ),
                request_id.as_deref(),
            );
        }

        let response = match envelope.command {
            RuntimeCommand::Handshake {
                protocol_version,
                capabilities,
            } => self.negotiate(protocol_version, capabilities),
            command => self.handle_command(runtime, command, canceled),
        };
        let encoded = encode_response(response, request_id.as_deref());
        if encoded.len() <= MAX_RESIDENT_PROTOCOL_MESSAGE_BYTES {
            encoded
        } else {
            encode_response(
                error_response(
                    "response_too_large",
                    "resident protocol response exceeds the hard size limit",
                ),
                request_id.as_deref(),
            )
        }
    }

    fn negotiate(&mut self, protocol_version: u32, capabilities: Vec<String>) -> RuntimeResponse {
        if protocol_version != vaultkern_runtime_protocol::PROTOCOL_VERSION {
            return error_response(
                "unsupported_version",
                &format!("unsupported runtime protocol version: {protocol_version}"),
            );
        }
        let capabilities = capabilities
            .into_iter()
            .filter(|capability| BROWSER_CAPABILITIES.contains(&capability.as_str()))
            .collect::<Vec<_>>();
        self.negotiated_capabilities = Some(capabilities.clone());
        RuntimeResponse::Handshake(HandshakeDto {
            protocol_version: vaultkern_runtime_protocol::PROTOCOL_VERSION,
            capabilities,
        })
    }

    fn handle_command(
        &mut self,
        runtime: &mut Runtime,
        command: RuntimeCommand,
        canceled: &AtomicBool,
    ) -> RuntimeResponse {
        let Some(capabilities) = self.negotiated_capabilities.as_ref() else {
            return error_response(
                "handshake_required",
                "runtime protocol handshake is required before business commands",
            );
        };
        if !capabilities
            .iter()
            .any(|capability| capability == "browser-extension")
        {
            return error_response(
                "capability_required",
                "resident protocol requires the browser-extension capability",
            );
        }
        for capability in required_command_capabilities(&command) {
            if !capabilities.iter().any(|granted| granted == capability) {
                return error_response(
                    "capability_required",
                    &format!("runtime command requires negotiated capability: {capability}"),
                );
            }
        }

        let result = catch_unwind(AssertUnwindSafe(|| {
            runtime.authorize_resident_browser_command(&command, canceled)?;
            runtime.handle(command)
        }));
        match result {
            Ok(Ok(response)) => response,
            Ok(Err(error)) if error.is::<ResidentBrowserRequestCanceled>() => {
                error_response("request_canceled", "browser request was canceled")
            }
            Ok(Err(error)) => error_response("invalid_request", &format!("{error:#}")),
            Err(_) => error_response("panic", "resident runtime command panicked"),
        }
    }
}

fn error_response(code: &str, message: &str) -> RuntimeResponse {
    RuntimeResponse::Error(ErrorDto {
        code: code.to_owned(),
        message: message.to_owned(),
    })
}

fn request_id_from_payload(payload: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct RequestIDOnly {
        #[serde(default, rename = "requestId")]
        request_id: Option<String>,
    }

    serde_json::from_slice::<RequestIDOnly>(payload)
        .ok()?
        .request_id
        .filter(|request_id| request_id.len() <= MAX_REQUEST_ID_BYTES)
}

fn encode_response(response: RuntimeResponse, request_id: Option<&str>) -> Zeroizing<Vec<u8>> {
    #[derive(Serialize)]
    struct ResponseWithRequestID<'a> {
        #[serde(flatten)]
        response: &'a RuntimeResponse,
        #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
        request_id: Option<&'a str>,
    }

    Zeroizing::new(
        serde_json::to_vec(&ResponseWithRequestID {
            response: &response,
            request_id,
        })
        .unwrap_or_else(|_| {
            br#"{"type":"error","code":"encoding_failed","message":"resident response encoding failed"}"#
                .to_vec()
        }),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use serde_json::{Value, json};
    use zeroize::Zeroizing;

    use super::{MAX_RESIDENT_PROTOCOL_MESSAGE_BYTES, ResidentProtocolSession};
    use crate::Runtime;
    use crate::runtime::resident_browser_command_requires_fresh_verification;
    use vaultkern_runtime_protocol::RuntimeCommand;

    fn send(
        session: &mut ResidentProtocolSession,
        runtime: &mut Runtime,
        value: Value,
        canceled: &AtomicBool,
    ) -> Value {
        let bytes = serde_json::to_vec(&value).unwrap();
        serde_json::from_slice(&session.handle_message(runtime, Zeroizing::new(bytes), canceled))
            .unwrap()
    }

    #[test]
    fn handshake_is_required_and_request_ids_are_preserved() {
        let mut runtime = Runtime::for_tests();
        let mut session = ResidentProtocolSession::new();
        let canceled = AtomicBool::new(false);

        let before = send(
            &mut session,
            &mut runtime,
            json!({
                "version": 1,
                "requestId": "before",
                "command": { "type": "get_session_state" }
            }),
            &canceled,
        );
        assert_eq!(before["code"], "handshake_required");
        assert_eq!(before["requestId"], "before");

        let handshake = send(
            &mut session,
            &mut runtime,
            json!({
                "version": 1,
                "requestId": "handshake",
                "command": {
                    "type": "handshake",
                    "protocol_version": 1,
                    "capabilities": [
                        "runtime-core",
                        "browser-extension",
                        "resident-app"
                    ]
                }
            }),
            &canceled,
        );
        assert_eq!(handshake["type"], "handshake");
        assert_eq!(handshake["requestId"], "handshake");
        assert_eq!(
            handshake["capabilities"],
            json!(["runtime-core", "browser-extension"])
        );

        let state = send(
            &mut session,
            &mut runtime,
            json!({
                "version": 1,
                "requestId": "state",
                "command": { "type": "get_session_state" }
            }),
            &canceled,
        );
        assert_eq!(state["type"], "session_state");
        assert_eq!(state["requestId"], "state");
    }

    #[test]
    fn canceled_requests_never_reach_runtime_dispatch() {
        let mut runtime = Runtime::for_tests();
        let mut session = ResidentProtocolSession::new();
        let canceled = AtomicBool::new(false);
        let _ = send(
            &mut session,
            &mut runtime,
            json!({
                "version": 1,
                "command": {
                    "type": "handshake",
                    "protocol_version": 1,
                    "capabilities": ["runtime-core", "browser-extension"]
                }
            }),
            &canceled,
        );
        canceled.store(true, std::sync::atomic::Ordering::Release);

        let response = send(
            &mut session,
            &mut runtime,
            json!({
                "version": 1,
                "requestId": "canceled",
                "command": { "type": "lock_session" }
            }),
            &canceled,
        );
        assert_eq!(response["code"], "request_canceled");
        assert_eq!(response["requestId"], "canceled");
    }

    #[test]
    fn oversized_payload_is_refused_without_allocation_from_declared_framing() {
        let mut runtime = Runtime::for_tests();
        let mut session = ResidentProtocolSession::new();
        let response = session.handle_message(
            &mut runtime,
            Zeroizing::new(vec![b' '; MAX_RESIDENT_PROTOCOL_MESSAGE_BYTES + 1]),
            &AtomicBool::new(false),
        );
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["code"], "invalid_request");
    }

    #[test]
    fn browser_uv_classifier_covers_policy_changes_without_reprompting_internal_uv() {
        assert!(resident_browser_command_requires_fresh_verification(
            &RuntimeCommand::DisableQuickUnlockForCurrentVault
        ));
        assert!(resident_browser_command_requires_fresh_verification(
            &RuntimeCommand::CompletePendingOneDriveLogin
        ));
        assert!(!resident_browser_command_requires_fresh_verification(
            &RuntimeCommand::UnlockCurrentVaultWithQuickUnlock
        ));
        assert!(!resident_browser_command_requires_fresh_verification(
            &RuntimeCommand::GetSessionState
        ));
    }
}
