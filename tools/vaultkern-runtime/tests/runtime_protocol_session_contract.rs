use vaultkern_runtime::{RuntimeProtocolDispatch, RuntimeProtocolSession};
use vaultkern_runtime_protocol::{PROTOCOL_VERSION, RuntimeCommand, RuntimeResponse};

fn handshake(
    session: &mut RuntimeProtocolSession,
    capabilities: &[&str],
) -> vaultkern_runtime_protocol::HandshakeDto {
    let RuntimeProtocolDispatch::Respond(RuntimeResponse::Handshake(response)) =
        session.accept(RuntimeCommand::Handshake {
            protocol_version: PROTOCOL_VERSION,
            capabilities: capabilities
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
        })
    else {
        panic!("handshake must be answered by the protocol session");
    };
    response
}

fn error_code(dispatch: RuntimeProtocolDispatch) -> String {
    let RuntimeProtocolDispatch::Respond(RuntimeResponse::Error(error)) = dispatch else {
        panic!("protocol rejection must be returned as a typed error");
    };
    error.code
}

#[test]
fn desktop_and_browser_handshakes_are_independent_over_one_shared_runtime() {
    let mut desktop = RuntimeProtocolSession::resident_app();
    let mut browser = RuntimeProtocolSession::browser_extension();

    let desktop_handshake = handshake(
        &mut desktop,
        &["runtime-core", "resident-app", "quick-unlock"],
    );
    assert!(
        desktop_handshake
            .capabilities
            .contains(&"resident-app".into())
    );
    assert!(
        !desktop_handshake
            .capabilities
            .contains(&"browser-extension".into())
    );

    assert_eq!(
        error_code(browser.accept(RuntimeCommand::GetSessionState)),
        "protocol_handshake_required",
        "another client's handshake must never authorize this browser connection"
    );

    let browser_handshake = handshake(
        &mut browser,
        &["runtime-core", "browser-extension", "quick-unlock"],
    );
    assert!(
        browser_handshake
            .capabilities
            .contains(&"browser-extension".into())
    );
    assert!(
        browser_handshake
            .capabilities
            .contains(&"quick-unlock".into())
    );
    assert!(
        !browser_handshake
            .capabilities
            .contains(&"resident-app".into())
    );
    assert!(matches!(
        browser.accept(RuntimeCommand::UnlockCurrentVaultWithQuickUnlock),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::UnlockCurrentVaultWithQuickUnlock)
    ));
}

#[test]
fn every_browser_connection_requires_its_own_handshake() {
    let mut first = RuntimeProtocolSession::browser_extension();
    let mut second = RuntimeProtocolSession::browser_extension();

    handshake(&mut first, &["runtime-core", "browser-extension"]);
    assert!(matches!(
        first.accept(RuntimeCommand::GetSessionState),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::GetSessionState)
    ));
    assert_eq!(
        error_code(second.accept(RuntimeCommand::GetSessionState)),
        "protocol_handshake_required"
    );
}

#[test]
fn a_session_rejects_commands_outside_its_negotiated_capabilities() {
    let mut browser = RuntimeProtocolSession::browser_extension();
    handshake(&mut browser, &["runtime-core", "browser-extension"]);

    assert_eq!(
        error_code(browser.accept(RuntimeCommand::UnlockCurrentVaultWithQuickUnlock)),
        "capability_not_negotiated"
    );
}
