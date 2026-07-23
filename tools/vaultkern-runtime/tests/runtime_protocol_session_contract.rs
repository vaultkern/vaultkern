use vaultkern_runtime::{RuntimeProtocolDispatch, RuntimeProtocolSession};
use vaultkern_runtime_protocol::{
    PROTOCOL_VERSION, PasskeyCeremonyPhaseDto, PasskeyUserVerificationMethodDto,
    ResidentAppRouteDto, RuntimeCommand, RuntimeResponse,
};

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
        &[
            "runtime-core",
            "browser-extension",
            "browser-autofill",
            "passkey-ceremonies",
            "quick-unlock",
        ],
    );
    assert!(
        browser_handshake
            .capabilities
            .contains(&"browser-extension".into())
    );
    assert!(
        browser_handshake
            .capabilities
            .contains(&"browser-autofill".into())
    );
    assert!(
        !browser_handshake
            .capabilities
            .contains(&"quick-unlock".into())
    );
    assert!(
        !browser_handshake
            .capabilities
            .contains(&"resident-app".into())
    );
    assert_eq!(
        error_code(browser.accept(RuntimeCommand::UnlockCurrentVaultWithQuickUnlock)),
        "browser_command_forbidden"
    );
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
        error_code(browser.accept(RuntimeCommand::GetPasskeyUserVerificationCapability)),
        "capability_not_negotiated"
    );
}

#[test]
fn browser_clients_are_limited_to_status_autofill_and_passkey_commands() {
    let mut browser = RuntimeProtocolSession::browser_extension();
    handshake(
        &mut browser,
        &[
            "runtime-core",
            "browser-extension",
            "browser-autofill",
            "passkey-ceremonies",
        ],
    );

    for forbidden in [
        RuntimeCommand::ListRecentVaults,
        RuntimeCommand::UnlockCurrentVault {
            password: Some("secret".into()),
            key_file_path: None,
        },
        RuntimeCommand::ListGroups {
            vault_id: "vault-1".into(),
        },
        RuntimeCommand::ListEntries {
            vault_id: "vault-1".into(),
        },
        RuntimeCommand::GetEntryDetail {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
        },
        RuntimeCommand::GetDatabaseSettings {
            vault_id: "vault-1".into(),
        },
        RuntimeCommand::VerifyPasskeyUser {
            ceremony_token: "ceremony-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: "vault-1".into(),
            method: PasskeyUserVerificationMethodDto::MasterPassword,
            password: Some("secret".into()),
        },
    ] {
        assert_eq!(
            error_code(browser.accept(forbidden)),
            "browser_command_forbidden"
        );
    }

    assert!(matches!(
        browser.accept(RuntimeCommand::GetSessionState),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::GetSessionState)
    ));
    assert!(matches!(
        browser.accept(RuntimeCommand::GetBrowserIntegrationSettings),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::GetBrowserIntegrationSettings)
    ));
    assert!(matches!(
        browser.accept(RuntimeCommand::FindFillCandidates {
            vault_id: "vault-1".into(),
            url: "https://example.com/login".into(),
        }),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::FindFillCandidates { .. })
    ));
    assert!(matches!(
        browser.accept(RuntimeCommand::GetAutofillCredential {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            url: "https://example.com/login".into(),
        }),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::GetAutofillCredential { .. })
    ));
    assert!(matches!(
        browser.accept(RuntimeCommand::GetAutofillEntryFields {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            url: "https://example.com/login".into(),
        }),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::GetAutofillEntryFields { .. })
    ));
    assert!(matches!(
        browser.accept(RuntimeCommand::GetAutofillCreateContext {
            vault_id: "vault-1".into(),
        }),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::GetAutofillCreateContext { .. })
    ));
    assert!(matches!(
        browser.accept(RuntimeCommand::ActivateResidentApp {
            route: ResidentAppRouteDto::Unlock,
        }),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::ActivateResidentApp { .. })
    ));
    assert!(matches!(
        browser.accept(RuntimeCommand::VerifyPasskeyUser {
            ceremony_token: "ceremony-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: "vault-1".into(),
            method: PasskeyUserVerificationMethodDto::QuickUnlock,
            password: None,
        }),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::VerifyPasskeyUser { .. })
    ));
    assert!(matches!(
        browser.accept(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "ceremony-1".into(),
            connection_id: "connection-1".into(),
            origin: "https://example.com".into(),
            top_origin: None,
            ancestor_origins: Vec::new(),
            relying_party: "example.com".into(),
            ceremony: vaultkern_runtime_protocol::PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification:
                vaultkern_runtime_protocol::PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "challenge".into(),
            request_id: 1,
            tab_id: 2,
            frame_id: 0,
            frame_kind: vaultkern_runtime_protocol::PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 1,
            expires_at_epoch_ms: 2,
        }),
        RuntimeProtocolDispatch::Dispatch(RuntimeCommand::RegisterPasskeyCeremony { .. })
    ));
}
