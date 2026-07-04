use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use vaultkern_core::{CompositeKey, KeepassCore, SaveProfile, Vault};
use vaultkern_runtime::Runtime;
use vaultkern_runtime_protocol::{
    PasskeyCeremonyAdvancedDto, PasskeyCeremonyDeliveryStateDto, PasskeyCeremonyDurableStateDto,
    PasskeyCeremonyKindDto, PasskeyCeremonyLedgerDto, PasskeyCeremonyPhaseDto,
    PasskeyCeremonyRegisteredDto, PasskeyFrameKindDto, PasskeyUserVerificationRequirementDto,
    RuntimeCommand, RuntimeResponse,
};

#[test]
fn runtime_phase_graph_uses_shared_active_transition_contract() {
    let runtime_source = include_str!("../src/runtime.rs");
    assert!(
        runtime_source.contains("passkey_ceremony_transitions.json"),
        "runtime phase graph must include the shared active transition contract"
    );
}

#[test]
fn runtime_registers_and_queries_passkey_ceremony_ledger() {
    let mut runtime = Runtime::for_tests_at(100);

    let unknown = runtime
        .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
            ceremony_token: "token-1".into(),
        })
        .unwrap();
    assert_eq!(
        unknown,
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: false,
            phase: None,
            durable_state: None,
            delivery_state: None,
        })
    );

    let registered = runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
    assert_eq!(
        registered,
        RuntimeResponse::PasskeyCeremonyRegistered(PasskeyCeremonyRegisteredDto {
            registered: true,
        })
    );

    let queried = runtime
        .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
            ceremony_token: "token-1".into(),
        })
        .unwrap();
    assert_eq!(
        queried,
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::PreAuthorization),
            durable_state: Some(PasskeyCeremonyDurableStateDto::None),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_treats_exact_duplicate_passkey_ceremony_registration_as_noop() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();

    let duplicate = runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
    assert_eq!(
        duplicate,
        RuntimeResponse::PasskeyCeremonyRegistered(PasskeyCeremonyRegisteredDto {
            registered: true,
        })
    );

    let queried = runtime
        .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
            ceremony_token: "token-1".into(),
        })
        .unwrap();
    assert_eq!(
        queried,
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::UserAuthorization),
            durable_state: Some(PasskeyCeremonyDurableStateDto::None),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_rejects_duplicate_passkey_ceremony_registration_with_changed_identity() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
    let error = runtime
        .handle(register_command(
            "token-1",
            "https://evil.example.com",
            301_000,
        ))
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony token already registered")
    );
}

#[test]
fn runtime_rejects_duplicate_passkey_ceremony_registration_with_extended_ttl() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            200_000,
        ))
        .unwrap();
    let error = runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            250_000,
        ))
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony token already registered")
    );
}

#[test]
fn runtime_rejects_explicit_passkey_vault_binding_before_user_authorization() {
    let mut runtime = Runtime::for_tests_at(100);
    let vault_id = open_unlocked_test_vault(&mut runtime, "pre-auth-bind");

    runtime
        .handle(register_command(
            "token-pre-auth-bind",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();

    let error = runtime
        .handle(RuntimeCommand::BindPasskeyCeremonyVault {
            ceremony_token: "token-pre-auth-bind".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            vault_id,
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony phase mismatch"),
        "unexpected error: {error}"
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-pre-auth-bind".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::PreAuthorization),
            durable_state: Some(PasskeyCeremonyDurableStateDto::None),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_rejects_explicit_passkey_vault_binding_unknown_token_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);

    let error = runtime
        .handle(RuntimeCommand::BindPasskeyCeremonyVault {
            ceremony_token: "token-missing-bind".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: "missing-vault".into(),
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony not registered: token-missing-bind"),
        "unexpected error: {error}"
    );
}

#[test]
fn runtime_rejects_explicit_passkey_vault_rebinding_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);
    let vault_id = open_unlocked_test_vault(&mut runtime, "explicit-bind");

    runtime
        .handle(register_command(
            "token-explicit-rebind",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-explicit-rebind".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::BindPasskeyCeremonyVault {
            ceremony_token: "token-explicit-rebind".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id,
        })
        .unwrap();

    let error = runtime
        .handle(RuntimeCommand::BindPasskeyCeremonyVault {
            ceremony_token: "token-explicit-rebind".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: "missing-vault".into(),
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony vault mismatch"),
        "unexpected error: {error}"
    );
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_public_suffix_rp_id() {
    let mut runtime = Runtime::for_tests_at(100);

    for (token, origin, relying_party) in [
        ("token-public-suffix-com", "https://attacker.com", "com"),
        (
            "token-public-suffix-co-uk",
            "https://attacker.co.uk",
            "co.uk",
        ),
        (
            "token-whitespace-rp",
            "https://login.example.com",
            " example.com",
        ),
        (
            "token-noncanonical-rp",
            "https://login.example.com",
            "Example.COM",
        ),
        (
            "token-trailing-dot-rp",
            "https://login.example.com",
            "example.com.",
        ),
    ] {
        let error = runtime
            .handle(register_command_with(
                token,
                PasskeyCeremonyKindDto::Get,
                origin,
                relying_party,
                "Y2hhbGxlbmdl",
                1_000,
                301_000,
            ))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("invalid passkey relying party id"),
            "unexpected error for {relying_party}: {error}"
        );
    }
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_insecure_origin() {
    let mut runtime = Runtime::for_tests_at(100);

    let error = runtime
        .handle(register_command_with(
            "token-insecure-origin",
            PasskeyCeremonyKindDto::Get,
            "http://example.com",
            "example.com",
            "Y2hhbGxlbmdl",
            1_000,
            301_000,
        ))
        .unwrap_err();

    assert!(error.to_string().contains("passkey origin must use https"));
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_ip_relying_party_mismatch() {
    let mut runtime = Runtime::for_tests_at(100);

    let error = runtime
        .handle(register_command_with(
            "token-ip-mismatch",
            PasskeyCeremonyKindDto::Get,
            "https://127.0.0.1",
            "192.0.2.1",
            "Y2hhbGxlbmdl",
            1_000,
            301_000,
        ))
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey origin does not match relying party")
    );
}

#[test]
fn runtime_allows_https_loopback_ceremony_to_skip_network_validation() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command_with(
            "token-https-localhost",
            PasskeyCeremonyKindDto::Get,
            "https://localhost",
            "localhost",
            "Y2hhbGxlbmdl",
            1_000,
            301_000,
        ))
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-https-localhost".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();

    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-https-localhost".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap();
}

#[test]
fn runtime_allows_bracketed_ipv6_loopback_ceremony_to_skip_network_validation() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command_with(
            "token-http-ipv6-loopback",
            PasskeyCeremonyKindDto::Get,
            "http://[::1]:8877",
            "::1",
            "Y2hhbGxlbmdl",
            1_000,
            301_000,
        ))
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-http-ipv6-loopback".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();

    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-http-ipv6-loopback".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap();
}

#[test]
fn runtime_rejects_concurrent_passkey_ceremonies_for_same_origin_rp_tab_and_frame() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();

    let concurrent = runtime
        .handle(register_command(
            "token-2",
            "https://login.example.com",
            301_000,
        ))
        .unwrap_err();
    assert!(
        concurrent
            .to_string()
            .contains("passkey ceremony already active for origin, relying party, tab, and frame")
    );

    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::ClosedAborted,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(register_command(
            "token-3",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
}

#[test]
fn runtime_allows_concurrent_passkey_ceremonies_for_different_tabs() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();

    runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-2".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: None,
            ancestor_origins: vec![],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 43,
            tab_id: 8,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap();
}

#[test]
fn runtime_allows_concurrent_passkey_ceremonies_for_different_frames_in_same_tab() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();

    runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-2".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: Some("https://login.example.com".into()),
            ancestor_origins: vec!["https://login.example.com".into()],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 43,
            tab_id: 7,
            frame_id: 2,
            frame_kind: PasskeyFrameKindDto::Subframe,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap();
}

#[test]
fn runtime_advances_passkey_ceremony_only_along_legal_edges() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();

    let advanced = runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
    assert_eq!(
        advanced,
        RuntimeResponse::PasskeyCeremonyAdvanced(PasskeyCeremonyAdvancedDto { advanced: true })
    );

    let illegal = runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap_err();
    assert!(
        illegal
            .to_string()
            .contains("illegal passkey ceremony phase transition")
    );
}

#[test]
fn runtime_requires_network_validation_before_cross_origin_credential_resolution() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command_with(
            "token-1",
            PasskeyCeremonyKindDto::Get,
            "https://login.example.net",
            "example.com",
            "Y2hhbGxlbmdl",
            1_000,
            301_000,
        ))
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();

    let direct_s3 = runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap_err();
    assert!(
        direct_s3
            .to_string()
            .contains("illegal passkey ceremony phase transition")
    );

    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::NetworkValidation,
            related_origin_verified: false,
        })
        .unwrap();
    let missing_evidence = runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::NetworkValidation,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap_err();
    assert!(
        missing_evidence
            .to_string()
            .contains("passkey ceremony related origin evidence is required")
    );

    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::NetworkValidation,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: true,
        })
        .unwrap();
}

#[test]
fn runtime_rejects_network_validation_phase_for_same_origin_ceremony() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command(
            "token-same-origin-s2",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-same-origin-s2".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();

    let error = runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-same-origin-s2".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::NetworkValidation,
            related_origin_verified: false,
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("illegal passkey ceremony phase transition")
    );
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_invalid_ttl() {
    let mut runtime = Runtime::for_tests_at(100);

    let zero_ttl = runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            1_000,
        ))
        .unwrap_err();
    assert!(
        zero_ttl
            .to_string()
            .contains("invalid passkey ceremony ttl")
    );

    let too_long = runtime
        .handle(register_command(
            "token-2",
            "https://login.example.com",
            301_001,
        ))
        .unwrap_err();
    assert!(
        too_long
            .to_string()
            .contains("invalid passkey ceremony ttl")
    );
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_future_ttl_window() {
    let mut runtime = Runtime::for_tests_at(1);

    let error = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-future-ttl".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: None,
            ancestor_origins: vec![],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 601_000,
            expires_at_epoch_ms: 901_000,
        })
        .unwrap_err();

    assert!(error.to_string().contains("invalid passkey ceremony ttl"));
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_expired_ttl_window() {
    let mut runtime = Runtime::for_tests_at(400);

    let error = runtime
        .handle(register_command(
            "token-expired-ttl",
            "https://login.example.com",
            301_000,
        ))
        .unwrap_err();

    assert!(error.to_string().contains("invalid passkey ceremony ttl"));
}

#[test]
fn runtime_rejects_expired_passkey_ceremony_phase_advance() {
    let mut runtime = Runtime::for_tests_at(100);
    runtime
        .handle(register_command(
            "token-expired-before-advance",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
    runtime.set_test_unix_time(400);

    let error = runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-expired-before-advance".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap_err();

    assert!(
        error.to_string().contains("passkey ceremony expired"),
        "unexpected error: {error}"
    );
}

#[test]
fn runtime_rejects_expired_passkey_ceremony_vault_bind_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);
    runtime
        .handle(register_command(
            "token-expired-before-bind",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-expired-before-bind".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
    runtime.set_test_unix_time(400);

    let error = runtime
        .handle(RuntimeCommand::BindPasskeyCeremonyVault {
            ceremony_token: "token-expired-before-bind".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: "missing-vault".into(),
        })
        .unwrap_err();

    assert!(
        error.to_string().contains("passkey ceremony expired"),
        "unexpected error: {error}"
    );
    assert!(!error.to_string().contains("vault not opened"));
}

#[test]
fn runtime_rejects_expired_passkey_ceremony_s3_read_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s3(
        &mut runtime,
        "token-expired-s3-read",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );
    runtime.set_test_unix_time(400);

    let response = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "token-expired-s3-read".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony expired"));
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_expired_passkey_ceremony_s4_assertion_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-expired-s4-assertion",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );
    runtime.set_test_unix_time(400);

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-expired-s4-assertion".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony expired"));
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_expired_passkey_registration_save_before_durable_commit() {
    let mut runtime = Runtime::for_tests_at(100);
    let (vault_id, _, _) =
        create_mutated_passkey_registration(&mut runtime, "token-expired-save", "Y2hhbGxlbmdl");
    runtime.set_test_unix_time(400);

    let response = runtime
        .handle(RuntimeCommand::SavePasskeyRegistration {
            ceremony_token: "token-expired-save".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error.message.contains("passkey ceremony expired"),
        "unexpected error: {error:?}"
    );
}

#[test]
fn runtime_rejects_expired_passkey_registration_commit_before_durable_commit() {
    let mut runtime = Runtime::for_tests_at(100);
    let (vault_id, entry_id, credential_id) =
        create_mutated_passkey_registration(&mut runtime, "token-expired-commit", "Y2hhbGxlbmdl");
    runtime.set_test_unix_time(400);

    let response = runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: "token-expired-commit".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
            entry_id,
            credential_id,
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error.message.contains("passkey ceremony expired"),
        "unexpected error: {error:?}"
    );
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_malformed_challenge() {
    let mut runtime = Runtime::for_tests_at(100);

    for (token, challenge) in [
        ("token-empty-challenge", ""),
        ("token-invalid-challenge", "!!!"),
    ] {
        let error = runtime
            .handle(register_command_with(
                token,
                PasskeyCeremonyKindDto::Get,
                "https://login.example.com",
                "example.com",
                challenge,
                1_000,
                301_000,
            ))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("invalid passkey ceremony challenge"),
            "unexpected error for challenge {challenge:?}: {error}"
        );
    }
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_non_origin_origin() {
    let mut runtime = Runtime::for_tests_at(100);

    for (token, origin) in [
        ("token-origin-path", "https://login.example.com/path"),
        ("token-origin-query", "https://login.example.com?debug=true"),
        ("token-origin-fragment", "https://login.example.com#frag"),
        ("token-origin-userinfo", "https://user@login.example.com"),
        ("token-origin-leading-space", " https://login.example.com"),
        ("token-origin-trailing-space", "https://login.example.com "),
    ] {
        let error = runtime
            .handle(register_command_with(
                token,
                PasskeyCeremonyKindDto::Get,
                origin,
                "example.com",
                "Y2hhbGxlbmdl",
                1_000,
                301_000,
            ))
            .unwrap_err();

        assert!(
            error.to_string().contains("invalid passkey origin"),
            "unexpected error for origin {origin:?}: {error}"
        );
    }
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_non_origin_top_origin() {
    let mut runtime = Runtime::for_tests_at(100);

    let error = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-top-origin-path".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: Some("https://container.example.net/path".into()),
            ancestor_origins: vec!["https://container.example.net/path".into()],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 2,
            frame_kind: PasskeyFrameKindDto::Subframe,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("invalid passkey ceremony top origin")
    );
}

#[test]
fn runtime_rejects_loopback_passkey_ceremony_with_non_origin_top_origin() {
    let mut runtime = Runtime::for_tests_at(100);

    let error = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-loopback-top-origin-path".into(),
            connection_id: "connection-1".into(),
            origin: "http://localhost".into(),
            top_origin: Some("http://localhost/path".into()),
            ancestor_origins: vec!["http://localhost/path".into()],
            relying_party: "localhost".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 2,
            frame_kind: PasskeyFrameKindDto::Subframe,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("invalid passkey ceremony top origin")
    );
}

#[test]
fn runtime_rejects_passkey_ceremony_registration_with_insecure_ancestor_origin() {
    let mut runtime = Runtime::for_tests_at(100);

    let error = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-insecure-ancestor".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: Some("https://container.example.net".into()),
            ancestor_origins: vec![
                "http://middle.example.net".into(),
                "https://container.example.net".into(),
            ],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 2,
            frame_kind: PasskeyFrameKindDto::Subframe,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony ancestor origin must use https")
    );
}

#[test]
fn runtime_rejects_subframe_passkey_ceremony_without_top_origin() {
    let mut runtime = Runtime::for_tests_at(100);

    let command = RuntimeCommand::RegisterPasskeyCeremony {
        ceremony_token: "token-1".into(),
        connection_id: "connection-1".into(),
        origin: "https://login.example.com".into(),
        top_origin: None,
        ancestor_origins: vec![],
        relying_party: "example.com".into(),
        ceremony: PasskeyCeremonyKindDto::Get,
        discoverable: false,
        user_verification: PasskeyUserVerificationRequirementDto::Preferred,
        challenge_base64url: "Y2hhbGxlbmdl".into(),
        request_id: 42,
        tab_id: 7,
        frame_id: 2,
        frame_kind: PasskeyFrameKindDto::Subframe,
        registered_at_epoch_ms: 1_000,
        expires_at_epoch_ms: 301_000,
    };

    let error = runtime.handle(command).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony subframe top origin is required")
    );
}

#[test]
fn runtime_rejects_passkey_ceremony_with_ancestors_without_top_origin() {
    let mut runtime = Runtime::for_tests_at(100);

    let error = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-1".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: None,
            ancestor_origins: vec!["https://top.example.net".into()],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 2,
            frame_kind: PasskeyFrameKindDto::Subframe,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony top origin is required when ancestors are present")
    );
}

#[test]
fn runtime_rejects_passkey_ceremony_when_top_origin_does_not_match_last_ancestor() {
    let mut runtime = Runtime::for_tests_at(100);

    let error = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-1".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: Some("https://declared-top.example.net".into()),
            ancestor_origins: vec![
                "https://middle.example.net".into(),
                "https://actual-top.example.net".into(),
            ],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 2,
            frame_kind: PasskeyFrameKindDto::Subframe,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony top origin must match the last ancestor")
    );
}

#[test]
fn runtime_accepts_passkey_ceremony_when_top_origin_matches_last_ancestor_by_origin() {
    let mut runtime = Runtime::for_tests_at(100);

    let response = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-default-port-ancestor".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: Some("https://container.example.net".into()),
            ancestor_origins: vec![
                "https://middle.example.net".into(),
                "https://container.example.net:443".into(),
            ],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 2,
            frame_kind: PasskeyFrameKindDto::Subframe,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap();

    assert!(matches!(
        response,
        RuntimeResponse::PasskeyCeremonyRegistered(PasskeyCeremonyRegisteredDto {
            registered: true
        })
    ));
}

#[test]
fn runtime_rejects_passkey_ceremony_with_inconsistent_frame_position() {
    let mut runtime = Runtime::for_tests_at(100);

    let frame_id_subframe = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-1".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: None,
            ancestor_origins: vec![],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 2,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap_err();
    assert!(
        frame_id_subframe
            .to_string()
            .contains("passkey ceremony frame kind mismatch")
    );

    let frame_id_top = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-2".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: Some("https://login.example.com".into()),
            ancestor_origins: vec!["https://login.example.com".into()],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 43,
            tab_id: 7,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Subframe,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap_err();
    assert!(
        frame_id_top
            .to_string()
            .contains("passkey ceremony frame kind mismatch")
    );
}

#[test]
fn runtime_rejects_top_frame_passkey_ceremony_with_ancestor_origins() {
    let mut runtime = Runtime::for_tests_at(100);

    let error = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-1".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: Some("https://container.example.net".into()),
            ancestor_origins: vec!["https://container.example.net".into()],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony top frame cannot have ancestor origins")
    );
}

#[test]
fn runtime_reconciles_no_passkey_ceremonies_without_side_effects() {
    let mut runtime = Runtime::for_tests_at(100);

    let response = runtime
        .handle(RuntimeCommand::ReconcilePasskeyCeremonyLedger {
            active_connection_id: "connection-1".into(),
        })
        .unwrap();

    assert_eq!(
        response,
        RuntimeResponse::PasskeyCeremonyReconciliation(
            vaultkern_runtime_protocol::PasskeyCeremonyReconciliationDto { reconciled: vec![] }
        )
    );
}

#[test]
fn runtime_reconciliation_skips_active_committed_passkey_ceremonies() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-1", "Y2hhbGxlbmdl");

    let response = runtime
        .handle(RuntimeCommand::ReconcilePasskeyCeremonyLedger {
            active_connection_id: "connection-1".into(),
        })
        .unwrap();

    assert_eq!(
        response,
        RuntimeResponse::PasskeyCeremonyReconciliation(
            vaultkern_runtime_protocol::PasskeyCeremonyReconciliationDto { reconciled: vec![] }
        )
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-1".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::CompletionAndMutation),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_reconciliation_marks_disconnected_committed_passkey_ceremonies_unknown_delivery() {
    let mut runtime = Runtime::for_tests_at(100);
    let vault_id = open_unlocked_test_vault(&mut runtime, "token-disconnected");
    runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-disconnected".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: None,
            ancestor_origins: vec![],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Create,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 100_000,
            expires_at_epoch_ms: 400_000,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-disconnected".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::BindPasskeyCeremonyVault {
            ceremony_token: "token-disconnected".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: vault_id.clone(),
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-disconnected".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-disconnected".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();
    let client_data = br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://login.example.com","crossOrigin":false}"#;
    let registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "token-disconnected".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(registration) = registration else {
        panic!("expected passkey registration, got {registration:?}");
    };
    runtime
        .handle(RuntimeCommand::SavePasskeyRegistration {
            ceremony_token: "token-disconnected".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: vault_id.clone(),
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: "token-disconnected".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
            entry_id: registration.entry_id,
            credential_id: registration.credential_id,
        })
        .unwrap();

    let response = runtime
        .handle(RuntimeCommand::ReconcilePasskeyCeremonyLedger {
            active_connection_id: "connection-2".into(),
        })
        .unwrap();

    assert_eq!(
        response,
        RuntimeResponse::PasskeyCeremonyReconciliation(
            vaultkern_runtime_protocol::PasskeyCeremonyReconciliationDto {
                reconciled: vec![vaultkern_runtime_protocol::PasskeyCeremonyReconciledDto {
                    ceremony_token: "token-disconnected".into(),
                    delivery_state: PasskeyCeremonyDeliveryStateDto::UnknownDelivery,
                }],
            }
        )
    );
}

#[test]
fn runtime_reconciliation_before_new_tab_ceremony_keeps_unexpired_committed_ceremony() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-committed", "Y2hhbGxlbmdl");

    let reconciliation = runtime
        .handle(RuntimeCommand::ReconcilePasskeyCeremonyLedger {
            active_connection_id: "connection-1".into(),
        })
        .unwrap();
    assert_eq!(
        reconciliation,
        RuntimeResponse::PasskeyCeremonyReconciliation(
            vaultkern_runtime_protocol::PasskeyCeremonyReconciliationDto { reconciled: vec![] }
        )
    );

    let registered = runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-new-tab".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: None,
            ancestor_origins: vec![],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdlLTI".into(),
            request_id: 43,
            tab_id: 8,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 100_000,
            expires_at_epoch_ms: 400_000,
        })
        .unwrap();
    assert_eq!(
        registered,
        RuntimeResponse::PasskeyCeremonyRegistered(PasskeyCeremonyRegisteredDto {
            registered: true,
        })
    );

    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-committed".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::CompletionAndMutation),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_reconciliation_marks_expired_committed_passkey_ceremonies_unknown_delivery() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-1", "Y2hhbGxlbmdl");
    runtime.set_test_unix_time(400);

    let response = runtime
        .handle(RuntimeCommand::ReconcilePasskeyCeremonyLedger {
            active_connection_id: "connection-1".into(),
        })
        .unwrap();

    assert_eq!(
        response,
        RuntimeResponse::PasskeyCeremonyReconciliation(
            vaultkern_runtime_protocol::PasskeyCeremonyReconciliationDto {
                reconciled: vec![vaultkern_runtime_protocol::PasskeyCeremonyReconciledDto {
                    ceremony_token: "token-1".into(),
                    delivery_state: PasskeyCeremonyDeliveryStateDto::UnknownDelivery,
                }],
            }
        )
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-1".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedDelivered),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::UnknownDelivery),
        })
    );
}

#[test]
fn runtime_reconciliation_rolls_back_expired_saved_uncommitted_passkey_ceremonies() {
    let mut runtime = Runtime::for_tests_at(100);
    let (vault_id, _, _) = create_mutated_passkey_registration(
        &mut runtime,
        "token-saved-uncommitted",
        "Y2hhbGxlbmdl",
    );
    runtime
        .handle(RuntimeCommand::SavePasskeyRegistration {
            ceremony_token: "token-saved-uncommitted".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
        })
        .unwrap();
    runtime.set_test_unix_time(400);

    let response = runtime
        .handle(RuntimeCommand::ReconcilePasskeyCeremonyLedger {
            active_connection_id: "connection-1".into(),
        })
        .unwrap();

    assert_eq!(
        response,
        RuntimeResponse::PasskeyCeremonyReconciliation(
            vaultkern_runtime_protocol::PasskeyCeremonyReconciliationDto {
                reconciled: vec![vaultkern_runtime_protocol::PasskeyCeremonyReconciledDto {
                    ceremony_token: "token-saved-uncommitted".into(),
                    delivery_state: PasskeyCeremonyDeliveryStateDto::NotDelivered,
                }],
            }
        )
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-saved-uncommitted".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedFailed),
            durable_state: Some(PasskeyCeremonyDurableStateDto::None),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_reconciliation_reports_committed_ceremonies_when_a_later_rollback_fails() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-committed", "Y2hhbGxlbmdlMQ");
    create_mutated_passkey_registration_with_origin(
        &mut runtime,
        "token-uncommitted-locked",
        "Y2hhbGxlbmdlMg",
        "https://login2.example.com",
    );
    runtime.set_test_unix_time(400);
    runtime.lock_session();

    let response = runtime
        .handle(RuntimeCommand::ReconcilePasskeyCeremonyLedger {
            active_connection_id: "connection-1".into(),
        })
        .unwrap();

    assert_eq!(
        response,
        RuntimeResponse::PasskeyCeremonyReconciliation(
            vaultkern_runtime_protocol::PasskeyCeremonyReconciliationDto {
                reconciled: vec![vaultkern_runtime_protocol::PasskeyCeremonyReconciledDto {
                    ceremony_token: "token-committed".into(),
                    delivery_state: PasskeyCeremonyDeliveryStateDto::UnknownDelivery,
                }],
            }
        )
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-committed".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedDelivered),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::UnknownDelivery),
        })
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-uncommitted-locked".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::CompletionAndMutation),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Mutated),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_reconciliation_preserves_expired_delivered_passkey_ceremonies() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-1", "Y2hhbGxlbmdl");
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            next_phase: PasskeyCeremonyPhaseDto::ClosedDelivered,
            related_origin_verified: false,
        })
        .unwrap();
    runtime.set_test_unix_time(400);

    let response = runtime
        .handle(RuntimeCommand::ReconcilePasskeyCeremonyLedger {
            active_connection_id: "connection-1".into(),
        })
        .unwrap();

    assert_eq!(
        response,
        RuntimeResponse::PasskeyCeremonyReconciliation(
            vaultkern_runtime_protocol::PasskeyCeremonyReconciliationDto { reconciled: vec![] }
        )
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-1".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedDelivered),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::Delivered),
        })
    );
}

#[test]
fn runtime_prunes_expired_closed_passkey_ceremonies_before_registration() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-closed-expired", "Y2hhbGxlbmdl");
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-closed-expired".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            next_phase: PasskeyCeremonyPhaseDto::ClosedDelivered,
            related_origin_verified: false,
        })
        .unwrap();
    runtime.set_test_unix_time(400);

    runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "token-new-after-prune".into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: None,
            ancestor_origins: vec![],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdlLTI".into(),
            request_id: 43,
            tab_id: 8,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 400_000,
            expires_at_epoch_ms: 700_000,
        })
        .unwrap();

    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-closed-expired".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: false,
            phase: None,
            durable_state: None,
            delivery_state: None,
        })
    );
}

#[test]
fn runtime_rejects_passkey_assertion_with_unknown_ceremony_token_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "missing-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: "e30".into(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony not registered"));
}

#[test]
fn runtime_rejects_passkey_assertion_without_user_presence_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "assertion-no-presence-token",
        PasskeyCeremonyKindDto::Get,
        "https://example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-no-presence-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com","crossOrigin":false}"#,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey user presence was not verified"),
        "unexpected error: {error:?}"
    );
}

#[test]
fn runtime_rejects_passkey_registration_with_unknown_ceremony_token_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "missing-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: "e30".into(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony not registered"));
}

#[test]
fn runtime_rejects_passkey_registration_with_get_ceremony_token() {
    let mut runtime = Runtime::for_tests_at(100);

    runtime
        .handle(register_command(
            "token-1",
            "https://login.example.com",
            301_000,
        ))
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: "e30".into(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony type mismatch"));
}

#[test]
fn runtime_rejects_passkey_abort_with_get_ceremony_token() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-1",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony type mismatch"));
}

#[test]
fn runtime_rejects_token_bound_passkey_registration_controls_with_unknown_ceremony_token() {
    let commands = [
        RuntimeCommand::SavePasskeyRegistration {
            ceremony_token: "missing-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
        },
        RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: "missing-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            entry_id: "entry-1".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
        },
        RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "missing-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        },
        RuntimeCommand::MarkPasskeyCeremonyUnknownDelivery {
            ceremony_token: "missing-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        },
    ];

    for command in commands {
        let mut runtime = Runtime::for_tests_at(100);
        let response = runtime.handle(command).unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected error response, got {response:?}");
        };
        assert!(error.message.contains("passkey ceremony not registered"));
    }
}

#[test]
fn runtime_rejects_passkey_registration_commit_without_rollback_state() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-missing-rollback",
        PasskeyCeremonyKindDto::Create,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: "token-missing-rollback".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey registration rollback state missing")
    );
}

#[test]
fn runtime_rejects_passkey_assertion_when_ceremony_origin_is_changed() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-1",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://evil.example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://evil.example.com",
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony origin mismatch"));
}

#[test]
fn runtime_accepts_client_data_origin_that_matches_ceremony_origin_by_origin() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-get-origin-default-port",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com:443",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-get-origin-default-port".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com:443".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error.message.contains("vault not opened"),
        "unexpected error: {error:?}"
    );
    assert!(!error.message.contains("clientDataJSON"));
}

#[test]
fn runtime_rejects_passkey_assertion_when_ceremony_challenge_is_changed() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-get-challenge",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-get-challenge".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json(
                "webauthn.get",
                "b3RoZXItY2hhbGxlbmdl",
                "https://login.example.com",
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony challenge mismatch")
    );
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_passkey_registration_when_ceremony_challenge_is_changed() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-1",
        PasskeyCeremonyKindDto::Create,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json(
                "webauthn.create",
                "b3RoZXItY2hhbGxlbmdl",
                "https://login.example.com",
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony challenge mismatch")
    );
}

#[test]
fn runtime_rejects_passkey_registration_when_ceremony_relying_party_is_changed() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-1",
        PasskeyCeremonyKindDto::Create,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "evil.example.com".into(),
            origin: "https://login.example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json(
                "webauthn.create",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony relying party mismatch")
    );
}

#[test]
fn runtime_rejects_passkey_registration_with_unsupported_public_key_algorithm_before_vault_lookup()
{
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-unsupported-alg",
        PasskeyCeremonyKindDto::Create,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "token-unsupported-alg".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -257,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json(
                "webauthn.create",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("unsupported passkey public key algorithm")
    );
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_passkey_credential_list_with_unknown_ceremony_token_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);

    let response = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "missing-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony not registered"));
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_passkey_credential_status_with_unknown_ceremony_token_before_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);

    let response = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "missing-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: "missing-vault".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony not registered"));
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_passkey_credential_list_with_create_ceremony_token() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s3(
        &mut runtime,
        "token-create",
        PasskeyCeremonyKindDto::Create,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "token-create".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony type mismatch"));
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_passkey_credential_status_with_get_ceremony_token() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s3(
        &mut runtime,
        "token-get",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "token-get".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: "missing-vault".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(error.message.contains("passkey ceremony type mismatch"));
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_passkey_assertion_when_cross_origin_client_data_is_missing() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4_with_top_origin(
        &mut runtime,
        "token-1",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        Some("https://container.example.net"),
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony clientDataJSON crossOrigin mismatch")
    );
}

#[test]
fn runtime_rejects_passkey_assertion_when_cross_origin_client_data_omits_top_origin() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4_with_frame(
        &mut runtime,
        "token-1",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        Some("https://login.example.com"),
        vec![
            "https://middle.example.net".into(),
            "https://login.example.com".into(),
        ],
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json_with_frame(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
                true,
                None,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony clientDataJSON topOrigin mismatch")
    );
}

#[test]
fn runtime_accepts_same_origin_client_data_with_default_port_top_origin() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4_with_top_origin(
        &mut runtime,
        "token-default-port-top-origin",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        Some("https://login.example.com:443"),
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-default-port-top-origin".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error.message.contains("vault not opened"),
        "unexpected error: {error:?}"
    );
    assert!(!error.message.contains("clientDataJSON"));
}

#[test]
fn runtime_rejects_passkey_assertion_when_same_origin_client_data_has_null_top_origin() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-null-top-origin",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-null-top-origin".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json_with_null_top_origin(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
                false,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony clientDataJSON topOrigin mismatch")
    );
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_passkey_registration_when_same_origin_client_data_has_null_top_origin() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-create-null-top-origin",
        PasskeyCeremonyKindDto::Create,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "token-create-null-top-origin".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json_with_null_top_origin(
                "webauthn.create",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
                false,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony clientDataJSON topOrigin mismatch")
    );
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_rejects_passkey_registration_when_client_data_top_origin_differs() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4_with_top_origin(
        &mut runtime,
        "token-1",
        PasskeyCeremonyKindDto::Create,
        "https://login.example.com",
        Some("https://container.example.net"),
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json_with_frame(
                "webauthn.create",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
                true,
                Some("https://other.example.net"),
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony clientDataJSON topOrigin mismatch")
    );
}

#[test]
fn runtime_rejects_passkey_assertion_when_client_data_top_origin_is_not_an_origin() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4_with_top_origin(
        &mut runtime,
        "token-client-top-origin-path",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        Some("https://container.example.net"),
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-client-top-origin-path".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json_with_frame(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
                true,
                Some("https://container.example.net/path"),
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony clientDataJSON topOrigin mismatch")
    );
    assert!(!error.message.contains("vault not opened"));
}

#[test]
fn runtime_accepts_cross_origin_client_data_with_default_port_top_origin() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4_with_top_origin(
        &mut runtime,
        "token-cross-origin-default-port-top-origin",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        Some("https://container.example.net:443"),
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "token-cross-origin-default-port-top-origin".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            relying_party: "example.com".into(),
            origin: "https://login.example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json_with_frame(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://login.example.com",
                true,
                Some("https://container.example.net"),
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error response, got {response:?}");
    };
    assert!(
        error.message.contains("vault not opened"),
        "unexpected error: {error:?}"
    );
    assert!(!error.message.contains("clientDataJSON"));
}

#[test]
fn runtime_marks_passkey_registration_ceremony_committed_from_commit_token() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-1", "Y2hhbGxlbmdl");

    let queried = runtime
        .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
            ceremony_token: "token-1".into(),
        })
        .unwrap();

    assert_eq!(
        queried,
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::CompletionAndMutation),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_marks_passkey_ceremony_delivered_when_closed_delivered() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-1",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            next_phase: PasskeyCeremonyPhaseDto::ClosedDelivered,
            related_origin_verified: false,
        })
        .unwrap();

    let queried = runtime
        .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
            ceremony_token: "token-1".into(),
        })
        .unwrap();

    assert_eq!(
        queried,
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedDelivered),
            durable_state: Some(PasskeyCeremonyDurableStateDto::None),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::Delivered),
        })
    );
}

#[test]
fn runtime_treats_duplicate_passkey_delivery_confirmation_as_noop() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-duplicate-delivery",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-duplicate-delivery".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            next_phase: PasskeyCeremonyPhaseDto::ClosedDelivered,
            related_origin_verified: false,
        })
        .unwrap();
    let duplicate = runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-duplicate-delivery".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            next_phase: PasskeyCeremonyPhaseDto::ClosedDelivered,
            related_origin_verified: false,
        })
        .unwrap();

    assert_eq!(
        duplicate,
        RuntimeResponse::PasskeyCeremonyAdvanced(PasskeyCeremonyAdvancedDto { advanced: true })
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-duplicate-delivery".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedDelivered),
            durable_state: Some(PasskeyCeremonyDurableStateDto::None),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::Delivered),
        })
    );
}

#[test]
fn runtime_stale_delivery_confirmation_preserves_unknown_delivery_audit_state() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(
        &mut runtime,
        "token-unknown-then-stale-delivery",
        "Y2hhbGxlbmdl",
    );
    runtime
        .handle(RuntimeCommand::MarkPasskeyCeremonyUnknownDelivery {
            ceremony_token: "token-unknown-then-stale-delivery".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        })
        .unwrap();

    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-unknown-then-stale-delivery".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            next_phase: PasskeyCeremonyPhaseDto::ClosedDelivered,
            related_origin_verified: false,
        })
        .unwrap();

    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-unknown-then-stale-delivery".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedDelivered),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::UnknownDelivery),
        })
    );
}

#[test]
fn runtime_rejects_delivered_create_before_native_commit() {
    let mut runtime = Runtime::for_tests_at(100);
    let (vault_id, _, _) = create_mutated_passkey_registration(
        &mut runtime,
        "token-deliver-before-commit",
        "Y2hhbGxlbmdl",
    );
    runtime
        .handle(RuntimeCommand::SavePasskeyRegistration {
            ceremony_token: "token-deliver-before-commit".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
        })
        .unwrap();

    let error = runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-deliver-before-commit".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            next_phase: PasskeyCeremonyPhaseDto::ClosedDelivered,
            related_origin_verified: false,
        })
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("passkey ceremony must be committed before delivery"),
        "unexpected error: {error}"
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-deliver-before-commit".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::CompletionAndMutation),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Saved),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_treats_late_passkey_commit_after_closed_delivery_as_noop() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-late-commit", "Y2hhbGxlbmdl");
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-late-commit".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            next_phase: PasskeyCeremonyPhaseDto::ClosedDelivered,
            related_origin_verified: false,
        })
        .unwrap();
    let late_commit = runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: "token-late-commit".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            entry_id: "entry-1".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
        })
        .unwrap();

    assert_eq!(late_commit, RuntimeResponse::Saved);
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-late-commit".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedDelivered),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::Delivered),
        })
    );
}

#[test]
fn runtime_treats_duplicate_passkey_commit_after_durable_commit_as_noop() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-duplicate-commit", "Y2hhbGxlbmdl");

    let duplicate_commit = runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: "token-duplicate-commit".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: "missing-vault".into(),
            entry_id: "entry-1".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
        })
        .unwrap();

    assert_eq!(duplicate_commit, RuntimeResponse::Saved);
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-duplicate-commit".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::CompletionAndMutation),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_treats_late_passkey_abort_after_closed_failure_as_noop() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-late-rollback",
        PasskeyCeremonyKindDto::Create,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "token-late-rollback".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            next_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
            related_origin_verified: false,
        })
        .unwrap();
    let late_abort = runtime
        .handle(RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "token-late-rollback".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        })
        .unwrap();

    assert_eq!(late_abort, RuntimeResponse::Saved);
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-late-rollback".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedFailed),
            durable_state: Some(PasskeyCeremonyDurableStateDto::None),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_aborts_created_passkey_registration_before_entry_mutation_as_noop() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("passkey-pre-mutation-rollback");
    let vault = Vault::empty("Passkey Pre Mutation Rollback");
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save seed vault");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passkey-pre-mutation-rollback.kdbx");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = Runtime::for_tests_at(100);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-pre-mutation-rollback")
        .unwrap();
    register_and_advance_to_s4(
        &mut runtime,
        "token-pre-mutation-rollback",
        PasskeyCeremonyKindDto::Create,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let rolled_back = runtime
        .handle(RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "token-pre-mutation-rollback".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        })
        .unwrap();

    assert_eq!(rolled_back, RuntimeResponse::Saved);
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-pre-mutation-rollback".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedFailed),
            durable_state: Some(PasskeyCeremonyDurableStateDto::None),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_marks_committed_passkey_ceremony_unknown_delivery_without_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);
    create_committed_passkey_registration(&mut runtime, "token-unknown-delivery", "Y2hhbGxlbmdl");

    let marked = runtime
        .handle(RuntimeCommand::MarkPasskeyCeremonyUnknownDelivery {
            ceremony_token: "token-unknown-delivery".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        })
        .unwrap();

    assert_eq!(
        marked,
        RuntimeResponse::PasskeyCeremonyAdvanced(PasskeyCeremonyAdvancedDto { advanced: true })
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-unknown-delivery".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedDelivered),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::UnknownDelivery),
        })
    );
}

#[test]
fn runtime_marks_get_ceremony_unknown_delivery_without_commit_or_vault_lookup() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-get-unknown-delivery",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );

    let marked = runtime
        .handle(RuntimeCommand::MarkPasskeyCeremonyUnknownDelivery {
            ceremony_token: "token-get-unknown-delivery".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        })
        .unwrap();

    assert_eq!(
        marked,
        RuntimeResponse::PasskeyCeremonyAdvanced(PasskeyCeremonyAdvancedDto { advanced: true })
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-get-unknown-delivery".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::ClosedDelivered),
            durable_state: Some(PasskeyCeremonyDurableStateDto::None),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::UnknownDelivery),
        })
    );
}

#[test]
fn runtime_prunes_expired_pre_completion_passkey_ceremonies_before_registration() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s3(
        &mut runtime,
        "token-expired-s3-prune",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );
    runtime.set_test_unix_time_ms(302_000);

    runtime
        .handle(register_command_at(
            "token-new-after-expired-s3",
            "https://login.example.com",
            302_000,
            602_000,
        ))
        .unwrap();

    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-expired-s3-prune".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: false,
            phase: None,
            durable_state: None,
            delivery_state: None,
        })
    );
}

#[test]
fn runtime_prunes_expired_get_s4_passkey_ceremonies_before_registration() {
    let mut runtime = Runtime::for_tests_at(100);
    register_and_advance_to_s4(
        &mut runtime,
        "token-expired-get-s4-prune",
        PasskeyCeremonyKindDto::Get,
        "https://login.example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );
    runtime.set_test_unix_time_ms(302_000);

    runtime
        .handle(register_command_at(
            "token-new-after-expired-get-s4",
            "https://login.example.com",
            302_000,
            602_000,
        ))
        .unwrap();

    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "token-expired-get-s4-prune".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: false,
            phase: None,
            durable_state: None,
            delivery_state: None,
        })
    );
}

fn register_command(token: &str, origin: &str, expires_at_epoch_ms: u64) -> RuntimeCommand {
    register_command_at(token, origin, 1_000, expires_at_epoch_ms)
}

fn register_command_at(
    token: &str,
    origin: &str,
    registered_at_epoch_ms: u64,
    expires_at_epoch_ms: u64,
) -> RuntimeCommand {
    register_command_with(
        token,
        PasskeyCeremonyKindDto::Get,
        origin,
        "example.com",
        "Y2hhbGxlbmdl",
        registered_at_epoch_ms,
        expires_at_epoch_ms,
    )
}

fn register_command_with(
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
    registered_at_epoch_ms: u64,
    expires_at_epoch_ms: u64,
) -> RuntimeCommand {
    register_command_with_frame(
        token,
        ceremony,
        origin,
        None,
        vec![],
        relying_party,
        challenge_base64url,
        registered_at_epoch_ms,
        expires_at_epoch_ms,
    )
}

fn register_command_with_frame(
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    top_origin: Option<&str>,
    ancestor_origins: Vec<String>,
    relying_party: &str,
    challenge_base64url: &str,
    registered_at_epoch_ms: u64,
    expires_at_epoch_ms: u64,
) -> RuntimeCommand {
    RuntimeCommand::RegisterPasskeyCeremony {
        ceremony_token: token.into(),
        connection_id: "connection-1".into(),
        origin: origin.into(),
        top_origin: top_origin.map(str::to_owned),
        ancestor_origins: ancestor_origins.clone(),
        relying_party: relying_party.into(),
        ceremony,
        discoverable: false,
        user_verification: PasskeyUserVerificationRequirementDto::Preferred,
        challenge_base64url: challenge_base64url.into(),
        request_id: 42,
        tab_id: 7,
        frame_id: if ancestor_origins.is_empty() { 0 } else { 2 },
        frame_kind: if ancestor_origins.is_empty() {
            PasskeyFrameKindDto::Top
        } else {
            PasskeyFrameKindDto::Subframe
        },
        registered_at_epoch_ms,
        expires_at_epoch_ms,
    }
}

fn create_committed_passkey_registration(
    runtime: &mut Runtime,
    token: &str,
    challenge_base64url: &str,
) {
    let (vault_id, entry_id, credential_id) =
        create_mutated_passkey_registration(runtime, token, challenge_base64url);
    runtime
        .handle(RuntimeCommand::SavePasskeyRegistration {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: vault_id.clone(),
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
            entry_id,
            credential_id,
        })
        .unwrap();
}

fn create_mutated_passkey_registration(
    runtime: &mut Runtime,
    token: &str,
    challenge_base64url: &str,
) -> (String, String, String) {
    create_mutated_passkey_registration_with_origin(
        runtime,
        token,
        challenge_base64url,
        "https://login.example.com",
    )
}

fn create_mutated_passkey_registration_with_origin(
    runtime: &mut Runtime,
    token: &str,
    challenge_base64url: &str,
    origin: &str,
) -> (String, String, String) {
    let vault_id = open_unlocked_test_vault(runtime, token);
    register_and_advance_to_s4(
        runtime,
        token,
        PasskeyCeremonyKindDto::Create,
        origin,
        "example.com",
        challenge_base64url,
    );
    let client_data = format!(
        r#"{{"type":"webauthn.create","challenge":"{challenge_base64url}","origin":"{origin}","crossOrigin":false}}"#
    );
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: vault_id.clone(),
            relying_party: "example.com".into(),
            origin: origin.into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(registration) = response else {
        panic!("expected passkey registration, got {response:?}");
    };
    (vault_id, registration.entry_id, registration.credential_id)
}

fn open_unlocked_test_vault(runtime: &mut Runtime, name: &str) -> String {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password(name);
    let vault = Vault::empty(name);
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save seed vault");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("{name}.kdbx"));
    std::fs::write(&path, bytes).unwrap();
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, name)
        .expect("unlock vault");
    let _persisted_dir = dir.keep();
    handle.vault_id
}

fn register_and_advance_to_s4(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
) {
    register_and_advance_to_s3(
        runtime,
        token,
        ceremony,
        origin,
        relying_party,
        challenge_base64url,
    );
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();
}

fn register_and_advance_to_s3(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
) {
    register_and_advance_to_s3_with_frame(
        runtime,
        token,
        ceremony,
        origin,
        None,
        vec![],
        relying_party,
        challenge_base64url,
    )
}

fn register_and_advance_to_s4_with_top_origin(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    top_origin: Option<&str>,
    relying_party: &str,
    challenge_base64url: &str,
) {
    let ancestor_origins = top_origin.into_iter().map(str::to_owned).collect();
    register_and_advance_to_s3_with_frame(
        runtime,
        token,
        ceremony,
        origin,
        top_origin,
        ancestor_origins,
        relying_party,
        challenge_base64url,
    );
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();
}

fn register_and_advance_to_s4_with_frame(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    top_origin: Option<&str>,
    ancestor_origins: Vec<String>,
    relying_party: &str,
    challenge_base64url: &str,
) {
    register_and_advance_to_s3_with_frame(
        runtime,
        token,
        ceremony,
        origin,
        top_origin,
        ancestor_origins,
        relying_party,
        challenge_base64url,
    );
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();
}

fn register_and_advance_to_s3_with_frame(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    top_origin: Option<&str>,
    ancestor_origins: Vec<String>,
    relying_party: &str,
    challenge_base64url: &str,
) {
    runtime
        .handle(register_command_with_frame(
            token,
            ceremony,
            origin,
            top_origin,
            ancestor_origins,
            relying_party,
            challenge_base64url,
            1_000,
            301_000,
        ))
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap();
}

fn client_data_json(kind: &str, challenge: &str, origin: &str) -> String {
    client_data_json_with_frame(kind, challenge, origin, false, None)
}

fn client_data_json_with_frame(
    kind: &str,
    challenge: &str,
    origin: &str,
    cross_origin: bool,
    top_origin: Option<&str>,
) -> String {
    let top_origin_member = top_origin
        .map(|value| format!(r#","topOrigin":"{value}""#))
        .unwrap_or_default();
    URL_SAFE_NO_PAD.encode(format!(
        r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{origin}","crossOrigin":{cross_origin}{top_origin_member}}}"#
    ))
}

fn client_data_json_with_null_top_origin(
    kind: &str,
    challenge: &str,
    origin: &str,
    cross_origin: bool,
) -> String {
    URL_SAFE_NO_PAD.encode(format!(
        r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{origin}","crossOrigin":{cross_origin},"topOrigin":null}}"#
    ))
}
