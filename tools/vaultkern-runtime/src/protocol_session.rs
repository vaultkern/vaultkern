use std::collections::BTreeSet;

use vaultkern_runtime_protocol::{
    ErrorDto, HandshakeDto, PROTOCOL_VERSION, RuntimeCommand, RuntimeResponse,
};

pub enum RuntimeProtocolDispatch {
    Respond(RuntimeResponse),
    Dispatch(RuntimeCommand),
}

pub struct RuntimeProtocolSession {
    client_capability: &'static str,
    supported_capabilities: BTreeSet<&'static str>,
    negotiated_capabilities: Option<BTreeSet<String>>,
}

impl RuntimeProtocolSession {
    pub fn resident_app() -> Self {
        Self::new(
            "resident-app",
            [
                "runtime-core",
                "resident-app",
                "database-settings",
                "one-drive",
                "passkey-ceremonies",
                "quick-unlock",
            ],
        )
    }

    pub fn browser_extension() -> Self {
        Self::new(
            "browser-extension",
            [
                "runtime-core",
                "browser-extension",
                "browser-autofill",
                "passkey-ceremonies",
            ],
        )
    }

    pub fn legacy_native_host() -> Self {
        let mut session = Self::browser_extension();
        session.negotiated_capabilities = Some(
            session
                .supported_capabilities
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
        );
        session
    }

    fn new<const N: usize>(
        client_capability: &'static str,
        supported_capabilities: [&'static str; N],
    ) -> Self {
        Self {
            client_capability,
            supported_capabilities: supported_capabilities.into_iter().collect(),
            negotiated_capabilities: None,
        }
    }

    pub fn accept(&mut self, command: RuntimeCommand) -> RuntimeProtocolDispatch {
        let RuntimeCommand::Handshake {
            protocol_version,
            capabilities,
        } = command
        else {
            return self.authorize(command);
        };

        if protocol_version != PROTOCOL_VERSION {
            return error(
                "unsupported_version",
                format!("unsupported runtime protocol version: {protocol_version}"),
            );
        }

        let capabilities = capabilities
            .into_iter()
            .filter(|capability| self.supported_capabilities.contains(capability.as_str()))
            .collect::<BTreeSet<_>>();
        self.negotiated_capabilities = Some(capabilities.clone());
        RuntimeProtocolDispatch::Respond(RuntimeResponse::Handshake(HandshakeDto {
            protocol_version: PROTOCOL_VERSION,
            capabilities: capabilities.into_iter().collect(),
        }))
    }

    fn authorize(&self, command: RuntimeCommand) -> RuntimeProtocolDispatch {
        let Some(capabilities) = self.negotiated_capabilities.as_ref() else {
            return error(
                "protocol_handshake_required",
                "runtime protocol handshake is required before business commands",
            );
        };

        if self.client_capability == "browser-extension" && !browser_command_allowed(&command) {
            return error(
                "browser_command_forbidden",
                "browser clients cannot unlock or manage the vault",
            );
        }

        for capability in std::iter::once(self.client_capability)
            .chain(required_command_capabilities(&command).into_iter())
        {
            if !capabilities.contains(capability) {
                return error(
                    "capability_not_negotiated",
                    format!("runtime command requires negotiated capability: {capability}"),
                );
            }
        }

        RuntimeProtocolDispatch::Dispatch(command)
    }
}

fn error(code: &'static str, message: impl Into<String>) -> RuntimeProtocolDispatch {
    RuntimeProtocolDispatch::Respond(RuntimeResponse::Error(ErrorDto {
        code: code.into(),
        message: message.into(),
    }))
}

pub(crate) fn required_command_capabilities(command: &RuntimeCommand) -> Vec<&'static str> {
    let mut required = vec!["runtime-core"];
    if matches!(
        command,
        RuntimeCommand::FindFillCandidates { .. }
            | RuntimeCommand::GetAutofillCredential { .. }
            | RuntimeCommand::GetAutofillEntryFields { .. }
            | RuntimeCommand::GetAutofillCreateContext { .. }
            | RuntimeCommand::FindExactMatchingEntryIds { .. }
            | RuntimeCommand::CreateAutofillEntry { .. }
            | RuntimeCommand::UpdateAutofillEntryFields { .. }
            | RuntimeCommand::PersistAutofillMutation { .. }
    ) {
        required.push("browser-autofill");
    }
    if matches!(
        command,
        RuntimeCommand::BeginOneDriveLogin
            | RuntimeCommand::CompletePendingOneDriveLogin
            | RuntimeCommand::ListOneDriveChildren { .. }
            | RuntimeCommand::AddOneDriveVaultReference { .. }
            | RuntimeCommand::RetryVaultSourceSync { .. }
    ) {
        required.push("one-drive");
    }
    if command_requires_passkey_capability(command) {
        required.push("passkey-ceremonies");
    }
    if matches!(
        command,
        RuntimeCommand::EnableQuickUnlockForCurrentVault { .. }
            | RuntimeCommand::UnlockCurrentVaultWithQuickUnlock
            | RuntimeCommand::DisableQuickUnlockForCurrentVault
    ) {
        required.push("quick-unlock");
    }
    if matches!(
        command,
        RuntimeCommand::GetDatabaseSettings { .. } | RuntimeCommand::UpdateDatabaseSettings { .. }
    ) {
        required.push("database-settings");
    }
    required
}

pub(crate) fn browser_command_allowed(command: &RuntimeCommand) -> bool {
    matches!(
        command,
        RuntimeCommand::GetSessionState
            | RuntimeCommand::GetBrowserIntegrationSettings
            | RuntimeCommand::ActivateResidentApp { .. }
            | RuntimeCommand::RecordUserActivity
            | RuntimeCommand::FindFillCandidates { .. }
            | RuntimeCommand::GetAutofillCredential { .. }
            | RuntimeCommand::GetAutofillEntryFields { .. }
            | RuntimeCommand::GetAutofillCreateContext { .. }
            | RuntimeCommand::FindExactMatchingEntryIds { .. }
            | RuntimeCommand::CreateAutofillEntry { .. }
            | RuntimeCommand::UpdateAutofillEntryFields { .. }
            | RuntimeCommand::PersistAutofillMutation { .. }
    ) || matches!(
        command,
        RuntimeCommand::VerifyPasskeyUser {
            method: vaultkern_runtime_protocol::PasskeyUserVerificationMethodDto::QuickUnlock,
            password: None,
            ..
        }
    ) || (command_requires_passkey_capability(command)
        && !matches!(
            command,
            RuntimeCommand::SetEntryPasskey { .. }
                | RuntimeCommand::ClearEntryPasskey { .. }
                | RuntimeCommand::VerifyPasskeyUser { .. }
        ))
}

fn command_requires_passkey_capability(command: &RuntimeCommand) -> bool {
    matches!(
        command,
        RuntimeCommand::SetEntryPasskey { .. }
            | RuntimeCommand::ClearEntryPasskey { .. }
            | RuntimeCommand::GetPasskeyUserVerificationCapability
            | RuntimeCommand::VerifyPasskeyUser { .. }
            | RuntimeCommand::ListPasskeyCredentials { .. }
            | RuntimeCommand::RegisterPasskeyCeremony { .. }
            | RuntimeCommand::AdvancePasskeyCeremonyPhase { .. }
            | RuntimeCommand::BindPasskeyCeremonyVault { .. }
            | RuntimeCommand::QueryPasskeyCeremonyLedger { .. }
            | RuntimeCommand::ReconcilePasskeyCeremonyLedger { .. }
            | RuntimeCommand::MarkPasskeyCeremonyUnknownDelivery { .. }
            | RuntimeCommand::CreatePasskeyAssertion { .. }
            | RuntimeCommand::CreatePasskeyRegistration { .. }
            | RuntimeCommand::SavePasskeyRegistration { .. }
            | RuntimeCommand::AbortPasskeyRegistration { .. }
            | RuntimeCommand::CommitPasskeyRegistration { .. }
            | RuntimeCommand::PasskeyCredentialStatus { .. }
            | RuntimeCommand::PasskeyCredentialStatusBatch { .. }
    )
}
