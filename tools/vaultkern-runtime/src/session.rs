use vaultkern_runtime_protocol::SessionStateDto;

#[derive(Debug, Clone, Default)]
pub struct SessionState {
    unlocked: bool,
    active_vault_id: Option<String>,
    current_vault_ref_id: Option<String>,
}

impl SessionState {
    pub fn set_current_vault(&mut self, vault_ref_id: String) {
        self.current_vault_ref_id = Some(vault_ref_id);
        self.unlocked = false;
        self.active_vault_id = None;
    }

    pub fn unlock(&mut self, vault_id: String, current_vault_ref_id: String) {
        self.unlocked = true;
        self.active_vault_id = Some(vault_id);
        self.current_vault_ref_id = Some(current_vault_ref_id);
    }

    pub fn lock(&mut self) {
        self.unlocked = false;
        self.active_vault_id = None;
    }

    pub fn clear_current_vault(&mut self) {
        self.lock();
        self.current_vault_ref_id = None;
    }

    pub fn current_vault_ref_id(&self) -> Option<&str> {
        self.current_vault_ref_id.as_deref()
    }

    pub fn active_vault_id(&self) -> Option<&str> {
        self.active_vault_id.as_deref()
    }

    pub fn to_dto(
        &self,
        supports_biometric_unlock: bool,
        quick_unlock_requires_password: bool,
    ) -> SessionStateDto {
        SessionStateDto {
            unlocked: self.unlocked,
            active_vault_id: self.active_vault_id.clone(),
            current_vault_ref_id: self.current_vault_ref_id.clone(),
            supports_biometric_unlock,
            quick_unlock_requires_password,
            source_status: None,
        }
    }
}
