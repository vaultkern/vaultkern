use vaultkern_crypto::CompositeKey;
use vaultkern_kdbx::{
    ExternalKdfConfirmation, KdbxError, KdbxHeader, KdbxLoadDiagnostic, KdbxVersion,
    KdfPolicyEvaluator, SaveProfile, TransformedKey, derive_transformed_key_with_policy,
    load_kdbx_with_policy, load_kdbx_with_transformed_key,
    load_kdbx_with_transformed_key_diagnostic, required_version, save_kdbx,
    save_kdbx_with_transformed_key,
};
use vaultkern_model::{Entry, Group, Vault};

pub const VAULTKERN_KDBX_GENERATOR: &str = "VaultKern";

pub struct EncodedVault {
    pub vault: Vault,
    pub bytes: Vec<u8>,
}

pub trait VaultCodec {
    type Key;
    type EncodingOptions;
    type Error;

    fn decode(&self, bytes: &[u8], key: &Self::Key) -> Result<Vault, Self::Error>;

    fn encode(
        &self,
        vault: Vault,
        key: &Self::Key,
        options: Self::EncodingOptions,
    ) -> Result<EncodedVault, Self::Error>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct KdbxVaultCodec;

impl VaultCodec for KdbxVaultCodec {
    type Key = TransformedKey;
    type EncodingOptions = SaveProfile;
    type Error = KdbxError;

    fn decode(&self, bytes: &[u8], key: &Self::Key) -> Result<Vault, Self::Error> {
        load_kdbx_with_transformed_key(bytes, key)
    }

    fn encode(
        &self,
        vault: Vault,
        key: &Self::Key,
        options: Self::EncodingOptions,
    ) -> Result<EncodedVault, Self::Error> {
        encode_candidate(vault, options, |vault, profile| {
            save_kdbx_with_transformed_key(vault, key, profile)
        })
    }
}

impl KdbxVaultCodec {
    pub fn decode_diagnostic(
        &self,
        bytes: &[u8],
        key: &TransformedKey,
    ) -> Result<Vault, KdbxLoadDiagnostic> {
        load_kdbx_with_transformed_key_diagnostic(bytes, key)
    }

    pub fn decode_with_policy(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
        policy: &dyn KdfPolicyEvaluator,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<Vault, KdbxError> {
        load_kdbx_with_policy(bytes, composite_key, policy, confirmation)
    }

    pub fn encode_with_composite_key(
        &self,
        mut vault: Vault,
        composite_key: &CompositeKey,
        profile: SaveProfile,
    ) -> Result<EncodedVault, KdbxError> {
        let bytes = save_kdbx(&vault, composite_key, &profile)?;
        let header = KdbxHeader::decode(&bytes)?;
        vault.kdf_parameters = Some(header.kdf_parameters.encode()?);
        Ok(EncodedVault { vault, bytes })
    }

    pub fn derive_key_with_policy(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
        policy: &dyn KdfPolicyEvaluator,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<TransformedKey, KdbxError> {
        derive_transformed_key_with_policy(bytes, composite_key, policy, confirmation)
    }
}

fn encode_candidate(
    mut vault: Vault,
    mut profile: SaveProfile,
    save: impl FnOnce(&Vault, &SaveProfile) -> Result<Vec<u8>, KdbxError>,
) -> Result<EncodedVault, KdbxError> {
    vault.generator = Some(VAULTKERN_KDBX_GENERATOR.into());
    if required_version(&vault) == KdbxVersion::V4_1 {
        profile.version = KdbxVersion::V4_1;
    }

    let mut serialized_vault = vault.clone();
    enforce_history_limits(&mut serialized_vault);
    let bytes = save(&serialized_vault, &profile)?;
    let header = KdbxHeader::decode(&bytes)?;
    vault.kdf_parameters = Some(header.kdf_parameters.encode()?);
    Ok(EncodedVault { vault, bytes })
}

pub fn enforce_history_limits(vault: &mut Vault) {
    if let Some(max_items) = vault
        .history_max_items
        .and_then(|value| usize::try_from(value).ok())
    {
        enforce_history_item_limit(&mut vault.root, max_items);
    }

    if let Some(max_size) = vault
        .history_max_size
        .and_then(|value| usize::try_from(value).ok())
    {
        enforce_history_size_limit(vault, max_size);
    }
}

fn enforce_history_item_limit(group: &mut Group, max_items: usize) {
    for entry in &mut group.entries {
        while entry.history.len() > max_items {
            entry.history.remove(0);
        }
    }

    for child in &mut group.children {
        enforce_history_item_limit(child, max_items);
    }
}

fn enforce_history_size_limit(vault: &mut Vault, max_size: usize) {
    while total_history_size(&vault.root) > max_size {
        if !remove_oldest_history_item(&mut vault.root) {
            break;
        }
    }
}

fn total_history_size(group: &Group) -> usize {
    let entry_size = group
        .entries
        .iter()
        .flat_map(|entry| entry.history.iter())
        .map(estimated_entry_size)
        .sum::<usize>();
    let child_size = group.children.iter().map(total_history_size).sum::<usize>();
    entry_size + child_size
}

fn remove_oldest_history_item(group: &mut Group) -> bool {
    let Some(path) = oldest_history_path(group) else {
        return false;
    };
    remove_history_item_at_path(group, &path)
}

fn oldest_history_path(group: &Group) -> Option<Vec<usize>> {
    let mut oldest: Option<(u64, Vec<usize>)> = None;
    collect_oldest_history_path(group, &mut Vec::new(), &mut oldest);
    oldest.map(|(_, path)| path)
}

fn collect_oldest_history_path(
    group: &Group,
    group_path: &mut Vec<usize>,
    oldest: &mut Option<(u64, Vec<usize>)>,
) {
    for (entry_index, entry) in group.entries.iter().enumerate() {
        if let Some(history) = entry.history.first() {
            let mut path = group_path.clone();
            path.push(entry_index);
            let modified_at = history.modified_at;
            if oldest
                .as_ref()
                .map(|(oldest_modified_at, _)| modified_at < *oldest_modified_at)
                .unwrap_or(true)
            {
                *oldest = Some((modified_at, path));
            }
        }
    }

    for (child_index, child) in group.children.iter().enumerate() {
        group_path.push(child_index);
        collect_oldest_history_path(child, group_path, oldest);
        group_path.pop();
    }
}

fn remove_history_item_at_path(group: &mut Group, path: &[usize]) -> bool {
    if path.len() == 1 {
        return group
            .entries
            .get_mut(path[0])
            .and_then(|entry| {
                if entry.history.is_empty() {
                    None
                } else {
                    Some(entry.history.remove(0))
                }
            })
            .is_some();
    }

    let Some((child_index, rest)) = path.split_first() else {
        return false;
    };
    group
        .children
        .get_mut(*child_index)
        .map(|child| remove_history_item_at_path(child, rest))
        .unwrap_or(false)
}

fn estimated_entry_size(entry: &Entry) -> usize {
    entry.title.len()
        + entry.username.len()
        + entry.password.len()
        + entry.url.len()
        + entry.notes.len()
        + entry
            .attributes
            .iter()
            .map(|(key, field)| key.len() + field.value.len())
            .sum::<usize>()
        + entry
            .attachments
            .iter()
            .map(|(name, attachment)| name.len() + attachment.data.len())
            .sum::<usize>()
}
