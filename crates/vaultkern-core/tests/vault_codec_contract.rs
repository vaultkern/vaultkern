use vaultkern_core::{
    CompositeKey, CustomField, Entry, ExternalKdfConfirmation, ExternalKdfPolicy, KdbxVaultCodec,
    SaveProfile, Vault, VaultCodec,
};

#[test]
fn kdbx_codec_round_trips_opaque_bytes_and_keeps_working_copy_history() {
    let codec = KdbxVaultCodec;
    let mut composite_key = CompositeKey::default();
    composite_key.add_password("codec-contract");

    let mut vault = Vault::empty("codec");
    vault.history_max_items = Some(1);
    let mut entry = Entry::new("current");
    entry.password = "current-secret".into();
    entry.attributes.insert(
        "RecoveryCode".into(),
        CustomField {
            value: "protected-secret".into(),
            protected: true,
        },
    );
    let mut oldest = Entry::new("oldest");
    oldest.id = entry.id;
    oldest.modified_at = 1;
    let mut newest = Entry::new("newest");
    newest.id = entry.id;
    newest.modified_at = 2;
    entry.history = vec![oldest, newest];
    vault.root.entries.push(entry);

    let bootstrap = codec
        .encode_with_composite_key(vault, &composite_key, SaveProfile::recommended())
        .expect("encode initial KDBX generation");
    let transformed_key = codec
        .derive_key_with_policy(
            &bootstrap.bytes,
            &composite_key,
            &ExternalKdfPolicy::Desktop,
            ExternalKdfConfirmation::Unconfirmed,
        )
        .expect("derive transformed key");

    let encoded = codec
        .encode(
            bootstrap.vault,
            &transformed_key,
            SaveProfile {
                kdf: None,
                ..SaveProfile::recommended()
            },
        )
        .expect("encode through Vault Codec interface");
    assert_eq!(encoded.vault.root.entries[0].history.len(), 2);
    assert_eq!(encoded.vault.generator.as_deref(), Some("VaultKern"));

    let decoded = codec
        .decode(&encoded.bytes, &transformed_key)
        .expect("decode encoded candidate");
    assert_eq!(decoded.root.entries[0].history.len(), 1);
    assert_eq!(decoded.root.entries[0].history[0].title, "newest");
    assert_eq!(decoded.root.entries[0].password, "current-secret");
    assert_eq!(
        decoded.root.entries[0].attributes["RecoveryCode"].value,
        "protected-secret"
    );
}
