use vaultkern_runtime::{
    InMemoryProvider, LocalFileProvider, OneDriveMemoryWriteBehavior, OneDriveVaultSourceProvider,
    Provider, ProviderConflictCopy, ProviderError, ProviderRevision,
};

fn assert_provider_contract(provider: &mut dyn Provider) -> ProviderConflictCopy {
    let opened = provider.read().expect("read initial Provider snapshot");
    assert_eq!(opened.bytes, b"generation-a");

    let committed = provider
        .publish(&opened.revision, b"generation-b")
        .expect("conditionally publish against the current revision");
    assert_ne!(committed.revision, opened.revision);

    let current = provider.read().expect("read committed Provider snapshot");
    assert_eq!(current.bytes, b"generation-b");
    assert_eq!(current.revision, committed.revision);

    let stale = provider
        .publish(&opened.revision, b"must-not-overwrite")
        .expect_err("the previous revision must be stale");
    assert!(matches!(stale, ProviderError::StaleRevision { .. }));
    assert_eq!(
        provider.read().expect("read after stale rejection").bytes,
        b"generation-b"
    );

    let conflict = provider
        .preserve_conflict_copy(b"opaque-conflict-bytes")
        .expect("durably preserve an opaque sibling Conflict Copy");
    assert!(!conflict.identity.is_empty());
    assert!(!conflict.display_name.is_empty());
    assert_eq!(
        provider
            .read()
            .expect("read main snapshot after Conflict Copy")
            .bytes,
        b"generation-b",
        "Conflict Copy preservation must not replace the active snapshot"
    );
    conflict
}

#[test]
fn in_memory_adapter_satisfies_the_provider_contract() {
    let mut provider = InMemoryProvider::new(b"generation-a".to_vec());

    let conflict = assert_provider_contract(&mut provider);
    assert_eq!(
        provider.conflict_copy_bytes(&conflict.identity).as_deref(),
        Some(b"opaque-conflict-bytes".as_slice())
    );
}

#[test]
fn local_file_adapter_satisfies_the_provider_contract() {
    let directory = tempfile::tempdir().expect("temporary Provider directory");
    let path = directory.path().join("vault.kdbx");
    std::fs::write(&path, b"generation-a").expect("write initial local snapshot");
    let mut provider = LocalFileProvider::new(path);

    let conflict = assert_provider_contract(&mut provider);
    assert_eq!(
        std::fs::read(&conflict.identity).expect("read local Conflict Copy"),
        b"opaque-conflict-bytes"
    );
}

#[test]
fn onedrive_adapter_satisfies_the_provider_contract() {
    let mut source = OneDriveVaultSourceProvider::new_in_memory();
    source.insert_memory_item(
        "drive-1",
        "item-1",
        "vault.kdbx",
        "acceptance@example.com",
        b"generation-a".to_vec(),
    );
    let mut provider = source.bind("drive-1", "item-1");

    let conflict = assert_provider_contract(&mut provider);
    drop(provider);
    assert_eq!(
        source
            .read_memory_item_bytes("drive-1", &conflict.identity)
            .expect("read OneDrive Conflict Copy"),
        b"opaque-conflict-bytes"
    );
}

#[test]
fn onedrive_adapter_keeps_unknown_and_unavailable_distinct_from_stale() {
    let mut unknown_source = OneDriveVaultSourceProvider::new_in_memory();
    unknown_source.insert_memory_item(
        "drive-1",
        "unknown",
        "unknown.kdbx",
        "acceptance@example.com",
        b"generation-a".to_vec(),
    );
    let expected = unknown_source
        .bind("drive-1", "unknown")
        .read()
        .expect("read unknown-outcome baseline")
        .revision;
    unknown_source
        .queue_memory_write_behavior(OneDriveMemoryWriteBehavior::OutcomeUnknownNotCommitted);
    let unknown = unknown_source
        .bind("drive-1", "unknown")
        .publish(&expected, b"generation-b")
        .expect_err("injected transport ambiguity must remain unknown");
    assert!(matches!(unknown, ProviderError::OutcomeUnknown { .. }));

    let mut unavailable_source = OneDriveVaultSourceProvider::new_in_memory();
    unavailable_source.insert_memory_item(
        "drive-1",
        "unavailable",
        "unavailable.kdbx",
        "acceptance@example.com",
        b"generation-a".to_vec(),
    );
    let expected = unavailable_source
        .bind("drive-1", "unavailable")
        .read()
        .expect("read unavailable baseline")
        .revision;
    unavailable_source.remove_memory_item("drive-1", "unavailable");
    let unavailable = unavailable_source
        .bind("drive-1", "unavailable")
        .publish(&expected, b"generation-b")
        .expect_err("missing transport target must be unavailable");
    assert!(matches!(unavailable, ProviderError::Unavailable { .. }));
}

#[test]
fn provider_revision_is_opaque_but_supports_identity_comparison() {
    fn revision_identity(revision: &ProviderRevision) -> &ProviderRevision {
        revision
    }

    let mut provider = InMemoryProvider::new(b"opaque".to_vec());
    let first = provider.read().expect("first read").revision;
    let second = provider.read().expect("second read").revision;

    assert_eq!(revision_identity(&first), revision_identity(&second));
}
