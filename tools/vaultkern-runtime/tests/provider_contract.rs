use vaultkern_runtime::{
    InMemoryProvider, LocalFileProvider, Provider, ProviderError, ProviderRevision,
};

fn assert_provider_contract(provider: &dyn Provider) {
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
}

#[test]
fn in_memory_adapter_satisfies_the_provider_contract() {
    let provider = InMemoryProvider::new(b"generation-a".to_vec());

    assert_provider_contract(&provider);
}

#[test]
fn local_file_adapter_satisfies_the_provider_contract() {
    let directory = tempfile::tempdir().expect("temporary Provider directory");
    let path = directory.path().join("vault.kdbx");
    std::fs::write(&path, b"generation-a").expect("write initial local snapshot");
    let provider = LocalFileProvider::new(path);

    assert_provider_contract(&provider);
}

#[test]
fn provider_revision_is_opaque_but_supports_identity_comparison() {
    fn revision_identity(revision: &ProviderRevision) -> &ProviderRevision {
        revision
    }

    let provider = InMemoryProvider::new(b"opaque".to_vec());
    let first = provider.read().expect("first read").revision;
    let second = provider.read().expect("second read").revision;

    assert_eq!(revision_identity(&first), revision_identity(&second));
}
