use serde_json::json;
use vaultkern_windows::DesktopSettingsStore;

#[test]
fn native_settings_are_available_before_the_webview_starts() {
    let directory = tempfile::tempdir().unwrap();
    let store = DesktopSettingsStore::new(directory.path().join("settings.json"));
    let desired = json!({
        "recentVaultLimit": 10,
        "language": "en",
        "idleLockMinutes": 10,
        "clearClipboardSeconds": 30,
        "autofillOnPageLoadEnabled": false,
        "passkeyProviderEnabled": true,
        "quickUnlockEnabled": false
    });

    store.save(&desired).unwrap();

    assert_eq!(store.load().unwrap(), desired);
    assert!(store.passkey_provider_enabled().unwrap());
}

#[test]
fn a_failed_native_settings_save_preserves_the_previous_generation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("settings.json");
    let store = DesktopSettingsStore::new(path.clone());
    let previous = json!({ "passkeyProviderEnabled": false });
    store.save(&previous).unwrap();

    std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
    let error = store
        .save(&json!({ "passkeyProviderEnabled": true }))
        .expect_err("an unavailable temp path must fail before publish");

    assert!(!error.to_string().is_empty());
    assert_eq!(store.load().unwrap(), previous);
}
