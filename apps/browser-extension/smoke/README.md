# Browser v0 Smoke Test

This directory contains the fixed login page used by the browser extension v0 smoke test. It validates the smallest autofill path: the extension recognizes a normal HTTP login page and fills the selected entry's username and password into the page.

This is not a product page and does not replace unit tests. Its value is providing a stable, repeatable browser scene for regression checks.

## Boundaries

- Codex automation uses only the Chrome extension and Chrome control channel.
- It does not operate on the user's daily Edge window, profile, configuration, or extension state.
- Any future Edge installation validation must be confirmed separately and must use an isolated profile.

## Page

Smoke page:

```text
apps/browser-extension/smoke/basic-login.html
```

The page provides two stable inputs:

- `#vaultkern-smoke-username`
- `#vaultkern-smoke-password`

They use standard `autocomplete="username"` and `autocomplete="current-password"` attributes, which are recognized by the current content-script field selection rules.

## Manual Verification

Start a static server from the repository root:

```bash
python3 -m http.server 4174 -d apps/browser-extension/smoke
```

Build the browser extension:

```bash
npm run build --workspace @vaultkern/browser-extension
```

Then load `apps/browser-extension/dist` as an unpacked extension in Chrome. The current manually loaded Chrome extension id is:

```text
kblgblkjghklighdgmejjfondchkjcgf
```

If the extension needs to connect to the native host, the native host manifest must allow this origin:

```text
chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/
```

Linux / WSL Chrome native host manifest installation can use:

```bash
tools/vaultkern-runtime/scripts/install_native_host.sh kblgblkjghklighdgmejjfondchkjcgf /absolute/path/to/vaultkern-runtime
```

On Windows Chrome, use `vaultkern-native-setup` to register the `HKCU` native host. The setup utility extracts the embedded runtime and writes the browser manifest:

```text
HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vaultkern.runtime
```

Stable Windows manifest and runtime paths:

```text
%LOCALAPPDATA%\vaultkern-runtime\com.vaultkern.runtime.chrome.json
%LOCALAPPDATA%\vaultkern-runtime\vaultkern-runtime.exe
```

The browser native host isolates runtime state by extension id. For the current Chrome smoke extension, recent/current vault state, remote cache state, and OneDrive refresh tokens are stored under:

```text
C:\Users\<user>\AppData\Local\vaultkern-runtime\extensions\kblgblkjghklighdgmejjfondchkjcgf\
```

Older user-level state files may still exist, but a browser native host launched with an origin no longer shares them:

```text
C:\Users\<user>\AppData\Local\vaultkern-runtime\vault-references.json
```

The manifest should contain:

```json
{"name":"com.vaultkern.runtime","description":"VaultKern runtime native host","path":"C:\\Users\\<user>\\AppData\\Local\\vaultkern-runtime\\vaultkern-runtime.exe","type":"stdio","allowed_origins":["chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/"]}
```

Open:

```text
http://127.0.0.1:4174/basic-login.html
```

Expected result:

- the popup shows fillable entries for the current site context
- clicking fill writes the username into `#vaultkern-smoke-username`
- clicking fill writes the password into `#vaultkern-smoke-password`
- clicking the page's `Sign in` button shows `submitted:<username>:<password length>` at the bottom of the page

## Automated Guard

`apps/browser-extension/src/__tests__/fill-flow.test.ts` reads this HTML file and fills it through the real `fillLoginForm` logic. If the smoke page DOM or content-script field selection rules become incompatible, the targeted `fill-flow` test fails.

## Chrome E2E Automation

The real browser/native smoke path is available as a repository command:

```bash
npm run smoke:e2e --workspace @vaultkern/browser-extension
```

The command:

- builds an E2E extension with a dev/test manifest `key`
- fixes the E2E extension id to `akgcahfkhhffgcafpbbeihpmniekohik`
- builds `vaultkern-runtime`
- creates a temporary KDBX with password `smoke-password`
- starts a temporary HTTP smoke server
- writes `NativeMessagingHosts/com.vaultkern.runtime.json` under a temporary Chrome for Testing profile
- runs `open -> unlock -> create -> save -> find candidates -> fill` through the real extension background native bridge
- verifies the final submit result: `submitted:smoke-user@example.com:12`

Normal release builds still use:

```bash
npm run build --workspace @vaultkern/browser-extension
```

Normal builds do not write the dev/test `key` into `dist/manifest.json`. If the extension is uploaded to Chrome Web Store later, replace the dev/test public key with the production public key from Chrome Developer Dashboard and update the native host allowed origin for the production extension id.
