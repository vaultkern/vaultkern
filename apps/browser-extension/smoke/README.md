# Browser v0 Smoke Test

This directory contains fixed pages used by the browser extension v0 smoke and autofill regression tests. The automated Chrome smoke currently drives the smallest autofill path: the extension recognizes a normal HTTP login page and fills the selected entry's username and password into the page.

This is not a product page and does not replace unit tests. Its value is providing a stable, repeatable browser scene for regression checks.

## Boundaries

- Codex automation uses only the Chrome extension and Chrome control channel.
- It does not operate on the user's daily Edge window, profile, configuration, or extension state.
- Any future Edge installation validation must be confirmed separately and must use an isolated profile.

## Page

Chrome E2E smoke page:

```text
apps/browser-extension/smoke/basic-login.html
```

The page provides two stable inputs:

- `#vaultkern-smoke-username`
- `#vaultkern-smoke-password`

They use standard `autocomplete="username"` and `autocomplete="current-password"` attributes, which are recognized by the current content-script field selection rules.

Additional autofill regression fixtures:

```text
apps/browser-extension/smoke/username-first-login.html
apps/browser-extension/smoke/password-step-login.html
apps/browser-extension/smoke/noisy-login.html
apps/browser-extension/smoke/register.html
apps/browser-extension/smoke/change-password.html
apps/browser-extension/smoke/totp.html
apps/browser-extension/smoke/totp-split.html
```

These pages are covered by unit tests. They verify username-first login, password-only login steps, noisy pages with search, newsletter, and registration fields that should not receive login credentials, registration forms with new-password confirmation, password-change forms with current/new/confirm fields, and TOTP pages using both single-code and split-code layouts.

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
http://localhost:4174/basic-login.html
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

With no arguments, the command runs every required Chromium case. The registry is
strict: `--case` requires a known name, and unknown or stray arguments exit nonzero
instead of falling back to the native smoke.

Run one case while developing with:

```bash
npm run smoke:e2e --workspace @vaultkern/browser-extension -- --case controlled-react-input
```

Required cases:

```text
native-kdbx-totp-passkey
exact-origin-automatic-authorization
autofill-shadow-visibility
dynamic-shadow-submit
nested-dynamic-shadow-submit
trusted-spa-submit
controlled-react-input
large-dom-performance
mv3-pending-session-reload
```

The full command:

- builds an E2E extension with a dev/test manifest `key`
- fixes the E2E extension id to `akgcahfkhhffgcafpbbeihpmniekohik`
- builds `vaultkern-runtime`
- creates a temporary KDBX with password `smoke-password`
- starts a temporary HTTP smoke server
- writes `NativeMessagingHosts/com.vaultkern.runtime.json` under a temporary Chrome for Testing profile
- runs `open -> unlock -> create -> save -> find candidates -> fill` through the real extension background native bridge
- proves a message without a fill capability releases nothing, then fills with a manual capability bound to the real entry id
- verifies the final submit result: `submitted:smoke-user@example.com:12`
- verifies automatic fill through the native/background/page-load/content chain for an exact origin while rejecting different ports, sibling hosts, and HTTPS-to-HTTP downgrade pages; a held page resource keeps load incomplete until the isolated probe and attempt-sequence baseline are installed, and every assertion waits for the correlated terminal background diagnostic
- covers open, closed, nested dynamic, and unslotted shadow DOM plus real Chromium occlusion and hit-testing
- bundles the repository's local React 19 into a temporary fixture and checks DOM value, React state, events, and rerender stability
- measures seven fills after two warmups against 50,000 noise nodes and 20 credential fields, requiring a median at or below 500 ms and bounded hot-path DOM instrumentation
- terminates and restarts the MV3 worker twice through CDP; after each recovery it verifies the same session key, no local/sync secret copy, denied ISOLATED-world access, and restoration through a newly opened popup

Each successful invocation ends with an `executedCases` list. This makes it clear
which named cases actually ran in CI logs.

Chromium currently reuses the CDP target id and Playwright `Worker` wrapper when
restarting the same service-worker version. The MV3 case therefore also requires
an observed `stopped` lifecycle state and a fresh worker-realm nonce; the old nonce
must be absent before the popup recovery assertion is allowed to pass.

Normal release builds still use:

```bash
npm run build --workspace @vaultkern/browser-extension
```

Normal builds do not write the dev/test `key` into `dist/manifest.json`. If the extension is uploaded to Chrome Web Store later, replace the dev/test public key with the production public key from Chrome Developer Dashboard and update the native host allowed origin for the production extension id.
