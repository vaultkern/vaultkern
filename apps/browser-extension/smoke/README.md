# Browser v0 Smoke Test

This directory contains fixed pages used by the browser extension autofill regression tests. The supported automated guard exercises the page and content-script behavior without pretending that the browser owns vault setup or unlock.

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

On Windows Chrome, use the elevated `vaultkern-native-setup` utility to register the `HKCU` native host in both registry views. The registration leaf is protected from ordinary-user writes:

```text
HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vaultkern.runtime
```

Stable Windows manifest and runtime paths:

```text
%ProgramFiles%\VaultKern\Browser Integration\com.vaultkern.runtime.chrome.json
%ProgramFiles%\VaultKern\Browser Integration\vaultkern-runtime.exe
```

On Windows the installed native host is a stateless shim: it authenticates the resident app over a per-user named pipe and forwards protocol requests to the app's single in-process runtime. It attempts to activate the packaged resident app when the pipe is absent and does not fall back to a per-port runtime. If activation fails, the popup reports `resident_unavailable`; open or restart VaultKern and retry.

Recent/current vault state, remote cache state, and the Hello/DPAPI-protected OneDrive refresh token are owned by the resident app under:

```text
C:\Users\<user>\AppData\Local\vaultkern-runtime\
```

Retired per-extension state directories may still exist after upgrading, but the Windows shim no longer reads or writes them:

```text
C:\Users\<user>\AppData\Local\vaultkern-runtime\extensions\<extension-id>\
```

The manifest should contain:

```json
{"name":"com.vaultkern.runtime","description":"VaultKern resident app IPC shim","path":"C:\\Program Files\\VaultKern\\Browser Integration\\vaultkern-runtime.exe","type":"stdio","allowed_origins":["chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/"]}
```

Open:

```text
http://localhost:4174/basic-login.html
```

Expected result:

- the popup shows fillable entries for the current site context
- an already-unlocked resident vault supplies the selected credential without another Windows Hello prompt
- a locked resident vault exposes no credential and the popup opens the resident unlock UI
- clicking fill writes the username into `#vaultkern-smoke-username`
- clicking fill writes the password into `#vaultkern-smoke-password`
- clicking the page's `Sign in` button shows `submitted:<username>:<password length>` at the bottom of the page

## Automated Guard

`apps/browser-extension/src/__tests__/fill-flow.test.ts` reads this HTML file and fills it through the real `fillLoginForm` logic. If the smoke page DOM or content-script field selection rules become incompatible, the targeted `fill-flow` test fails.

## Resident E2E Status

The former `smoke:e2e` command launched a per-extension runtime and drove
`open -> unlock -> create` through native messaging. That topology is retired, so
the command has been removed instead of preserving a test-only browser unlock
backdoor. A replacement end-to-end harness must launch the signed Windows resident
package, prepare its vault through the resident UI/control surface, and then verify
popup fill and both passkey modes through the authenticated shim. Until that harness
exists, the Vitest protocol/content tests and the manual Windows procedure above are
the supported browser checks.

Normal release builds still use:

```bash
npm run build --workspace @vaultkern/browser-extension
```

Normal builds do not write the dev/test `key` into `dist/manifest.json`. If the extension is uploaded to Chrome Web Store later, replace the dev/test public key with the production public key from Chrome Developer Dashboard and update the native host allowed origin for the production extension id.
