export const SMOKE_HOST = "localhost";

export function smokeUrl(port, page) {
  return `http://${SMOKE_HOST}:${port}/${page}`;
}

export function smokePageUrls(port) {
  return {
    basicLogin: smokeUrl(port, "basic-login.html"),
    noisyLogin: smokeUrl(port, "noisy-login.html"),
    usernameFirst: smokeUrl(port, "username-first.html"),
    passwordStep: smokeUrl(port, "password-step.html"),
    passkeyRegister: smokeUrl(port, "passkey-register.html"),
    passkeyLogin: smokeUrl(port, "passkey-login.html")
  };
}
