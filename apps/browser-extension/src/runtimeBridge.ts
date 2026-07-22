import {
  RUNTIME_PROTOCOL_VERSION,
  type RuntimeTransport
} from "@vaultkern/runtime-web-client";

const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;

class ExtensionTransportError extends Error {
  constructor(
    public readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "ExtensionTransportError";
  }
}

function runtimeMessagingUnavailableError() {
  return new ExtensionTransportError(
    "runtime_messaging_unavailable",
    "runtime messaging is unavailable"
  );
}

function isStructuredErrorResponse(
  response: unknown
): response is { error: { code: string; message: string } } {
  return (
    typeof response === "object" &&
    response !== null &&
    "error" in response &&
    typeof (response as { error?: unknown }).error === "object" &&
    (response as { error?: unknown }).error !== null &&
    typeof ((response as { error: { code?: unknown } }).error.code) === "string" &&
    typeof ((response as { error: { message?: unknown } }).error.message) ===
      "string"
  );
}

async function sendBackgroundMessage(message: unknown) {
  if (!chromeApi?.runtime?.sendMessage) {
    throw runtimeMessagingUnavailableError();
  }

  const response = await chromeApi.runtime.sendMessage(message);

  if (isStructuredErrorResponse(response)) {
    throw new ExtensionTransportError(
      response.error.code,
      response.error.message
    );
  }

  if (
    response &&
    typeof response === "object" &&
    "error" in response &&
    typeof (response as { error?: unknown }).error === "string"
  ) {
    throw new ExtensionTransportError(
      "native_unknown",
      (response as { error: string }).error
    );
  }

  return response;
}

export async function sendRuntimeCommand(command: unknown) {
  return extensionTransport.send({
    version: RUNTIME_PROTOCOL_VERSION,
    command
  });
}

export const extensionTransport: RuntimeTransport = { send: sendBackgroundMessage };
