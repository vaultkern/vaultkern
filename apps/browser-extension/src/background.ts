import { createNativeMessagingBridge } from "./nativeBridge";

const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;

function isRuntimeCommand(message: unknown): message is { version: number; command: unknown } {
  return (
    typeof message === "object" &&
    message !== null &&
    "version" in message &&
    "command" in message &&
    (message as { version?: unknown }).version === 1
  );
}

function serializeError(error: unknown) {
  if (
    error instanceof Error &&
    "code" in error &&
    typeof (error as { code?: unknown }).code === "string"
  ) {
    return {
      code: (error as { code: string }).code,
      message: error.message
    };
  }

  return {
    code: "native_unknown",
    message: error instanceof Error ? error.message : "native messaging failed"
  };
}

const nativeBridge =
  chromeApi?.runtime?.connectNative && chromeApi?.runtime?.onMessage
    ? createNativeMessagingBridge(
        chromeApi.runtime.connectNative.bind(chromeApi.runtime),
        "com.vaultkern.runtime"
      )
    : null;

if (chromeApi?.runtime?.onMessage && nativeBridge) {
  chromeApi.runtime.onMessage.addListener(
    (
      message: unknown,
      _sender: unknown,
      sendResponse: (response: unknown) => void
    ) => {
      if (!isRuntimeCommand(message)) {
        return false;
      }

      nativeBridge
        .send(message)
        .then(sendResponse, (error) =>
          sendResponse({ error: serializeError(error) })
        );

      return true;
    }
  );
}
