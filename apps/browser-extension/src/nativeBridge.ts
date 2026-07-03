type NativePort = chrome.runtime.Port;

type NativeMessagingErrorCode =
  | "native_host_missing"
  | "native_permission_denied"
  | "native_port_disconnected"
  | "native_timeout"
  | "native_unknown";

type PendingRequest = {
  message: unknown;
  resolve: (response: unknown) => void;
  reject: (error: Error) => void;
  timeoutId: ReturnType<typeof setTimeout> | null;
  postMessageAttempts: number;
};

type NativeBridgeEvent = {
  event: "connect" | "post" | "response" | "disconnect" | "post_error";
  commandType?: string | null;
  message?: string;
  code?: NativeMessagingErrorCode;
};

export class NativeMessagingError extends Error {
  constructor(
    public readonly code: NativeMessagingErrorCode,
    message: string
  ) {
    super(message);
    this.name = "NativeMessagingError";
  }
}

function classifyNativeMessagingError(
  message: string,
  fallback: NativeMessagingErrorCode
): NativeMessagingErrorCode {
  const normalized = message.toLowerCase();

  if (
    normalized.includes("host not found") ||
    normalized.includes("native messaging host not found")
  ) {
    return "native_host_missing";
  }

  if (
    normalized.includes("forbidden") ||
    normalized.includes("not allowed") ||
    normalized.includes("permission")
  ) {
    return "native_permission_denied";
  }

  if (
    normalized.includes("host has exited") ||
    normalized.includes("port closed") ||
    normalized.includes("port disconnected") ||
    normalized.includes("native port disconnected") ||
    normalized.includes("disconnected")
  ) {
    return "native_port_disconnected";
  }

  return fallback;
}

function toNativeMessagingError(
  error: unknown,
  fallback: NativeMessagingErrorCode
) {
  if (error instanceof NativeMessagingError) {
    return error;
  }

  const message =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "native messaging failed";

  return new NativeMessagingError(
    classifyNativeMessagingError(message, fallback),
    message
  );
}

function disconnectError() {
  const message =
    (globalThis as typeof globalThis & {
      chrome?: { runtime?: { lastError?: { message?: string } } };
    }).chrome?.runtime?.lastError?.message ?? "native port disconnected";

  return new NativeMessagingError(
    classifyNativeMessagingError(message, "native_port_disconnected"),
    message
  );
}

function timeoutError() {
  return new NativeMessagingError("native_timeout", "native messaging timed out");
}

function commandTypeFromMessage(message: unknown) {
  if (
    typeof message !== "object" ||
    message === null ||
    !("command" in message) ||
    typeof (message as { command?: unknown }).command !== "object" ||
    (message as { command?: unknown }).command === null
  ) {
    return null;
  }

  const command = (message as { command: { type?: unknown } }).command;
  return typeof command.type === "string" ? command.type : null;
}

function isStartupCommand(message: unknown) {
  const type = commandTypeFromMessage(message);
  return type === "get_session_state" || type === "list_recent_vaults";
}

function isPreloadCommand(message: unknown) {
  return commandTypeFromMessage(message) === "preload_current_vault";
}

function preloadCanceledError() {
  return new NativeMessagingError(
    "native_port_disconnected",
    "preload canceled by startup request"
  );
}

function shouldCancelActivePreload(
  active: PendingRequest | null,
  nextMessage: unknown
) {
  if (!isPreloadCommand(active?.message)) {
    return false;
  }

  return isStartupCommand(nextMessage);
}

export function createNativeMessagingBridge(
  connectNative: (hostName: string) => NativePort,
  hostName: string,
  options?: {
    timeoutMs?: number;
    interactiveTimeoutMs?: number;
    onPortDetached?: () => void;
    onEvent?: (event: NativeBridgeEvent) => void;
  }
) {
  const timeoutMs = options?.timeoutMs ?? 30_000;
  const interactiveTimeoutMs = options?.interactiveTimeoutMs ?? 5 * 60_000;
  let port: NativePort | null = null;
  let activeRequest: PendingRequest | null = null;
  const queuedRequests: PendingRequest[] = [];

  function timeoutForMessage(message: unknown) {
    if (
      typeof message === "object" &&
      message !== null &&
      "command" in message &&
      typeof (message as { command?: unknown }).command === "object" &&
      (message as { command?: unknown }).command !== null
    ) {
      const command = (message as { command: { type?: unknown; path?: unknown } }).command;
      if (
        (command.type === "add_local_vault_reference" && command.path === undefined) ||
        command.type === "unlock_current_vault" ||
        command.type === "unlock_current_vault_with_password" ||
        command.type === "unlock_with_password" ||
        command.type === "enable_quick_unlock_for_current_vault" ||
        command.type === "unlock_current_vault_with_quick_unlock" ||
        command.type === "create_passkey_assertion" ||
        command.type === "create_passkey_registration" ||
        command.type === "save_passkey_registration" ||
        command.type === "save_vault" ||
        command.type === "abort_passkey_registration" ||
        command.type === "commit_passkey_registration"
      ) {
        return interactiveTimeoutMs;
      }
    }

    return timeoutMs;
  }

  function clearRequestTimeout(request: PendingRequest | null) {
    if (request?.timeoutId) {
      clearTimeout(request.timeoutId);
      request.timeoutId = null;
    }
  }

  function emitEvent(event: NativeBridgeEvent) {
    try {
      options?.onEvent?.(event);
    } catch {
      // Diagnostics must not affect native messaging behavior.
    }
  }

  function rejectAll(error: Error) {
    clearRequestTimeout(activeRequest);
    if (activeRequest) {
      activeRequest.reject(error);
      activeRequest = null;
    }

    while (queuedRequests.length > 0) {
      const request = queuedRequests.shift();
      clearRequestTimeout(request ?? null);
      request?.reject(error);
    }
  }

  function detachPort() {
    const hadPort = port !== null;
    port = null;
    if (hadPort) {
      try {
        options?.onPortDetached?.();
      } catch {
        // Detach observers must not mask native messaging failures.
      }
    }
  }

  function cancelActivePreload() {
    if (!activeRequest) {
      return;
    }

    cancelActiveRequest(preloadCanceledError());
  }

  function cancelActiveRequest(error: Error) {
    const request = activeRequest;
    const requestPort = port;
    activeRequest = null;
    clearRequestTimeout(request);
    detachPort();

    try {
      requestPort?.disconnect();
    } catch {
      // The stale request is already being rejected locally.
    }

    request.reject(error);
  }

  function cancelQueuedPreloads(nextMessage: unknown) {
    if (!isStartupCommand(nextMessage)) {
      return;
    }

    for (let index = queuedRequests.length - 1; index >= 0; index -= 1) {
      const request = queuedRequests[index];

      if (!isPreloadCommand(request.message)) {
        continue;
      }

      queuedRequests.splice(index, 1);
      clearRequestTimeout(request);
      request.reject(preloadCanceledError());
    }
  }

  function enqueueRequest(request: PendingRequest) {
    if (!isStartupCommand(request.message)) {
      queuedRequests.push(request);
      return;
    }

    const firstNonStartupIndex = queuedRequests.findIndex(
      (queuedRequest) => !isStartupCommand(queuedRequest.message)
    );

    if (firstNonStartupIndex === -1) {
      queuedRequests.push(request);
      return;
    }

    queuedRequests.splice(firstNonStartupIndex, 0, request);
  }

  function onNativeMessage(attachedPort: NativePort, response: unknown) {
    if (port !== attachedPort || !activeRequest) {
      return;
    }

    const request = activeRequest;
    emitEvent({
      event: "response",
      commandType: commandTypeFromMessage(request.message)
    });
    activeRequest = null;
    clearRequestTimeout(request);
    request.resolve(response);
    flushQueue();
  }

  function onNativeDisconnect(attachedPort: NativePort) {
    if (port !== attachedPort) {
      return;
    }

    const error = disconnectError();
    emitEvent({
      event: "disconnect",
      commandType: commandTypeFromMessage(activeRequest?.message),
      code: error.code,
      message: error.message
    });
    clearRequestTimeout(activeRequest);
    detachPort();
    rejectAll(error);
  }

  function ensurePort() {
    if (port) {
      return port;
    }

    port = connectNative(hostName);
    emitEvent({ event: "connect" });
    const attachedPort = port;
    port.onMessage.addListener((response: unknown) =>
      onNativeMessage(attachedPort, response)
    );
    port.onDisconnect.addListener(() => onNativeDisconnect(attachedPort));
    return port;
  }

  function flushQueue() {
    if (activeRequest || queuedRequests.length === 0) {
      return;
    }

    const request = queuedRequests.shift();

    if (!request) {
      return;
    }

    activeRequest = request;

    try {
      request.postMessageAttempts += 1;
      const requestPort = ensurePort();
      request.timeoutId = setTimeout(() => {
        if (activeRequest !== request || port !== requestPort) {
          return;
        }

        activeRequest = null;
        clearRequestTimeout(request);
        detachPort();

        try {
          requestPort.disconnect();
        } catch {
          // Ignore disconnect failures after timeout; the request is already rejected.
        }

        request.reject(timeoutError());
        flushQueue();
      }, timeoutForMessage(request.message));
      emitEvent({
        event: "post",
        commandType: commandTypeFromMessage(request.message)
      });
      requestPort.postMessage(request.message);
    } catch (error) {
      clearRequestTimeout(request);
      activeRequest = null;
      detachPort();
      const nativeError = toNativeMessagingError(error, "native_unknown");
      emitEvent({
        event: "post_error",
        commandType: commandTypeFromMessage(request.message),
        code: nativeError.code,
        message: nativeError.message
      });
      if (
        nativeError.code === "native_port_disconnected" &&
        request.postMessageAttempts < 2
      ) {
        queuedRequests.unshift(request);
        flushQueue();
        return;
      }

      request.reject(nativeError);

      if (queuedRequests.length > 0) {
        flushQueue();
      }
    }
  }

  return {
    send(message: unknown) {
      return new Promise<unknown>((resolve, reject) => {
        if (shouldCancelActivePreload(activeRequest, message)) {
          cancelActivePreload();
        }
        cancelQueuedPreloads(message);
        enqueueRequest({ message, resolve, reject, timeoutId: null, postMessageAttempts: 0 });
        flushQueue();
      });
    }
  };
}
