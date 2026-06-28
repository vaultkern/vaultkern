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

function isInterruptibleReadCommand(message: unknown) {
  switch (commandTypeFromMessage(message)) {
    case "preload_current_vault":
    case "list_entries":
    case "find_fill_candidates":
    case "get_entry_detail":
    case "list_groups":
    case "get_database_settings":
    case "list_entry_history":
    case "get_entry_history_detail":
    case "get_entry_attachment_content":
    case "list_one_drive_children":
      return true;
    default:
      return false;
  }
}

function preloadCanceledError() {
  return new NativeMessagingError(
    "native_port_disconnected",
    "preload canceled by startup request"
  );
}

function readCanceledError() {
  return new NativeMessagingError(
    "native_port_disconnected",
    "native read canceled by startup request"
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

function shouldCancelActiveInterruptibleRead(
  active: PendingRequest | null,
  nextMessage: unknown
) {
  return (
    isStartupCommand(nextMessage) &&
    isInterruptibleReadCommand(active?.message) &&
    !isPreloadCommand(active?.message)
  );
}

export function createNativeMessagingBridge(
  connectNative: (hostName: string) => NativePort,
  hostName: string,
  options?: { timeoutMs?: number; interactiveTimeoutMs?: number }
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
        command.type === "unlock_with_password"
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
    port = null;
  }

  function cancelActivePreload() {
    if (!activeRequest) {
      return;
    }

    cancelActiveRequest(preloadCanceledError());
  }

  function cancelActiveInterruptibleRead() {
    if (!activeRequest) {
      return;
    }

    cancelActiveRequest(readCanceledError());
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
    clearRequestTimeout(activeRequest);
    detachPort();
    rejectAll(error);
  }

  function ensurePort() {
    if (port) {
      return port;
    }

    port = connectNative(hostName);
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
      requestPort.postMessage(request.message);
    } catch (error) {
      clearRequestTimeout(request);
      activeRequest = null;
      detachPort();
      request.reject(toNativeMessagingError(error, "native_unknown"));

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
        } else if (shouldCancelActiveInterruptibleRead(activeRequest, message)) {
          cancelActiveInterruptibleRead();
        }
        cancelQueuedPreloads(message);
        enqueueRequest({ message, resolve, reject, timeoutId: null });
        flushQueue();
      });
    }
  };
}
