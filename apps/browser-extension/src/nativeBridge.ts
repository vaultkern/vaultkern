type NativePort = {
  postMessage: (message: unknown) => void;
  disconnect: () => void;
  onMessage: {
    addListener: (listener: (message: unknown) => void) => void;
  };
  onDisconnect: {
    addListener: (listener: () => void) => void;
  };
};

type NativeMessagingErrorCode =
  | "native_host_missing"
  | "native_permission_denied"
  | "native_port_disconnected"
  | "native_timeout"
  | "native_unknown";

type PendingRequest = {
  message: unknown;
  wireMessage: unknown;
  requestId: string;
  resolve: (response: unknown) => void;
  reject: (error: Error) => void;
  timeoutId: ReturnType<typeof setTimeout> | null;
  chunks: {
    count: number;
    nextIndex: number;
    totalCharacters: number;
    parts: string[];
  } | null;
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
    normalized.includes("native port disconnected")
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

const NATIVE_RESPONSE_GRACE_MS = 1_000;
const MAX_NATIVE_RESPONSE_CHUNKS = 256;
const MAX_CHUNKED_RESPONSE_CHARACTERS = 64 * 1024 * 1024;

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

function attachRequestId(
  message: unknown,
  requestId: string,
  requestTimeoutMs: number
) {
  if (typeof message === "object" && message !== null && !Array.isArray(message)) {
    return { ...message, requestId, requestTimeoutMs };
  }

  return { requestId, requestTimeoutMs, payload: message };
}

function requestIdFromResponse(response: unknown) {
  if (typeof response !== "object" || response === null || !("requestId" in response)) {
    return null;
  }

  const requestId = (response as { requestId?: unknown }).requestId;
  return typeof requestId === "string" ? requestId : null;
}

function stripResponseRequestId(response: unknown) {
  if (typeof response !== "object" || response === null || !("requestId" in response)) {
    return response;
  }

  const { requestId: _requestId, ...rest } = response as Record<string, unknown>;
  return rest;
}

function nativeResponseChunk(response: unknown) {
  if (
    typeof response !== "object" ||
    response === null ||
    (response as { type?: unknown }).type !== "native_response_chunk"
  ) {
    return null;
  }
  const chunk = response as {
    requestId?: unknown;
    chunkIndex?: unknown;
    chunkCount?: unknown;
    data?: unknown;
  };
  if (
    typeof chunk.requestId !== "string" ||
    !Number.isInteger(chunk.chunkIndex) ||
    !Number.isInteger(chunk.chunkCount) ||
    typeof chunk.data !== "string"
  ) {
    return false;
  }
  return {
    requestId: chunk.requestId,
    chunkIndex: chunk.chunkIndex as number,
    chunkCount: chunk.chunkCount as number,
    data: chunk.data
  };
}

function isStartupCommand(message: unknown) {
  const type = commandTypeFromMessage(message);
  return type === "get_session_state" || type === "list_recent_vaults";
}

function isPreloadCommand(message: unknown) {
  return commandTypeFromMessage(message) === "preload_current_vault";
}

function isHandshakeCommand(message: unknown) {
  return commandTypeFromMessage(message) === "handshake";
}

const STARTUP_OVERTAKEABLE_COMMANDS = new Set([
  "preload_current_vault",
  "list_groups",
  "list_entries",
  "get_entry_detail",
  "list_entry_history",
  "get_entry_history_detail",
  "get_entry_attachment_content",
  "get_database_settings",
  "find_fill_candidates",
  "find_exact_matching_entry_ids"
]);

function canStartupOvertake(message: unknown) {
  const type = commandTypeFromMessage(message);
  return type !== null && STARTUP_OVERTAKEABLE_COMMANDS.has(type);
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

// This list only grants enough UI time for the runtime's interactive gate.
// The Rust runtime owns and exhaustively enforces the authorization policy.
const FRESH_VERIFICATION_COMMANDS = new Set([
  "create_autofill_entry",
  "update_autofill_entry_fields"
]);

function commandRequiresFreshVerification(command: Record<string, unknown>) {
  return (
    typeof command.type === "string" &&
    FRESH_VERIFICATION_COMMANDS.has(command.type)
  );
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
  let nextRequestId = 0;
  let connectionGeneration = 0;

  function timeoutForMessage(message: unknown) {
    if (
      typeof message === "object" &&
      message !== null &&
      "command" in message &&
      typeof (message as { command?: unknown }).command === "object" &&
      (message as { command?: unknown }).command !== null
    ) {
      const command = (message as { command: Record<string, unknown> }).command;
      if (
        commandRequiresFreshVerification(command) ||
        command.type === "create_passkey_assertion" ||
        command.type === "create_passkey_registration" ||
        command.type === "verify_passkey_user" ||
        command.type === "save_passkey_registration" ||
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
      connectionGeneration += 1;
      try {
        options?.onPortDetached?.();
      } catch {
        // Detach observers must not mask native messaging failures.
      }
    }
  }

  function interruptActivePreload() {
    const request = activeRequest;
    const requestPort = port;
    if (!request) {
      return;
    }

    activeRequest = null;
    clearRequestTimeout(request);
    detachPort();
    request.reject(preloadCanceledError());

    try {
      requestPort?.disconnect();
    } catch {
      // The interrupted preload was already rejected and will not be replayed.
    }
  }

  function prepareForSend(message: unknown) {
    cancelQueuedPreloads(message);
    if (shouldCancelActivePreload(activeRequest, message)) {
      interruptActivePreload();
    }
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
    if (isHandshakeCommand(request.message) && port === null) {
      queuedRequests.unshift(request);
      return;
    }

    if (!isStartupCommand(request.message)) {
      queuedRequests.push(request);
      return;
    }

    let insertionIndex = queuedRequests.length;
    for (let index = queuedRequests.length - 1; index >= 0; index -= 1) {
      if (!canStartupOvertake(queuedRequests[index].message)) {
        insertionIndex = index + 1;
        break;
      }
      insertionIndex = index;
    }

    queuedRequests.splice(insertionIndex, 0, request);
  }

  function onNativeMessage(attachedPort: NativePort, response: unknown) {
    if (port !== attachedPort || !activeRequest) {
      return;
    }

    const request = activeRequest;
    const chunk = nativeResponseChunk(response);
    if (chunk === false) {
      rejectProtocolConnection(attachedPort, "native response chunk is malformed");
      return;
    }
    if (chunk) {
      if (
        chunk.requestId !== request.requestId ||
        chunk.chunkCount < 2 ||
        chunk.chunkCount > MAX_NATIVE_RESPONSE_CHUNKS ||
        chunk.chunkIndex < 0 ||
        chunk.chunkIndex >= chunk.chunkCount
      ) {
        rejectProtocolConnection(attachedPort, "native response chunk sequence is invalid");
        return;
      }
      if (chunk.chunkIndex === 0) {
        if (request.chunks !== null) {
          rejectProtocolConnection(attachedPort, "native response chunk sequence restarted");
          return;
        }
        request.chunks = {
          count: chunk.chunkCount,
          nextIndex: 0,
          totalCharacters: 0,
          parts: []
        };
      }
      const chunks = request.chunks;
      if (
        !chunks ||
        chunks.count !== chunk.chunkCount ||
        chunks.nextIndex !== chunk.chunkIndex ||
        chunks.totalCharacters + chunk.data.length >
          MAX_CHUNKED_RESPONSE_CHARACTERS
      ) {
        rejectProtocolConnection(attachedPort, "native response chunk sequence is invalid");
        return;
      }
      chunks.parts.push(chunk.data);
      chunks.totalCharacters += chunk.data.length;
      chunks.nextIndex += 1;
      if (chunks.nextIndex !== chunks.count) {
        return;
      }
      let assembled: unknown;
      try {
        assembled = JSON.parse(chunks.parts.join(""));
      } catch {
        rejectProtocolConnection(attachedPort, "native response chunks are not valid JSON");
        return;
      }
      request.chunks = null;
      onNativeMessage(attachedPort, assembled);
      return;
    }
    if (request.chunks !== null) {
      rejectProtocolConnection(attachedPort, "native response interrupted a chunk sequence");
      return;
    }
    const responseRequestId = requestIdFromResponse(response);
    if (responseRequestId !== request.requestId) {
      rejectProtocolConnection(
        attachedPort,
        responseRequestId === null
          ? "native response is missing its request ID"
          : "native response request ID does not match the active request"
      );
      return;
    }
    emitEvent({
      event: "response",
      commandType: commandTypeFromMessage(request.message)
    });
    activeRequest = null;
    clearRequestTimeout(request);
    request.resolve(stripResponseRequestId(response));
    flushQueue();
  }

  function rejectProtocolConnection(attachedPort: NativePort, message: string) {
    if (port !== attachedPort) {
      return;
    }
    const error = new NativeMessagingError("native_unknown", message);
    detachPort();
    rejectAll(error);
    try {
      attachedPort.disconnect();
    } catch {
      // The protocol-invalid connection is already detached.
    }
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
    connectionGeneration += 1;
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
      const requestPort = ensurePort();
      request.timeoutId = setTimeout(() => {
        if (activeRequest !== request || port !== requestPort) {
          return;
        }

        const error = timeoutError();
        detachPort();
        rejectAll(error);

        try {
          requestPort.disconnect();
        } catch {
          // The timed-out connection and all work queued behind it are already rejected.
        }
      }, timeoutForMessage(request.message) + NATIVE_RESPONSE_GRACE_MS);
      emitEvent({
        event: "post",
        commandType: commandTypeFromMessage(request.message)
      });
      requestPort.postMessage(request.wireMessage);
    } catch (error) {
      clearRequestTimeout(request);
      if (activeRequest !== request) {
        return;
      }
      const failedPort = port;
      detachPort();
      try {
        failedPort?.disconnect();
      } catch {
        // The failed post is already detached and will not reuse this port.
      }
      const nativeError = toNativeMessagingError(error, "native_unknown");
      emitEvent({
        event: "post_error",
        commandType: commandTypeFromMessage(request.message),
        code: nativeError.code,
        message: nativeError.message
      });
      rejectAll(nativeError);
    }
  }

  return {
    connectionGeneration() {
      return connectionGeneration;
    },
    prepareForSend,
    send(message: unknown) {
      return new Promise<unknown>((resolve, reject) => {
        prepareForSend(message);
        const requestId = `native-${++nextRequestId}`;
        const requestTimeoutMs = timeoutForMessage(message);
        enqueueRequest({
          message,
          wireMessage: attachRequestId(message, requestId, requestTimeoutMs),
          requestId,
          resolve,
          reject,
          timeoutId: null,
          chunks: null
        });
        flushQueue();
      });
    }
  };
}
