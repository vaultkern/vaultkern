import type {
  ResidentAppRoute,
  SessionState
} from "@vaultkern/runtime-web-client";

export type PasskeyPromptMode = "unlock" | "approve" | "verify";

export type PasskeyCredentialOption = {
  credentialId: string;
  username: string;
};

type SessionStateLike = Pick<SessionState, "unlocked" | "activeVaultId">;

type PasskeyPromptRuntime = {
  getSessionState(): Promise<SessionStateLike>;
  recordUserActivity(): Promise<SessionStateLike>;
  activateResidentApp(route: ResidentAppRoute): Promise<void>;
};

type PasskeyPromptContext = {
  mode: PasskeyPromptMode;
  requestId?: number;
  origin?: string;
  relyingParty?: string;
  topOrigin?: string;
  nonce?: string;
};

export type PasskeyPromptCompletion =
  | { type: "unlock" }
  | { type: "presence"; credentialId?: string }
  | { type: "user_verification" };

export type PasskeyPromptCompletionResult = {
  keepOpen: boolean;
  credentialOptions: PasskeyCredentialOption[];
};

export interface BrowserPasskeyPromptWorkflow {
  readonly request: {
    mode: PasskeyPromptMode;
    siteLabel: string;
  };
  getSessionState(): Promise<SessionStateLike>;
  recordUserActivity(): Promise<SessionStateLike>;
  activateResidentApp(route: ResidentAppRoute): Promise<void>;
  loadCredentialOptions(): Promise<PasskeyCredentialOption[]>;
  complete(
    completion: PasskeyPromptCompletion
  ): Promise<PasskeyPromptCompletionResult>;
}

function promptMode(value: string | null): PasskeyPromptMode | null {
  return value === "unlock" || value === "approve" || value === "verify"
    ? value
    : null;
}

function optionalPromptValue(params: URLSearchParams, key: string) {
  const value = params.get(key);
  return value && value.trim() !== "" ? value : undefined;
}

function promptContext(search: string): PasskeyPromptContext | null {
  const params = new URLSearchParams(search);
  const mode = promptMode(params.get("webauthn"));
  if (!mode) {
    return null;
  }
  const requestIdValue = optionalPromptValue(params, "requestId");
  const parsedRequestId =
    requestIdValue === undefined ? undefined : Number(requestIdValue);
  const requestId =
    parsedRequestId !== undefined && Number.isFinite(parsedRequestId)
      ? parsedRequestId
      : undefined;
  return {
    mode,
    ...(requestId === undefined ? {} : { requestId }),
    ...(optionalPromptValue(params, "origin")
      ? { origin: optionalPromptValue(params, "origin") }
      : {}),
    ...(optionalPromptValue(params, "relyingParty")
      ? { relyingParty: optionalPromptValue(params, "relyingParty") }
      : {}),
    ...(optionalPromptValue(params, "topOrigin")
      ? { topOrigin: optionalPromptValue(params, "topOrigin") }
      : {}),
    ...(optionalPromptValue(params, "nonce")
      ? { nonce: optionalPromptValue(params, "nonce") }
      : {})
  };
}

function siteLabel(context: PasskeyPromptContext) {
  if (context.relyingParty) {
    return context.relyingParty;
  }
  if (!context.origin) {
    return "No active site";
  }
  try {
    return new URL(context.origin).host || context.origin;
  } catch {
    return context.origin;
  }
}

function chromeRuntime() {
  return (
    globalThis as typeof globalThis & {
      chrome?: {
        runtime?: {
          sendMessage?: (message: unknown) => Promise<unknown> | unknown;
        };
      };
    }
  ).chrome?.runtime;
}

function promptMessage(
  context: PasskeyPromptContext,
  type: string,
  fields: Record<string, unknown> = {}
) {
  return {
    type,
    ...(context.requestId === undefined ? {} : { requestId: context.requestId }),
    ...(context.origin ? { origin: context.origin } : {}),
    ...(context.relyingParty ? { relyingParty: context.relyingParty } : {}),
    ...(context.topOrigin ? { topOrigin: context.topOrigin } : {}),
    ...fields,
    ...(context.nonce ? { nonce: context.nonce } : {})
  };
}

function credentialOptionsFromUnknown(options: unknown): PasskeyCredentialOption[] {
  if (!Array.isArray(options)) {
    return [];
  }
  const parsed = options.map((option) => {
    const candidate = option as Partial<PasskeyCredentialOption> | null;
    if (
      !candidate ||
      typeof candidate !== "object" ||
      Array.isArray(candidate) ||
      typeof candidate.credentialId !== "string" ||
      candidate.credentialId.trim() === "" ||
      typeof candidate.username !== "string" ||
      Object.keys(candidate).some(
        (key) => key !== "credentialId" && key !== "username"
      )
    ) {
      return null;
    }
    return {
      credentialId: candidate.credentialId,
      username: candidate.username
    };
  });
  return parsed.some((option) => option === null)
    ? []
    : (parsed as PasskeyCredentialOption[]);
}

function responseKeepsPromptOpen(response: unknown) {
  return (
    typeof response === "object" &&
    response !== null &&
    (response as { keepOpen?: unknown }).keepOpen === true
  );
}

async function sendPromptMessage(
  message: Record<string, unknown>,
  closeOnCompletion: boolean
) {
  const runtime = chromeRuntime();
  const sendMessage = runtime?.sendMessage;
  if (typeof sendMessage !== "function") {
    window.close();
    return undefined;
  }

  if (!closeOnCompletion) {
    return Promise.resolve(sendMessage.call(runtime, message));
  }

  let shouldClose = true;
  try {
    const response = await Promise.resolve(sendMessage.call(runtime, message));
    if (responseKeepsPromptOpen(response)) {
      shouldClose = false;
    }
    return response;
  } catch {
    return undefined;
  } finally {
    if (shouldClose) {
      window.close();
    }
  }
}

async function loadCredentialOptions(context: PasskeyPromptContext) {
  if (context.mode !== "approve" || context.requestId === undefined) {
    return [];
  }
  const runtime = chromeRuntime();
  const sendMessage = runtime?.sendMessage;
  if (typeof sendMessage !== "function") {
    return [];
  }
  const response = await Promise.resolve(
    sendMessage.call(
      runtime,
      promptMessage(context, "vaultkern_presence_options_request")
    )
  );
  return credentialOptionsFromUnknown(
    (response as { credentialOptions?: unknown } | null)?.credentialOptions
  );
}

export function createBrowserPasskeyPromptWorkflow(
  client: PasskeyPromptRuntime,
  search: string
): BrowserPasskeyPromptWorkflow | null {
  const context = promptContext(search);
  if (!context) {
    return null;
  }

  return {
    request: {
      mode: context.mode,
      siteLabel: siteLabel(context)
    },
    getSessionState: () => client.getSessionState(),
    recordUserActivity: () => client.recordUserActivity(),
    activateResidentApp: (route) => client.activateResidentApp(route),
    loadCredentialOptions: () => loadCredentialOptions(context),
    async complete(completion) {
      if (completion.type === "unlock") {
        await sendPromptMessage(
          promptMessage(context, "vaultkern_unlock_complete"),
          true
        );
        return { keepOpen: false, credentialOptions: [] };
      }

      if (completion.type === "presence") {
        const response = await sendPromptMessage(
          promptMessage(context, "vaultkern_presence_complete", {
            ...(completion.credentialId
              ? { credentialId: completion.credentialId }
              : {})
          }),
          true
        );
        const keepOpen = responseKeepsPromptOpen(response);
        return {
          keepOpen,
          credentialOptions: keepOpen
            ? await loadCredentialOptions(context)
            : []
        };
      }

      const runtime = chromeRuntime();
      const sendMessage = runtime?.sendMessage;
      if (typeof sendMessage !== "function") {
        window.close();
        return { keepOpen: false, credentialOptions: [] };
      }
      const response = await Promise.resolve(
        sendMessage.call(
          runtime,
          promptMessage(context, "vaultkern_user_verification_complete", {
            method: "quick_unlock"
          })
        )
      );
      if (
        response &&
        typeof response === "object" &&
        (response as { ok?: unknown }).ok === false
      ) {
        const error = (response as { error?: unknown }).error;
        throw new Error(
          typeof error === "string" ? error : "Passkey verification failed"
        );
      }
      window.close();
      return { keepOpen: false, credentialOptions: [] };
    }
  };
}
