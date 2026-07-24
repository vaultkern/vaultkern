import type {
  AutofillUpdateFields,
  CommittedAutofillMutation,
  EntrySummary
} from "@vaultkern/runtime-web-client";

import { sameExactHttpOrigin } from "../autofill/originPolicy";
import type {
  PendingAutofillDesiredFields,
  PendingAutofillSubmission,
  PendingAutofillTransaction,
  PendingAutofillUpdateFields
} from "../autofill/pendingSubmission";
import { popupErrorMessage } from "./popupError";

export type ResidentLoginMutation =
  | {
      mode: "update";
      entryId: string;
      expectedFields: PendingAutofillUpdateFields;
      desiredFields: PendingAutofillUpdateFields;
    }
  | {
      mode: "create";
      parentGroupId: string;
      expectedMatchingEntryIds: string[];
      desiredFields: PendingAutofillDesiredFields;
    };

export type PendingLoginPrompt =
  | {
      readonly mode: "save";
      readonly vaultId: string;
      readonly siteLabel: string;
      readonly action: "save" | "save_new";
      readonly canDismiss: true;
      readonly ambiguous?: true;
    }
  | {
      readonly mode: "update";
      readonly vaultId: string;
      readonly siteLabel: string;
      readonly action: "update";
      readonly canDismiss: true;
    }
  | {
      readonly mode: "retry";
      readonly vaultId: string;
      readonly siteLabel: string;
      readonly action: "retry_lookup";
      readonly canDismiss: true;
    }
  | {
      readonly mode: "cleanup";
      readonly vaultId: string;
      readonly siteLabel: string;
      readonly action: "retry_cleanup";
      readonly canDismiss: false;
    };

type PendingLoginPromptInput =
  | Omit<Extract<PendingLoginPrompt, { mode: "save" }>, "action" | "canDismiss">
  | Omit<Extract<PendingLoginPrompt, { mode: "update" }>, "action" | "canDismiss">
  | Omit<Extract<PendingLoginPrompt, { mode: "retry" }>, "action" | "canDismiss">
  | Omit<Extract<PendingLoginPrompt, { mode: "cleanup" }>, "action" | "canDismiss">;

export type PendingLoginPromptLoad = {
  prompt: PendingLoginPrompt | null;
  errorMessage?: string;
};

export type PendingLoginSaveResult =
  | {
      status: "saved";
      candidates: EntrySummary[] | null;
    }
  | {
      status: "dismissed";
    }
  | {
      status: "expired";
    }
  | {
      status: "retry";
      prompt: PendingLoginPrompt;
      errorMessage: string;
    };

type PendingLoginDependencies = {
  load(): Promise<PendingAutofillTransaction | null>;
  findCandidates(vaultId: string, siteUrl?: string): Promise<EntrySummary[]>;
  getEntryFields(
    vaultId: string,
    entryId: string,
    url: string
  ): Promise<{ id: string; fields: AutofillUpdateFields }>;
  getCreateContext(vaultId: string): Promise<{ rootGroupId: string }>;
  findExactMatchingEntryIds(
    vaultId: string,
    fields: PendingAutofillDesiredFields
  ): Promise<string[]>;
  dismiss(transactionId: string, tabId: number): Promise<boolean>;
  commit(
    vaultId: string,
    mutation: ResidentLoginMutation
  ): Promise<CommittedAutofillMutation>;
};

export interface PendingLoginWorkflow {
  loadPrompt(vaultId: string): Promise<PendingLoginPromptLoad>;
  save(prompt: PendingLoginPrompt): Promise<PendingLoginSaveResult>;
  dismiss(prompt: PendingLoginPrompt): Promise<void>;
}

function pendingPassword(submission: PendingAutofillSubmission) {
  return submission.newPassword ?? submission.password;
}

function siteLabel(transaction: PendingAutofillTransaction) {
  try {
    return new URL(transaction.submission.url).host || transaction.submission.url;
  } catch {
    return transaction.submission.url;
  }
}

function savedUrl(transaction: PendingAutofillTransaction) {
  try {
    const url = new URL(transaction.submission.url);
    url.search = "";
    url.hash = "";
    return url.href;
  } catch {
    return transaction.submission.url.split(/[?#]/, 1)[0] || transaction.submission.url;
  }
}

function desiredCreateFields(
  transaction: PendingAutofillTransaction
): PendingAutofillDesiredFields {
  return {
    title: siteLabel(transaction),
    username: transaction.submission.username,
    password: pendingPassword(transaction.submission),
    url: savedUrl(transaction),
    notes: "",
    totpUri: null,
    customFields: []
  };
}

function commitOutcomeIsUnknown(error: unknown) {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return false;
  }
  const code = (error as { code?: unknown }).code;
  return (
    code === "native_port_disconnected" ||
    code === "native_timeout" ||
    code === "request_outcome_unknown"
  );
}

async function refreshedCandidates(
  dependencies: PendingLoginDependencies,
  vaultId: string
) {
  try {
    return await dependencies.findCandidates(vaultId);
  } catch {
    return null;
  }
}

export function createPendingLoginWorkflow(
  dependencies: PendingLoginDependencies
): PendingLoginWorkflow {
  const promptBindings = new WeakMap<
    PendingLoginPrompt,
    {
      vaultId: string;
      transaction: PendingAutofillTransaction;
      updateEntryId?: string;
      expectedMatchingEntryIds?: string[];
    }
  >();

  function bindPrompt(
    input: PendingLoginPromptInput,
    transaction: PendingAutofillTransaction,
    options: {
      updateEntryId?: string;
      expectedMatchingEntryIds?: string[];
    } = {}
  ): PendingLoginPrompt {
    const action =
      input.mode === "cleanup"
        ? "retry_cleanup"
        : input.mode === "retry"
          ? "retry_lookup"
          : input.mode === "update"
            ? "update"
            : input.ambiguous
              ? "save_new"
              : "save";
    const prompt = Object.freeze({
      ...input,
      action,
      canDismiss: input.mode !== "cleanup"
    }) as PendingLoginPrompt;
    promptBindings.set(prompt, {
      vaultId: input.vaultId,
      transaction,
      ...options
    });
    return prompt;
  }

  function bindingFor(prompt: PendingLoginPrompt) {
    const binding = promptBindings.get(prompt);
    if (!binding) {
      throw new Error("Pending login save is no longer available");
    }
    return binding;
  }

  async function dismissPrompt(prompt: PendingLoginPrompt) {
    const { transaction } = bindingFor(prompt);
    if (
      !(await dependencies.dismiss(
        transaction.transactionId,
        transaction.tabId
      ))
    ) {
      throw new Error("Failed to discard login save");
    }
  }

  async function loadCreatePrompt(
    vaultId: string,
    transaction: PendingAutofillTransaction,
    ambiguous = false
  ): Promise<PendingLoginPromptLoad> {
    let expectedMatchingEntryIds: string[];
    try {
      expectedMatchingEntryIds =
        await dependencies.findExactMatchingEntryIds(
          vaultId,
          desiredCreateFields(transaction)
        );
    } catch (lookupFailure) {
      return {
        prompt: bindPrompt(
          { mode: "retry", vaultId, siteLabel: siteLabel(transaction) },
          transaction
        ),
        errorMessage: popupErrorMessage(
          lookupFailure,
          "Failed to check the pending login"
        )
      };
    }
    if (expectedMatchingEntryIds.length > 0) {
      return {
        prompt: bindPrompt(
          { mode: "cleanup", vaultId, siteLabel: siteLabel(transaction) },
          transaction
        ),
        errorMessage:
          "This login is already present in the active vault. Clear the pending prompt instead of saving it again."
      };
    }
    return {
      prompt: bindPrompt(
        {
          mode: "save",
          vaultId,
          siteLabel: siteLabel(transaction),
          ...(ambiguous ? { ambiguous: true as const } : {})
        },
        transaction,
        { expectedMatchingEntryIds }
      )
    };
  }

  return {
    async loadPrompt(vaultId) {
      const transaction = await dependencies.load();
      if (!transaction) {
        return { prompt: null };
      }
      const submission = transaction.submission;
      if (submission.saveOnly) {
        return loadCreatePrompt(vaultId, transaction);
      }

      let candidates: EntrySummary[];
      try {
        candidates = await dependencies.findCandidates(vaultId, submission.url);
      } catch (lookupFailure) {
        return {
          prompt: bindPrompt(
            { mode: "retry", vaultId, siteLabel: siteLabel(transaction) },
            transaction
          ),
          errorMessage: popupErrorMessage(
            lookupFailure,
            "Failed to match pending login"
          )
        };
      }

      const exactOriginCandidates = candidates.filter((entry) =>
        sameExactHttpOrigin(entry.url, submission.url)
      );
      const submittedUsername = submission.username.trim();
      const matchingEntries =
        submittedUsername === ""
          ? exactOriginCandidates
          : exactOriginCandidates.filter(
              (entry) => entry.username === submittedUsername
            );
      if (matchingEntries.length === 1) {
        return {
          prompt: bindPrompt(
            { mode: "update", vaultId, siteLabel: siteLabel(transaction) },
            transaction,
            { updateEntryId: matchingEntries[0].id }
          )
        };
      }
      return loadCreatePrompt(
        vaultId,
        transaction,
        matchingEntries.length > 1
      );
    },

    async save(prompt) {
      const binding = bindingFor(prompt);
      const { transaction, vaultId } = binding;
      const submission = transaction.submission;
      let mutation: ResidentLoginMutation;

      if (prompt.mode === "cleanup") {
        try {
          await dismissPrompt(prompt);
          return { status: "dismissed" };
        } catch (error) {
          return {
            status: "retry",
            prompt,
            errorMessage: popupErrorMessage(
              error,
              "Failed to clear the saved login prompt"
            )
          };
        }
      }
      if (prompt.mode === "update") {
        const entryId = binding.updateEntryId;
        if (!entryId) {
          throw new Error("Pending login update target is no longer available");
        }
        const result = await dependencies.getEntryFields(
          vaultId,
          entryId,
          submission.url
        );
        if (result.id !== entryId) {
          throw new Error("Autofill entry detail did not match the requested entry");
        }
        if (
          typeof submission.newPassword === "string" &&
          result.fields.password !== submission.password
        ) {
          await dismissPrompt(prompt);
          return { status: "dismissed" };
        }
        mutation = {
          mode: "update",
          entryId,
          expectedFields: result.fields,
          desiredFields: {
            username:
              submission.username.trim() === ""
                ? result.fields.username
                : submission.username,
            password: pendingPassword(submission),
            url: result.fields.url || savedUrl(transaction)
          }
        };
      } else if (prompt.mode === "save") {
        const createContext = await dependencies.getCreateContext(vaultId);
        if (!binding.expectedMatchingEntryIds) {
          throw new Error("Pending login create precondition is no longer available");
        }
        mutation = {
          mode: "create",
          parentGroupId: createContext.rootGroupId,
          expectedMatchingEntryIds: binding.expectedMatchingEntryIds,
          desiredFields: desiredCreateFields(transaction)
        };
      } else {
        throw new Error("Reconnect before retrying the pending login save");
      }

      let committed: CommittedAutofillMutation;
      try {
        committed = await dependencies.commit(vaultId, mutation);
      } catch (error) {
        return {
          status: "retry",
          prompt: bindPrompt(
            { mode: "retry", vaultId, siteLabel: prompt.siteLabel },
            transaction
          ),
          errorMessage: commitOutcomeIsUnknown(error)
            ? "Login save result is unknown. Reconnect to inspect the vault or retry manually."
            : popupErrorMessage(error, "Failed to save login")
        };
      }

      if (committed.publication.status === "conflict_split") {
        const conflictCopy = committed.publication.conflictCopyPath
          ? ` Conflict copy: ${committed.publication.conflictCopyPath}`
          : "";
        return {
          status: "retry",
          prompt: bindPrompt(
            { mode: "retry", vaultId, siteLabel: prompt.siteLabel },
            transaction
          ),
          errorMessage:
            "The login was preserved in a conflict copy, but the active vault was not updated. Review the current vault before saving again." +
            conflictCopy
        };
      }

      try {
        await dismissPrompt(prompt);
      } catch {
        return {
          status: "retry",
          prompt: bindPrompt(
            { mode: "cleanup", vaultId, siteLabel: prompt.siteLabel },
            transaction
          ),
          errorMessage:
            "The login was saved, but its pending prompt could not be cleared. Retry cleanup without saving again."
        };
      }
      return {
        status: "saved",
        candidates: await refreshedCandidates(dependencies, vaultId)
      };
    },

    dismiss: dismissPrompt
  };
}
