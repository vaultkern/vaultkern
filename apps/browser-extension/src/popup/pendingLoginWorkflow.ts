import type {
  AutofillUpdateFields,
  EntrySummary
} from "@vaultkern/runtime-web-client";

import { sameExactHttpOrigin } from "../autofill/originPolicy";
import type {
  PendingAutofillDesiredFields,
  PendingAutofillPlanInput,
  PendingAutofillSubmission,
  PendingAutofillTransaction,
  PendingAutofillUpdateFields
} from "../autofill/pendingSubmission";
import { popupErrorMessage } from "./popupError";

type PendingAutofillUpdatePlan = Extract<
  PendingAutofillPlanInput,
  { mode: "update" }
>;

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
      desiredFields: PendingAutofillDesiredFields;
    };

export type PendingLoginPrompt =
  | {
      readonly mode: "save";
      readonly vaultId: string;
      readonly siteLabel: string;
      readonly action: "save" | "save_new";
      readonly canDismiss: boolean;
      readonly ambiguous?: true;
    }
  | {
      readonly mode: "update";
      readonly vaultId: string;
      readonly siteLabel: string;
      readonly action: "update" | "retry_update" | "replan_update";
      readonly canDismiss: boolean;
    }
  | {
      readonly mode: "retry";
      readonly vaultId: string;
      readonly siteLabel: string;
      readonly action: "retry_lookup";
      readonly canDismiss: boolean;
    };

type PendingLoginPromptInput =
  | Omit<Extract<PendingLoginPrompt, { mode: "save" }>, "action" | "canDismiss">
  | Omit<Extract<PendingLoginPrompt, { mode: "update" }>, "action" | "canDismiss">
  | Omit<Extract<PendingLoginPrompt, { mode: "retry" }>, "action" | "canDismiss">;

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
  findExactMatchingEntryIds?(
    vaultId: string,
    fields: PendingAutofillDesiredFields
  ): Promise<string[]>;
  plan?(
    transactionId: string,
    tabId: number,
    vaultId: string,
    plan: PendingAutofillPlanInput
  ): Promise<PendingAutofillTransaction | null>;
  dismiss(transactionId: string, tabId: number): Promise<boolean>;
  execute?(
    transactionId: string,
    tabId: number
  ): Promise<{
    ok: boolean;
    expired?: boolean;
    pending?: PendingAutofillTransaction | null;
    errorMessage?: string;
  }>;
  commit?(
    vaultId: string,
    mutation: ResidentLoginMutation
  ): Promise<unknown>;
};

export interface PendingLoginWorkflow {
  loadPrompt(vaultId: string): Promise<PendingLoginPromptLoad>;
  save(prompt: PendingLoginPrompt): Promise<PendingLoginSaveResult>;
  dismiss(prompt: PendingLoginPrompt): Promise<void>;
}

function pendingSubmission(
  transaction: PendingAutofillTransaction
): PendingAutofillSubmission | null {
  if (transaction.state === "captured") {
    return transaction.submission;
  }
  if (!("plan" in transaction)) {
    return null;
  }
  return {
    url: transaction.plan.desiredFields.url,
    username: transaction.plan.desiredFields.username,
    password: transaction.plan.desiredFields.password,
    submittedAt: transaction.submittedAt
  };
}

function pendingPassword(transaction: PendingAutofillTransaction) {
  const submission = pendingSubmission(transaction);
  if (!submission) {
    throw new Error("Pending login save has no recoverable fields");
  }
  return submission.newPassword ?? submission.password;
}

function siteLabel(transaction: PendingAutofillTransaction) {
  const url = pendingSubmission(transaction)?.url ?? transaction.origin;
  try {
    return new URL(url).host || url;
  } catch {
    return url;
  }
}

function savedUrl(transaction: PendingAutofillTransaction) {
  const urlValue = pendingSubmission(transaction)?.url ?? transaction.origin;
  try {
    const url = new URL(urlValue);
    url.search = "";
    url.hash = "";
    return url.href;
  } catch {
    return urlValue.split(/[?#]/, 1)[0] || urlValue;
  }
}

function rebaseIntendedString(
  expected: string,
  desired: string,
  current: string
) {
  if (expected === desired || current === desired) {
    return current;
  }
  return current === expected ? desired : null;
}

function rebasePendingUpdate(
  plan: PendingAutofillUpdatePlan,
  current: PendingAutofillUpdateFields
): PendingAutofillUpdatePlan | null {
  if (plan.expectedFields.url !== plan.desiredFields.url) {
    return null;
  }
  const username = rebaseIntendedString(
    plan.expectedFields.username,
    plan.desiredFields.username,
    current.username
  );
  const password = rebaseIntendedString(
    plan.expectedFields.password,
    plan.desiredFields.password,
    current.password
  );
  if (username === null || password === null) {
    return null;
  }
  return {
    mode: "update",
    entryId: plan.entryId,
    expectedFields: {
      username: current.username,
      password: current.password,
      url: current.url
    },
    desiredFields: {
      username,
      password,
      url: current.url
    }
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

async function checkedEntryFields(
  dependencies: PendingLoginDependencies,
  vaultId: string,
  entryId: string,
  url: string
) {
  const result = await dependencies.getEntryFields(vaultId, entryId, url);
  if (result.id !== entryId) {
    throw new Error("Autofill entry detail did not match the requested entry");
  }
  return result.fields;
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
    }
  >();

  function bindPrompt(
    input: PendingLoginPromptInput,
    transaction: PendingAutofillTransaction,
    updateEntryId?: string
  ): PendingLoginPrompt {
    const action =
      input.mode === "retry"
        ? "retry_lookup"
        : input.mode === "save"
          ? input.ambiguous
            ? "save_new"
            : "save"
          : transaction.state === "persist_conflict"
            ? transaction.conflict.retryable
              ? "retry_update"
              : "replan_update"
            : "update";
    const prompt = Object.freeze({
      ...input,
      action,
      canDismiss: transaction.state !== "persisting"
    }) as PendingLoginPrompt;
    promptBindings.set(prompt, {
      vaultId: input.vaultId,
      transaction,
      ...(updateEntryId ? { updateEntryId } : {})
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

  function promptForPlannedTransaction(
    vaultId: string,
    transaction: PendingAutofillTransaction
  ): PendingLoginPrompt | null {
    if (transaction.state === "captured" || !("plan" in transaction)) {
      return null;
    }
    if (transaction.plan.mode === "update") {
      return bindPrompt(
        {
          mode: "update",
          vaultId,
          siteLabel: siteLabel(transaction)
        },
        transaction,
        transaction.plan.entryId
      );
    }
    return bindPrompt(
      {
        mode: "save",
        vaultId,
        siteLabel: siteLabel(transaction)
      },
      transaction
    );
  }

  function rebindPrompt(
    prompt: PendingLoginPrompt,
    transaction: PendingAutofillTransaction
  ) {
    const { vaultId } = bindingFor(prompt);
    if (prompt.mode === "update") {
      const { updateEntryId } = bindingFor(prompt);
      return bindPrompt(
        {
          mode: "update",
          vaultId,
          siteLabel: siteLabel(transaction)
        },
        transaction,
        updateEntryId
      );
    }
    if (prompt.mode === "retry") {
      return bindPrompt(
        {
          mode: "retry",
          vaultId,
          siteLabel: siteLabel(transaction)
        },
        transaction
      );
    }
    return bindPrompt(
      {
        mode: "save",
        vaultId,
        siteLabel: siteLabel(transaction),
        ...(prompt.ambiguous ? { ambiguous: true as const } : {})
      },
      transaction
    );
  }

  async function planTransaction(
    transaction: PendingAutofillTransaction,
    vaultId: string,
    plan: PendingAutofillPlanInput
  ) {
    if (!dependencies.plan) {
      throw new Error("Legacy login persistence is unavailable");
    }
    const planned = await dependencies.plan(
      transaction.transactionId,
      transaction.tabId,
      vaultId,
      plan
    );
    if (!planned) {
      throw new Error("Failed to persist a changed login save plan");
    }
    return planned;
  }

  async function refreshedCandidates(vaultId: string) {
    try {
      return await dependencies.findCandidates(vaultId);
    } catch {
      return null;
    }
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

  async function commitResidentMutation(
    prompt: PendingLoginPrompt
  ): Promise<PendingLoginSaveResult> {
    const commit = dependencies.commit;
    if (!commit) {
      throw new Error("Resident login mutation is unavailable");
    }
    const binding = bindingFor(prompt);
    const { transaction, vaultId } = binding;
    if ("vaultId" in transaction && transaction.vaultId !== vaultId) {
      throw new Error("Pending login save belongs to another vault");
    }
    const submission = pendingSubmission(transaction);
    if (!submission) {
      throw new Error("Pending login save has no recoverable fields");
    }

    let mutation: ResidentLoginMutation;
    if (prompt.mode === "update") {
      const entryId =
        binding.updateEntryId ??
        ("plan" in transaction && transaction.plan.mode === "update"
          ? transaction.plan.entryId
          : undefined);
      if (!entryId) {
        throw new Error("Pending login update target is no longer available");
      }
      const currentFields = await checkedEntryFields(
        dependencies,
        vaultId,
        entryId,
        submission.url
      );
      if (
        typeof submission.newPassword === "string" &&
        currentFields.password !== submission.password
      ) {
        await dismissPrompt(prompt);
        return { status: "dismissed" };
      }
      mutation = {
        mode: "update",
        entryId,
        expectedFields: currentFields,
        desiredFields: {
          username:
            submission.username.trim() === ""
              ? currentFields.username
              : submission.username,
          password: pendingPassword(transaction),
          url: currentFields.url || savedUrl(transaction)
        }
      };
    } else if (prompt.mode === "save") {
      const createContext = await dependencies.getCreateContext(vaultId);
      mutation = {
        mode: "create",
        parentGroupId: createContext.rootGroupId,
        desiredFields: {
          title: siteLabel(transaction),
          username: submission.username,
          password: pendingPassword(transaction),
          url: savedUrl(transaction),
          notes: "",
          totpUri: null,
          customFields: []
        }
      };
    } else {
      throw new Error("Reconnect before retrying the pending login save");
    }

    try {
      await commit(vaultId, mutation);
    } catch (error) {
      return {
        status: "retry",
        prompt: rebindPrompt(prompt, transaction),
        errorMessage: commitOutcomeIsUnknown(error)
          ? "Login save result is unknown. Reconnect to inspect the vault or retry manually."
          : popupErrorMessage(error, "Failed to save login")
      };
    }

    try {
      await dismissPrompt(prompt);
    } catch {
      // The resident Commit is authoritative. Cleanup failure must not invite
      // an automatic or implicit replay of the mutation.
    }
    return {
      status: "saved",
      candidates: await refreshedCandidates(vaultId)
    };
  }

  return {
    async loadPrompt(vaultId) {
      const transaction = await dependencies.load();
      if (!transaction) {
        return { prompt: null };
      }
      if ("vaultId" in transaction && transaction.vaultId !== vaultId) {
        return { prompt: null };
      }

      const plannedPrompt = promptForPlannedTransaction(vaultId, transaction);
      if (plannedPrompt) {
        return { prompt: plannedPrompt };
      }
      if (transaction.state === "captured" && transaction.submission.saveOnly) {
        return {
          prompt: bindPrompt(
            {
              mode: "save",
              vaultId,
              siteLabel: siteLabel(transaction)
            },
            transaction
          )
        };
      }

      const submission = pendingSubmission(transaction);
      if (!submission) {
        return {
          prompt: bindPrompt(
            {
              mode: "retry",
              vaultId,
              siteLabel: siteLabel(transaction)
            },
            transaction
          ),
          errorMessage:
            "Pending login outcome is ambiguous; discard and submit again"
        };
      }

      let candidates: EntrySummary[];
      try {
        candidates = await dependencies.findCandidates(vaultId, submission.url);
      } catch (lookupFailure) {
        return {
          prompt: bindPrompt(
            {
              mode: "retry",
              vaultId,
              siteLabel: siteLabel(transaction)
            },
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
      if (exactOriginCandidates.length === 0) {
        return {
          prompt: bindPrompt(
            {
              mode: "save",
              vaultId,
              siteLabel: siteLabel(transaction)
            },
            transaction
          )
        };
      }

      const submittedUsername = submission.username.trim();
      const matchingEntries =
        submittedUsername === ""
          ? exactOriginCandidates
          : exactOriginCandidates.filter(
              (entry) => entry.username === submittedUsername
            );
      if (matchingEntries.length === 0) {
        return {
          prompt: bindPrompt(
            {
              mode: "save",
              vaultId,
              siteLabel: siteLabel(transaction)
            },
            transaction
          )
        };
      }
      if (matchingEntries.length !== 1) {
        return {
          prompt: bindPrompt(
            {
              mode: "save",
              vaultId,
              siteLabel: siteLabel(transaction),
              ambiguous: true
            },
            transaction
          )
        };
      }
      return {
        prompt: bindPrompt(
          {
            mode: "update",
            vaultId,
            siteLabel: siteLabel(transaction)
          },
          transaction,
          matchingEntries[0].id
        )
      };
    },

    async save(prompt) {
      if (dependencies.commit) {
        return commitResidentMutation(prompt);
      }
      const binding = bindingFor(prompt);
      const { vaultId } = binding;
      let { transaction } = binding;
      let plan = "plan" in transaction ? transaction.plan : null;
      if ("vaultId" in transaction && transaction.vaultId !== vaultId) {
        throw new Error("Pending login save belongs to another vault");
      }

      if (
        transaction.state === "persist_conflict" &&
        plan &&
        !transaction.conflict.retryable
      ) {
        if (plan.mode === "update") {
          const currentFields = await checkedEntryFields(
            dependencies,
            vaultId,
            plan.entryId,
            plan.desiredFields.url
          );
          const rebased = rebasePendingUpdate(plan, currentFields);
          if (!rebased) {
            throw new Error(
              "The login changed in the same field; review it before updating"
            );
          }
          transaction = await planTransaction(transaction, vaultId, rebased);
        } else if (transaction.conflict.code === "planned_entry_id_collision") {
          transaction = await planTransaction(transaction, vaultId, {
            mode: "create",
            parentGroupId: plan.parentGroupId,
            expectedMatchingEntryIds: plan.expectedMatchingEntryIds,
            desiredFields: plan.desiredFields
          });
        } else {
          if (!dependencies.findExactMatchingEntryIds) {
            throw new Error("Legacy login persistence is unavailable");
          }
          const matchingEntryIds =
            await dependencies.findExactMatchingEntryIds(
              vaultId,
              plan.desiredFields
            );
          throw new Error(
            matchingEntryIds.length > 0
              ? "An exact login already exists; use the existing entry"
              : "The matching login set changed; review before saving"
          );
        }
        plan = "plan" in transaction ? transaction.plan : null;
      } else if (!plan && prompt.mode === "update") {
        const { updateEntryId } = bindingFor(prompt);
        if (!updateEntryId) {
          throw new Error("Pending login update target is no longer available");
        }
        const submission = pendingSubmission(transaction);
        if (!submission) {
          throw new Error("Pending login save has no recoverable fields");
        }
        const currentFields = await checkedEntryFields(
          dependencies,
          vaultId,
          updateEntryId,
          submission.url
        );
        if (
          typeof submission.newPassword === "string" &&
          currentFields.password !== submission.password
        ) {
          await dismissPrompt(prompt);
          return { status: "dismissed" };
        }
        transaction = await planTransaction(transaction, vaultId, {
          mode: "update",
          entryId: updateEntryId,
          expectedFields: {
            username: currentFields.username,
            password: currentFields.password,
            url: currentFields.url
          },
          desiredFields: {
            username:
              submission.username.trim() === ""
                ? currentFields.username
                : submission.username,
            password: pendingPassword(transaction),
            url: currentFields.url || savedUrl(transaction)
          }
        });
        plan = "plan" in transaction ? transaction.plan : null;
      } else if (!plan && prompt.mode === "save") {
        const submission = pendingSubmission(transaction);
        if (!submission) {
          throw new Error("Pending login save has no recoverable fields");
        }
        const createContext = await dependencies.getCreateContext(vaultId);
        const desiredFields: PendingAutofillDesiredFields = {
          title: siteLabel(transaction),
          username: submission.username,
          password: pendingPassword(transaction),
          url: savedUrl(transaction),
          notes: "",
          totpUri: null,
          customFields: []
        };
        if (!dependencies.findExactMatchingEntryIds) {
          throw new Error("Legacy login persistence is unavailable");
        }
        const expectedMatchingEntryIds =
          await dependencies.findExactMatchingEntryIds(vaultId, desiredFields);
        transaction = await planTransaction(transaction, vaultId, {
          mode: "create",
          parentGroupId: createContext.rootGroupId,
          expectedMatchingEntryIds,
          desiredFields
        });
        plan = "plan" in transaction ? transaction.plan : null;
      }

      if (transaction.state === "persisted") {
        return {
          status: "saved",
          candidates: await refreshedCandidates(vaultId)
        };
      }
      if (
        transaction.state === "persist_conflict" &&
        !transaction.conflict.retryable
      ) {
        throw new Error("The login changed; review it before saving again");
      }
      if (!plan) {
        throw new Error("Pending login save has no mutation plan");
      }

      if (!dependencies.execute) {
        throw new Error("Legacy login persistence is unavailable");
      }
      const execution = await dependencies.execute(
        transaction.transactionId,
        transaction.tabId
      );
      if (execution.ok) {
        return {
          status: "saved",
          candidates: await refreshedCandidates(vaultId)
        };
      }
      if (execution.expired) {
        return { status: "expired" };
      }
      const retryTransaction = execution.pending ?? transaction;
      return {
        status: "retry",
        prompt: rebindPrompt(prompt, retryTransaction),
        errorMessage:
          execution.errorMessage ?? "Background login save did not complete"
      };
    },

    dismiss: dismissPrompt
  };
}
