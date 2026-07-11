import type {
  AutofillPersistResult,
  PersistAutofillMutationRequest
} from "@vaultkern/runtime-web-client";

import {
  isValidPendingAutofillToken,
  isValidPendingAutofillVaultId,
  pendingAutofillPlanFromUnknown,
  type PendingAutofillExecutableTransaction
} from "./pendingSubmission";

export interface PendingAutofillPersistClient {
  persistAutofillMutation(
    request: PersistAutofillMutationRequest
  ): Promise<AutofillPersistResult>;
}

function requiredString(value: unknown, name: string) {
  if (typeof value !== "string" || value === "") {
    throw new TypeError(`pending autofill ${name} is missing`);
  }
  return value;
}

export async function executePendingAutofillPersist(
  client: PendingAutofillPersistClient,
  transaction: Pick<
    PendingAutofillExecutableTransaction,
    "transactionId" | "operationId" | "vaultId" | "plan"
  > | Record<string, unknown>
): Promise<AutofillPersistResult> {
  for (const redundantField of [
    "username",
    "password",
    "newPassword",
    "submission",
    "mutation"
  ]) {
    if (redundantField in transaction) {
      throw new TypeError(
        `pending autofill contains redundant secret field ${redundantField}`
      );
    }
  }
  const transactionId = requiredString(
    transaction.transactionId,
    "transaction binding"
  );
  const operationId = requiredString(
    transaction.operationId,
    "operation binding"
  );
  const vaultId = requiredString(transaction.vaultId, "vault binding");
  if (
    !isValidPendingAutofillToken(transactionId) ||
    !isValidPendingAutofillToken(operationId) ||
    !isValidPendingAutofillVaultId(vaultId)
  ) {
    throw new TypeError("pending autofill request binding is invalid");
  }
  const plan = pendingAutofillPlanFromUnknown(transaction.plan);
  if (!plan) {
    throw new TypeError("pending autofill plan contains an invalid UUID or field");
  }
  const request: PersistAutofillMutationRequest = {
    transactionId,
    operationId,
    vaultId,
    plan
  };
  const result = await client.persistAutofillMutation(request);
  if (
    result.transactionId !== transactionId ||
    result.operationId !== operationId ||
    result.vaultId !== vaultId
  ) {
    throw new Error("pending autofill persist result binding does not match");
  }
  if (result.outcome === "durable") {
    const expectedEntryId =
      plan.mode === "update" ? plan.entryId : plan.plannedEntryId;
    if (result.entryId !== expectedEntryId) {
      throw new Error("pending autofill persist entry binding does not match");
    }
  }
  return result;
}
