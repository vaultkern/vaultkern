import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import type {
  EntrySummary,
  EntryDraft,
  ResidentAppRoute,
  SessionState
} from "@vaultkern/runtime-web-client";
import {
  DEFAULT_EXTENSION_SETTINGS,
  I18nProvider,
  normalizeBrowserExtensionSettings,
  translate
} from "@vaultkern/shared-web-ui";
import type { ExtensionSettingsStore } from "@vaultkern/shared-web-ui";

import { PopupStatusStrip } from "./PopupStatusStrip";
import { SiteCandidateList } from "./SiteCandidateList";
import { popupErrorMessage, popupTheme } from "./theme";
import { sameExactHttpOrigin } from "../autofill/originPolicy";
import {
  type PendingAutofillDesiredFields,
  type PendingAutofillPlanInput,
  type PendingAutofillSubmission,
  type PendingAutofillTransaction
} from "../autofill/pendingSubmission";

type PendingAutofillPromptTransaction = PendingAutofillTransaction;
type PendingAutofillUpdatePlan = Extract<
  PendingAutofillPlanInput,
  { mode: "update" }
>;

type SessionStateLike = Pick<
  SessionState,
  "unlocked" | "activeVaultId"
>;

type PasskeyCredentialOption = {
  credentialId: string;
  username: string;
};

export interface PopupClientLike {
  getSessionState(): Promise<SessionStateLike>;
  activateResidentApp(route: ResidentAppRoute): Promise<void>;
  recordUserActivity(): Promise<SessionStateLike>;
  getAutofillEntryFields(
    vaultId: string,
    entryId: string,
    url: string
  ): Promise<{ id: string; fields: EntryDraft }>;
  getAutofillCreateContext(vaultId: string): Promise<{ rootGroupId: string }>;
  findExactMatchingEntryIds?(
    vaultId: string,
    fields: PendingAutofillDesiredFields
  ): Promise<string[]>;
}

const AUTOFILL_ENTRY_ID_MISMATCH_MESSAGE =
  "Autofill entry detail did not match the requested entry";

class AutofillEntryIdMismatchError extends Error {
  constructor() {
    super(AUTOFILL_ENTRY_ID_MISMATCH_MESSAGE);
    this.name = "AutofillEntryIdMismatchError";
  }
}

async function loadCheckedAutofillEntryFields(
  client: Pick<PopupClientLike, "getAutofillEntryFields">,
  vaultId: string,
  requestedEntryId: string,
  url: string
) {
  const result = await client.getAutofillEntryFields(
    vaultId,
    requestedEntryId,
    url
  );
  if (result.id !== requestedEntryId) {
    throw new AutofillEntryIdMismatchError();
  }
  return result.fields;
}

function sameCustomFields(
  left: PendingAutofillDesiredFields["customFields"],
  right: PendingAutofillDesiredFields["customFields"]
) {
  return (
    left.length === right.length &&
    left.every((field, index) => {
      const other = right[index];
      return (
        other !== undefined &&
        field.key === other.key &&
        field.value === other.value &&
        field.protected === other.protected
      );
    })
  );
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

function rebasePendingAutofillUpdate(
  plan: PendingAutofillUpdatePlan,
  current: PendingAutofillDesiredFields
): PendingAutofillUpdatePlan | null {
  const expected = plan.expectedFields;
  const desired = plan.desiredFields;
  if (
    expected.title !== desired.title ||
    expected.url !== desired.url ||
    expected.notes !== desired.notes ||
    expected.totpUri !== desired.totpUri ||
    !sameCustomFields(expected.customFields, desired.customFields)
  ) {
    return null;
  }
  const username = rebaseIntendedString(
    expected.username,
    desired.username,
    current.username
  );
  const password = rebaseIntendedString(
    expected.password,
    desired.password,
    current.password
  );
  if (username === null || password === null) {
    return null;
  }
  return {
    mode: "update",
    entryId: plan.entryId,
    expectedFields: current,
    desiredFields: {
      ...current,
      username,
      password
    }
  };
}

type AutofillSavePrompt =
  | {
      mode: "save";
      submission: PendingAutofillPromptTransaction;
      ambiguous?: true;
    }
  | {
      mode: "update";
      submission: PendingAutofillPromptTransaction;
      entry: EntrySummary;
    }
  | {
      mode: "retry";
      submission: PendingAutofillPromptTransaction;
    };

interface FillEntryOptions {
  requireSiteCandidate?: boolean;
}

function passkeyCredentialOptionsFromUnknown(
  options: unknown
): PasskeyCredentialOption[] {
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
  if (parsed.some((option) => option === null)) {
    return [];
  }
  return parsed as PasskeyCredentialOption[];
}

function responseKeepsPasskeyPromptOpen(response: unknown) {
  return (
    typeof response === "object" &&
    response !== null &&
    (response as { keepOpen?: unknown }).keepOpen === true
  );
}

async function loadPasskeyCredentialOptionsFromPrompt() {
  if (typeof window === "undefined") {
    return [];
  }
  const params = new URLSearchParams(window.location.search);
  if (params.get("webauthn") !== "approve") {
    return [];
  }
  const requestIdValue = params.get("requestId");
  const requestId =
    requestIdValue && requestIdValue.trim() !== "" ? Number(requestIdValue) : null;
  if (typeof requestId !== "number" || !Number.isFinite(requestId)) {
    return [];
  }
  const runtime = (
    globalThis as typeof globalThis & {
      chrome?: {
        runtime?: {
          sendMessage?: (message: unknown) => Promise<unknown> | unknown;
        };
      };
    }
  ).chrome?.runtime;
  if (typeof runtime?.sendMessage !== "function") {
    return [];
  }
  const nonce = params.get("nonce");
  const origin = params.get("origin");
  const relyingParty = params.get("relyingParty");
  const topOrigin = params.get("topOrigin");
  const response = await Promise.resolve(
    runtime.sendMessage({
      type: "vaultkern_presence_options_request",
      requestId,
      ...(origin ? { origin } : {}),
      ...(relyingParty ? { relyingParty } : {}),
      ...(topOrigin ? { topOrigin } : {}),
      ...(nonce ? { nonce } : {})
    })
  );
  return passkeyCredentialOptionsFromUnknown(
    (response as { credentialOptions?: unknown } | null)?.credentialOptions
  );
}

export function PopupApp({
  client,
  findCandidates,
  fillEntry,
  activeSite,
  loadPendingAutofillSubmission,
  planPendingAutofillSubmission,
  dismissPendingAutofillSubmission,
  executePendingAutofillMutation,
  openResidentApp,
  extensionSettingsStore,
  renderRuntimeErrorHelp,
  onUnlockComplete,
  onWebAuthnPresenceComplete,
  onWebAuthnUserVerificationComplete
}: {
  client: PopupClientLike;
  findCandidates: (vaultId: string, siteUrl?: string) => Promise<EntrySummary[]>;
  fillEntry: (vaultId: string, entryId: string, options?: FillEntryOptions) => Promise<void>;
  activeSite: () => Promise<string>;
  loadPendingAutofillSubmission?: () => Promise<PendingAutofillPromptTransaction | null>;
  planPendingAutofillSubmission?: (
    transactionId: string,
    tabId: number,
    vaultId: string,
    plan: PendingAutofillPlanInput
  ) => Promise<PendingAutofillPromptTransaction | null>;
  dismissPendingAutofillSubmission?: (
    transactionId: string,
    tabId: number
  ) => Promise<boolean>;
  executePendingAutofillMutation?: (
    transactionId: string,
    tabId: number
  ) => Promise<{
    ok: boolean;
    expired?: boolean;
    conflict?: boolean;
    pending?: PendingAutofillPromptTransaction | null;
    errorMessage?: string;
  }>;
  openResidentApp: (route: ResidentAppRoute) => Promise<void>;
  extensionSettingsStore?: Pick<ExtensionSettingsStore, "load">;
  renderRuntimeErrorHelp?: (error: unknown) => ReactNode;
  onUnlockComplete?: (
    session: SessionStateLike,
    options?: { method: "quick_unlock" }
  ) => void | Promise<void>;
  onWebAuthnPresenceComplete?: (
    session: SessionStateLike,
    options?: { credentialId?: string }
  ) => unknown | Promise<unknown>;
  onWebAuthnUserVerificationComplete?: (
    session: SessionStateLike,
    options: { method: "quick_unlock" }
  ) => void | Promise<void>;
}) {
  const [session, setSession] = useState<SessionStateLike | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [sessionErrorCause, setSessionErrorCause] = useState<unknown>(null);
  const [siteLabel, setSiteLabel] = useState("No active site");
  const [candidates, setCandidates] = useState<EntrySummary[]>([]);
  const [entriesError, setEntriesError] = useState<string | null>(null);
  const [pendingAutofillSubmission, setPendingAutofillSubmission] =
    useState<PendingAutofillPromptTransaction | null>(null);
  const [autofillSavePrompt, setAutofillSavePrompt] =
    useState<AutofillSavePrompt | null>(null);
  const [autofillSaveError, setAutofillSaveError] = useState<string | null>(null);
  const [pendingAutofillRetryVersion, setPendingAutofillRetryVersion] =
    useState(0);
  const [savingAutofillPrompt, setSavingAutofillPrompt] = useState(false);
  const savingAutofillPromptRef = useRef(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [unlockErrorCause, setUnlockErrorCause] = useState<unknown>(null);
  const [submitting, setSubmitting] = useState(false);
  const [extensionSettings, setExtensionSettings] = useState(
    DEFAULT_EXTENSION_SETTINGS
  );
  const webAuthnUnlockCompletionSent = useRef(false);
  const webAuthnMode =
    typeof window !== "undefined" &&
    new URLSearchParams(window.location.search).get("webauthn");
  const webAuthnUnlockPrompt = webAuthnMode === "unlock";
  const webAuthnApprovePrompt = webAuthnMode === "approve";
  const webAuthnVerifyPrompt = webAuthnMode === "verify";
  const webAuthnCeremonyPrompt =
    webAuthnUnlockPrompt || webAuthnApprovePrompt || webAuthnVerifyPrompt;
  const [passkeyCredentialOptions, setPasskeyCredentialOptions] = useState<
    PasskeyCredentialOption[]
  >([]);
  const [selectedPasskeyCredentialId, setSelectedPasskeyCredentialId] = useState("");
  const [
    waitingForPasskeyCredentialOptions,
    setWaitingForPasskeyCredentialOptions
  ] = useState(false);

  function pendingSubmission(
    transaction: PendingAutofillPromptTransaction
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

  function pendingPassword(transaction: PendingAutofillPromptTransaction) {
    const submission = pendingSubmission(transaction);
    if (!submission) {
      throw new Error("Pending login save has no recoverable fields");
    }
    return submission.newPassword ?? submission.password;
  }

  function pendingTransactionState(transaction: PendingAutofillPromptTransaction) {
    return transaction.state;
  }

  function titleForPendingSubmission(transaction: PendingAutofillPromptTransaction) {
    const url = pendingSubmission(transaction)?.url ?? transaction.origin;
    try {
      return new URL(url).host || url;
    } catch {
      return url;
    }
  }

  function savedUrlForPendingSubmission(
    transaction: PendingAutofillPromptTransaction
  ) {
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

  function entryMatchesPendingUsername(
    entry: EntrySummary,
    transaction: PendingAutofillPromptTransaction
  ) {
    const submission = pendingSubmission(transaction);
    if (!submission) {
      return false;
    }
    const submittedUsername = submission.username.trim();
    return submittedUsername !== "" && entry.username === submittedUsername;
  }

  async function loadExtensionSettingsForPopup() {
    const loadedSettings =
      (await extensionSettingsStore?.load()) ?? DEFAULT_EXTENSION_SETTINGS;
    const normalizedSettings = normalizeBrowserExtensionSettings(loadedSettings);
    setExtensionSettings(normalizedSettings);
    return normalizedSettings;
  }

  function notifyWebAuthnUnlockCompleteOnce(
    nextSession: SessionStateLike,
    options?: { method: "quick_unlock" }
  ) {
    if (
      !webAuthnUnlockPrompt ||
      webAuthnUnlockCompletionSent.current ||
      !nextSession.unlocked ||
      !nextSession.activeVaultId
    ) {
      return;
    }

    webAuthnUnlockCompletionSent.current = true;
    void Promise.resolve(onUnlockComplete?.(nextSession, options)).catch(
      () => undefined
    );
  }

  useEffect(() => {
    let cancelled = false;

    loadExtensionSettingsForPopup()
      .catch((loadError) => {
        if (!cancelled) {
          setSessionError(
            popupErrorMessage(loadError, "Failed to load extension preferences")
          );
          setSessionErrorCause(loadError);
        }
      });

    client
      .getSessionState()
      .then((state) => {
        if (!cancelled) {
          setSession(state);
          setSessionError(null);
          setSessionErrorCause(null);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setSession(null);
          setSessionError(
            popupErrorMessage(
              loadError,
              translate(extensionSettings.language, "Failed to load session state")
            )
          );
          setSessionErrorCause(loadError);
        }
      });

    activeSite().then((value) => {
      if (!cancelled) {
        setSiteLabel(value);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [activeSite, client, extensionSettingsStore]);

  useEffect(() => {
    setSelectedPasskeyCredentialId((currentCredentialId) => {
      if (
        currentCredentialId &&
        passkeyCredentialOptions.some(
          (option) => option.credentialId === currentCredentialId
        )
      ) {
        return currentCredentialId;
      }
      return passkeyCredentialOptions[0]?.credentialId ?? "";
    });
  }, [passkeyCredentialOptions]);

  useEffect(() => {
    let cancelled = false;
    if (!webAuthnApprovePrompt) {
      setPasskeyCredentialOptions([]);
      return () => {
        cancelled = true;
      };
    }

    loadPasskeyCredentialOptionsFromPrompt()
      .then((options) => {
        if (!cancelled) {
          setPasskeyCredentialOptions(options);
          if (options.length > 0) {
            setWaitingForPasskeyCredentialOptions(false);
          }
        }
      })
      .catch(() => {
        if (!cancelled) {
          setPasskeyCredentialOptions([]);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [webAuthnApprovePrompt]);

  useEffect(() => {
    if (
      !webAuthnApprovePrompt ||
      !waitingForPasskeyCredentialOptions ||
      passkeyCredentialOptions.length > 0
    ) {
      return undefined;
    }

    let cancelled = false;
    const timer = window.setInterval(() => {
      loadPasskeyCredentialOptionsFromPrompt()
        .then((options) => {
          if (cancelled || options.length === 0) {
            return;
          }
          setPasskeyCredentialOptions(options);
          setWaitingForPasskeyCredentialOptions(false);
        })
        .catch(() => undefined);
    }, 250);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [
    passkeyCredentialOptions.length,
    waitingForPasskeyCredentialOptions,
    webAuthnApprovePrompt
  ]);

  useEffect(() => {
    if (typeof window === "undefined" || !session?.unlocked) {
      return undefined;
    }

    let disposed = false;
    let reportPending = false;
    let lastReportedAt = 0;

    function reportActivity() {
      const now = Date.now();
      if (reportPending || now - lastReportedAt < 15_000) {
        return;
      }
      reportPending = true;
      lastReportedAt = now;
      void client
        .recordUserActivity()
        .then((nextSession) => {
          if (!disposed) {
            setSession(nextSession);
          }
        })
        .catch(() => undefined)
        .finally(() => {
          reportPending = false;
        });
    }

    const events = ["pointerdown", "keydown", "wheel", "scroll"];
    for (const eventName of events) {
      window.addEventListener(eventName, reportActivity, { passive: true });
    }

    return () => {
      disposed = true;
      for (const eventName of events) {
        window.removeEventListener(eventName, reportActivity);
      }
    };
  }, [client, session?.unlocked]);

  useEffect(() => {
    if (webAuthnCeremonyPrompt) {
      setCandidates([]);
      return;
    }

    if (!session?.unlocked || !session.activeVaultId) {
      setCandidates([]);
      return;
    }

    let cancelled = false;
    findCandidates(session.activeVaultId)
      .then((loadedCandidates) => {
        if (cancelled) {
          return;
        }
        setCandidates(loadedCandidates);
        setEntriesError(null);
      })
      .catch((loadError) => {
        if (cancelled) {
          return;
        }
        setCandidates([]);
        setEntriesError(
          popupErrorMessage(
            loadError,
            translate(extensionSettings.language, "Failed to load site candidates")
          )
        );
      });

    return () => {
      cancelled = true;
    };
  }, [
    client,
    extensionSettings.language,
    findCandidates,
    session?.activeVaultId,
    session?.unlocked,
    webAuthnCeremonyPrompt
  ]);

  useEffect(() => {
    if (
      webAuthnCeremonyPrompt ||
      !session?.unlocked ||
      !session.activeVaultId ||
      !loadPendingAutofillSubmission
    ) {
      setPendingAutofillSubmission(null);
      setAutofillSavePrompt(null);
      setAutofillSaveError(null);
      return;
    }

    let cancelled = false;
    loadPendingAutofillSubmission()
      .then((submission) => {
        if (!cancelled) {
          setPendingAutofillSubmission(submission);
          setAutofillSaveError(null);
        }
      })
      .catch((loadFailure) => {
        if (!cancelled) {
          setPendingAutofillSubmission(null);
          setAutofillSavePrompt(null);
          setAutofillSaveError(
            popupErrorMessage(
              loadFailure,
              "Failed to recover pending login save"
            )
          );
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    loadPendingAutofillSubmission,
    pendingAutofillRetryVersion,
    session?.activeVaultId,
    session?.unlocked,
    webAuthnCeremonyPrompt
  ]);

  useEffect(() => {
    if (!pendingAutofillSubmission || !session?.activeVaultId) {
      setAutofillSavePrompt(null);
      return;
    }
    const activeVaultId = session.activeVaultId;
    const transactionState = pendingTransactionState(pendingAutofillSubmission);
    const submission = pendingSubmission(pendingAutofillSubmission);
    const existingPlan =
      "plan" in pendingAutofillSubmission
        ? pendingAutofillSubmission.plan
        : null;

    let cancelled = false;
    setAutofillSavePrompt(null);
    setAutofillSaveError(null);
    if (
      "vaultId" in pendingAutofillSubmission &&
      pendingAutofillSubmission.vaultId !== activeVaultId
    ) {
      return;
    }
    if (
      transactionState !== "captured" &&
      existingPlan?.mode === "update"
    ) {
      setAutofillSavePrompt({
        mode: "update",
        submission: pendingAutofillSubmission,
        entry: {
          id: existingPlan.entryId,
          title: existingPlan.desiredFields.title,
          username: existingPlan.desiredFields.username,
          url: existingPlan.desiredFields.url
        }
      });
      return;
    }
    if (
      (pendingAutofillSubmission.state === "captured" &&
        pendingAutofillSubmission.submission.saveOnly) ||
      (transactionState !== "captured" &&
        existingPlan?.mode === "create")
    ) {
      setAutofillSavePrompt({
        mode: "save",
        submission: pendingAutofillSubmission
      });
      return;
    }

    if (!submission) {
      setAutofillSavePrompt({
        mode: "retry",
        submission: pendingAutofillSubmission
      });
      setAutofillSaveError("Pending login outcome is ambiguous; discard and submit again");
      return;
    }

    findCandidates(activeVaultId, submission.url)
      .then(async (pendingCandidates) => {
        if (cancelled) {
          return;
        }

        const exactOriginCandidates = pendingCandidates.filter((entry) =>
          sameExactHttpOrigin(entry.url, submission.url)
        );
        const hasSubmittedUsername = submission.username.trim() !== "";
        if (!exactOriginCandidates.length) {
          setAutofillSavePrompt({
            mode: "save",
            submission: pendingAutofillSubmission
          });
          return;
        }

        try {
          if (hasSubmittedUsername) {
            const matchingEntries = exactOriginCandidates.filter((entry) =>
              entryMatchesPendingUsername(entry, pendingAutofillSubmission)
            );
            if (!matchingEntries.length) {
              setAutofillSavePrompt({
                mode: "save",
                submission: pendingAutofillSubmission
              });
              return;
            }
            if (matchingEntries.length !== 1) {
              setAutofillSavePrompt({
                mode: "save",
                submission: pendingAutofillSubmission,
                ambiguous: true
              });
              return;
            }

            setAutofillSavePrompt({
              mode: "update",
              submission: pendingAutofillSubmission,
              entry: matchingEntries[0]
            });
            return;
          }

          if (exactOriginCandidates.length !== 1) {
            setAutofillSavePrompt({
              mode: "save",
              submission: pendingAutofillSubmission,
              ambiguous: true
            });
            return;
          }

          setAutofillSavePrompt({
            mode: "update",
            submission: pendingAutofillSubmission,
            entry: exactOriginCandidates[0]
          });
        } catch (lookupFailure) {
          if (!cancelled) {
            setAutofillSavePrompt({
              mode: "retry",
              submission: pendingAutofillSubmission
            });
            setAutofillSaveError(
              popupErrorMessage(
                lookupFailure,
                "Failed to match pending login"
              )
            );
          }
        }
      })
      .catch((lookupFailure) => {
        if (cancelled) {
          return;
        }
        setAutofillSavePrompt({
          mode: "retry",
          submission: pendingAutofillSubmission
        });
        setAutofillSaveError(
          popupErrorMessage(
            lookupFailure,
            "Failed to match pending login"
          )
        );
      });

    return () => {
      cancelled = true;
    };
  }, [
    client,
    findCandidates,
    pendingAutofillRetryVersion,
    pendingAutofillSubmission,
    session?.activeVaultId
  ]);

  async function handleWebAuthnPresenceApproval() {
    if (!session?.unlocked || submitting) {
      return;
    }

    setSubmitting(true);
    try {
      const response = await Promise.resolve(
        onWebAuthnPresenceComplete?.(
          session,
          passkeyCredentialOptions.length > 0 && selectedPasskeyCredentialId
            ? { credentialId: selectedPasskeyCredentialId }
            : undefined
        )
      );
      if (responseKeepsPasskeyPromptOpen(response)) {
        setWaitingForPasskeyCredentialOptions(true);
        const options = await loadPasskeyCredentialOptionsFromPrompt();
        setPasskeyCredentialOptions(options);
        if (options.length > 0) {
          setWaitingForPasskeyCredentialOptions(false);
        }
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function handleWebAuthnUserVerification() {
    if (!session?.unlocked || submitting) {
      return;
    }

    setSubmitting(true);
    setUnlockError(null);
    setUnlockErrorCause(null);
    try {
      await Promise.resolve(
        onWebAuthnUserVerificationComplete?.(session, {
          method: "quick_unlock"
        })
      );
    } catch (verificationFailure) {
      setUnlockError(
        popupErrorMessage(
          verificationFailure,
          extensionSettings.language === "zh-CN"
            ? "用户验证失败"
            : "User verification failed"
        )
      );
      setUnlockErrorCause(verificationFailure);
    } finally {
      setSubmitting(false);
    }
  }

  useEffect(() => {
    if (!webAuthnUnlockPrompt || session?.unlocked) {
      return undefined;
    }
    let cancelled = false;
    let requestPending = false;
    const timer = window.setInterval(() => {
      if (requestPending) {
        return;
      }
      requestPending = true;
      void client
        .getSessionState()
        .then((nextSession) => {
          if (!cancelled && nextSession.unlocked) {
            setSession(nextSession);
            notifyWebAuthnUnlockCompleteOnce(nextSession);
          }
        })
        .catch(() => undefined)
        .finally(() => {
          requestPending = false;
        });
    }, 500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [client, session?.unlocked, webAuthnUnlockPrompt]);

  async function handleOpenResident(route: ResidentAppRoute) {
    setUnlockError(null);
    setUnlockErrorCause(null);
    try {
      await openResidentApp(route);
    } catch (activationFailure) {
      setUnlockError(
        popupErrorMessage(activationFailure, "Failed to open VaultKern")
      );
      setUnlockErrorCause(activationFailure);
    }
  }

  async function handleOpenManager() {
    await handleOpenResident("vaults");
  }

  async function handleOpenExtensionSettings() {
    await handleOpenResident("settings");
  }

  function clearAutofillPromptLocally() {
    setPendingAutofillSubmission(null);
    setAutofillSavePrompt(null);
    setAutofillSaveError(null);
  }

  function retryPendingAutofillPrompt() {
    setAutofillSaveError(null);
    setPendingAutofillRetryVersion((version) => version + 1);
  }

  async function planAutofillTransaction(
    vaultId: string,
    plan: PendingAutofillPlanInput
  ) {
    const currentSubmission =
      autofillSavePrompt?.submission ?? pendingAutofillSubmission;
    if (!currentSubmission) {
      throw new Error("Pending login save is no longer available");
    }
    if (!planPendingAutofillSubmission) {
      throw new Error("Background login save planning is unavailable");
    }
    const planned = await planPendingAutofillSubmission(
      currentSubmission.transactionId,
      currentSubmission.tabId,
      vaultId,
      plan
    );
    if (!planned) {
      throw new Error("Failed to persist a changed login save plan");
    }
    setPendingAutofillSubmission(planned);
    setAutofillSavePrompt((currentPrompt) =>
      currentPrompt
        ? { ...currentPrompt, submission: planned }
        : currentPrompt
    );
    return planned;
  }

  async function dismissAutofillPrompt() {
    try {
      const currentSubmission =
        autofillSavePrompt?.submission ?? pendingAutofillSubmission;
      if (!currentSubmission) {
        throw new Error("Pending login save is no longer available");
      }
      if (
        !dismissPendingAutofillSubmission ||
        !(await dismissPendingAutofillSubmission(
          currentSubmission.transactionId,
          currentSubmission.tabId
        ))
      ) {
        throw new Error("Failed to discard login save");
      }
      clearAutofillPromptLocally();
    } catch (dismissFailure) {
      setAutofillSaveError(
        popupErrorMessage(dismissFailure, "Failed to dismiss login save")
      );
    }
  }

  async function refreshEntriesAfterAutofillSave(vaultId: string) {
    const nextCandidates = await findCandidates(vaultId);
    setCandidates(nextCandidates);
  }

  async function handleSavePendingLogin() {
    if (
      !session?.activeVaultId ||
      !autofillSavePrompt ||
      savingAutofillPromptRef.current
    ) {
      return;
    }

    savingAutofillPromptRef.current = true;
    setSavingAutofillPrompt(true);
    setAutofillSaveError(null);
    const activeVaultId = session.activeVaultId;
    let transaction = autofillSavePrompt.submission;
    let plan = "plan" in transaction ? transaction.plan : null;

    try {
      if ("vaultId" in transaction && transaction.vaultId !== activeVaultId) {
        throw new Error("Pending login save belongs to another vault");
      }

      if (
        transaction.state === "persist_conflict" &&
        plan &&
        !transaction.conflict.retryable
      ) {
        if (plan.mode === "update") {
          const detail = await loadCheckedAutofillEntryFields(
            client,
            activeVaultId,
            plan.entryId,
            plan.desiredFields.url
          );
          const currentFields: PendingAutofillDesiredFields = {
            title: detail.title,
            username: detail.username,
            password: detail.password,
            url: detail.url,
            notes: detail.notes,
            totpUri: detail.totpUri ?? null,
            customFields: detail.customFields ?? []
          };
          const rebased = rebasePendingAutofillUpdate(plan, currentFields);
          if (!rebased) {
            throw new Error(
              "The login changed in the same field; review it before updating"
            );
          }
          transaction = await planAutofillTransaction(activeVaultId, rebased);
        } else {
          if (transaction.conflict.code === "planned_entry_id_collision") {
            transaction = await planAutofillTransaction(activeVaultId, {
              mode: "create",
              parentGroupId: plan.parentGroupId,
              expectedMatchingEntryIds: plan.expectedMatchingEntryIds,
              desiredFields: plan.desiredFields
            });
          } else {
            if (!client.findExactMatchingEntryIds) {
              throw new Error("Exact login matching is unavailable");
            }
            const matchingEntryIds = await client.findExactMatchingEntryIds(
              activeVaultId,
              plan.desiredFields
            );
            throw new Error(
              matchingEntryIds.length > 0
                ? "An exact login already exists; use the existing entry"
                : "The matching login set changed; review before saving"
            );
          }
        }
        plan = "plan" in transaction ? transaction.plan : null;
      } else if (!plan && autofillSavePrompt.mode === "update") {
        const submission = pendingSubmission(transaction);
        if (!submission) {
          throw new Error("Pending login save has no recoverable fields");
        }
        const detail = await loadCheckedAutofillEntryFields(
          client,
          activeVaultId,
          autofillSavePrompt.entry.id,
          submission.url
        );
        if (
          typeof submission.newPassword === "string" &&
          detail.password !== submission.password
        ) {
          await dismissAutofillPrompt();
          return;
        }
        const nextPlan: PendingAutofillPlanInput = {
          mode: "update",
          entryId: autofillSavePrompt.entry.id,
          expectedFields: {
            title: detail.title,
            username: detail.username,
            password: detail.password,
            url: detail.url,
            notes: detail.notes,
            totpUri: detail.totpUri ?? null,
            customFields: detail.customFields ?? []
          },
          desiredFields: {
            title: detail.title,
            username:
              submission.username.trim() === ""
                ? detail.username
                : submission.username,
            password: pendingPassword(transaction),
            url: detail.url || savedUrlForPendingSubmission(transaction),
            notes: detail.notes,
            totpUri: detail.totpUri ?? null,
            customFields: detail.customFields ?? []
          }
        };
        transaction = await planAutofillTransaction(activeVaultId, nextPlan);
        plan = "plan" in transaction ? transaction.plan : null;
      } else if (!plan && autofillSavePrompt.mode === "save") {
        const submission = pendingSubmission(transaction);
        if (!submission) {
          throw new Error("Pending login save has no recoverable fields");
        }
        const createContext = await client.getAutofillCreateContext(activeVaultId);
        const desiredFields: PendingAutofillDesiredFields = {
          title: titleForPendingSubmission(transaction),
          username: submission.username,
          password: pendingPassword(transaction),
          url: savedUrlForPendingSubmission(transaction),
          notes: "",
          totpUri: null,
          customFields: []
        };
        if (!client.findExactMatchingEntryIds) {
          throw new Error("Exact login matching is unavailable");
        }
        const expectedMatchingEntryIds = await client.findExactMatchingEntryIds(
          activeVaultId,
          desiredFields
        );
        const nextPlan: PendingAutofillPlanInput = {
          mode: "create",
          parentGroupId: createContext.rootGroupId,
          expectedMatchingEntryIds,
          desiredFields
        };
        transaction = await planAutofillTransaction(activeVaultId, nextPlan);
        plan = "plan" in transaction ? transaction.plan : null;
      }

      if (transaction.state === "persisted") {
        clearAutofillPromptLocally();
        await refreshEntriesAfterAutofillSave(activeVaultId);
        return;
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
      if (!executePendingAutofillMutation) {
        throw new Error("Background login save execution is unavailable");
      }
      const execution = await executePendingAutofillMutation(
        transaction.transactionId,
        transaction.tabId
      );
      if (!execution.ok) {
        if (execution.expired) {
          clearAutofillPromptLocally();
          return;
        }
        if (execution.pending) {
          transaction = execution.pending;
          setPendingAutofillSubmission(transaction);
          setAutofillSavePrompt((currentPrompt) =>
            currentPrompt
              ? { ...currentPrompt, submission: transaction }
              : currentPrompt
          );
        }
        throw new Error(
          execution.errorMessage ?? "Background login save did not complete"
        );
      }
      clearAutofillPromptLocally();
      await refreshEntriesAfterAutofillSave(activeVaultId);
    } catch (saveFailure) {
      setAutofillSaveError(
        popupErrorMessage(saveFailure, "Failed to save login")
      );
    } finally {
      savingAutofillPromptRef.current = false;
      setSavingAutofillPrompt(false);
    }
  }


  if (!session) {
    if (sessionError) {
      return (
        <div style={shellStyle}>
          <div role="alert">{sessionError}</div>
          {renderRuntimeErrorHelp?.(sessionErrorCause)}
        </div>
      );
    }

    return <div style={shellStyle}>Loading...</div>;
  }

  if (!session.unlocked) {
    const passkeyPromptTitle =
      extensionSettings.language === "zh-CN"
        ? "通行密钥请求等待中"
        : "Passkey request waiting";
    const passkeyPromptBody =
      siteLabel === "No active site"
        ? extensionSettings.language === "zh-CN"
          ? "请解锁数据库以继续当前网站的通行密钥请求。"
          : "Unlock your vault to continue the website passkey request."
        : extensionSettings.language === "zh-CN"
          ? `请解锁数据库以继续 ${siteLabel} 的通行密钥请求。`
          : `Unlock your vault to continue the passkey request for ${siteLabel}.`;
    const lockedBody =
      extensionSettings.language === "zh-CN"
        ? "数据库由 VaultKern 客户端持有。请在客户端完成解锁。"
        : "Your vault is held by the VaultKern app. Unlock it there to continue.";

    return (
      <I18nProvider language={extensionSettings.language}>
      <div style={shellStyle}>
        <PopupStatusStrip
          siteLabel={siteLabel}
          unlocked={false}
          onOpenExtensionSettings={handleOpenExtensionSettings}
        />
        {webAuthnUnlockPrompt ? (
          <section style={passkeyPromptStyle} aria-live="polite">
            <strong>{passkeyPromptTitle}</strong>
            <span>{passkeyPromptBody}</span>
          </section>
        ) : null}
        <div style={messagePanelStyle}>{lockedBody}</div>
        <div style={{ display: "grid", gap: popupTheme.spacing.sm }}>
          <button
            type="button"
            onClick={() => {
              void handleOpenResident("unlock");
            }}
            style={primaryActionStyle}
          >
            {extensionSettings.language === "zh-CN" ? "打开 VaultKern" : "Open VaultKern"}
          </button>
          <button
            type="button"
            onClick={handleOpenManager}
            style={secondaryActionStyle}
          >
            {extensionSettings.language === "zh-CN" ? "管理数据库" : "Manage Vaults"}
          </button>
          {unlockError ? <div role="alert">{unlockError}</div> : null}
          {unlockError && renderRuntimeErrorHelp
            ? renderRuntimeErrorHelp(unlockErrorCause)
            : null}
        </div>
      </div>
      </I18nProvider>
    );
  }

  if (webAuthnVerifyPrompt) {
    const passkeyPromptTitle =
      extensionSettings.language === "zh-CN"
        ? "验证通行密钥请求"
        : "Verify passkey request";
    const passkeyPromptBody =
      siteLabel === "No active site"
        ? extensionSettings.language === "zh-CN"
          ? "请使用 Windows Hello 验证以继续当前网站的通行密钥请求。"
          : "Verify with Windows Hello to continue this passkey request."
        : extensionSettings.language === "zh-CN"
          ? `请使用 Windows Hello 验证以继续 ${siteLabel} 的通行密钥请求。`
          : `Verify with Windows Hello to continue the passkey request for ${siteLabel}.`;

    return (
      <I18nProvider language={extensionSettings.language}>
      <div style={shellStyle}>
        <PopupStatusStrip
          siteLabel={siteLabel}
          unlocked
          onOpenManager={undefined}
        />
        <section style={passkeyPromptStyle} aria-live="polite">
          <strong>{passkeyPromptTitle}</strong>
          <span>{passkeyPromptBody}</span>
        </section>
        <div style={{ display: "grid", gap: popupTheme.spacing.md }}>
          <button
            type="button"
            onClick={() => {
              void handleWebAuthnUserVerification();
            }}
            disabled={submitting}
            style={primaryActionStyle}
          >
            {submitting
              ? extensionSettings.language === "zh-CN"
                ? "验证中..."
                : "Verifying..."
              : extensionSettings.language === "zh-CN"
                ? "使用 Windows Hello 验证"
                : "Verify with Windows Hello"}
          </button>
          {unlockError ? <div role="alert">{unlockError}</div> : null}
          {unlockError && renderRuntimeErrorHelp
            ? renderRuntimeErrorHelp(unlockErrorCause)
            : null}
        </div>
      </div>
      </I18nProvider>
    );
  }

  if (webAuthnApprovePrompt) {
    const passkeyPromptTitle =
      extensionSettings.language === "zh-CN"
        ? "确认通行密钥请求"
        : "Confirm passkey request";
    const passkeyPromptBody =
      siteLabel === "No active site"
        ? extensionSettings.language === "zh-CN"
          ? "确认后继续当前网站的通行密钥请求。"
          : "Approve this passkey request to continue."
        : extensionSettings.language === "zh-CN"
          ? `确认后继续 ${siteLabel} 的通行密钥请求。`
          : `Approve this passkey request for ${siteLabel}.`;
    const passkeyPromptAction = waitingForPasskeyCredentialOptions
      ? extensionSettings.language === "zh-CN"
        ? "正在载入通行密钥账号..."
        : "Loading passkey accounts..."
      : extensionSettings.language === "zh-CN"
        ? "继续通行密钥请求"
        : "Continue passkey request";

    return (
      <I18nProvider language={extensionSettings.language}>
      <div style={shellStyle}>
        <PopupStatusStrip
          siteLabel={siteLabel}
          unlocked
          onOpenManager={undefined}
        />
        <section style={passkeyPromptStyle} aria-live="polite">
          <strong>{passkeyPromptTitle}</strong>
          <span>{passkeyPromptBody}</span>
        </section>
        {passkeyCredentialOptions.length > 0 ? (
          <div
            role="radiogroup"
            aria-label={
              extensionSettings.language === "zh-CN"
                ? "选择通行密钥账号"
                : "Choose passkey account"
            }
            style={passkeyCredentialListStyle}
          >
            {passkeyCredentialOptions.map((option) => (
              <label key={option.credentialId} style={passkeyCredentialOptionStyle}>
                <input
                  type="radio"
                  aria-label={option.username || option.credentialId}
                  checked={selectedPasskeyCredentialId === option.credentialId}
                  onChange={() => setSelectedPasskeyCredentialId(option.credentialId)}
                />
                <span>{option.username || option.credentialId}</span>
              </label>
            ))}
          </div>
        ) : null}
        <button
          type="button"
          onClick={() => {
            void handleWebAuthnPresenceApproval();
          }}
          disabled={
            submitting ||
            waitingForPasskeyCredentialOptions ||
            (passkeyCredentialOptions.length > 0 && !selectedPasskeyCredentialId)
          }
          style={primaryActionStyle}
        >
          {passkeyPromptAction}
        </button>
      </div>
      </I18nProvider>
    );
  }

  return (
    <I18nProvider language={extensionSettings.language}>
    <div style={shellStyle}>
      <PopupStatusStrip
        siteLabel={siteLabel}
        unlocked
        onOpenManager={handleOpenManager}
        onOpenExtensionSettings={handleOpenExtensionSettings}
      />
      {entriesError ? <div role="alert">{entriesError}</div> : null}
      {!autofillSavePrompt && autofillSaveError ? (
        <section style={passkeyPromptStyle} aria-live="polite">
          <div role="alert">{autofillSaveError}</div>
          <button
            type="button"
            onClick={retryPendingAutofillPrompt}
            style={primaryActionStyle}
          >
            Retry
          </button>
        </section>
      ) : null}
      {autofillSavePrompt ? (
        <section style={passkeyPromptStyle} aria-live="polite">
          <strong>
            {autofillSavePrompt.mode === "update"
              ? "Update password?"
              : autofillSavePrompt.mode === "retry"
                ? "Retry login lookup?"
                : autofillSavePrompt.ambiguous
                  ? "Save new login?"
                  : "Save login?"}
          </strong>
          <div style={{ color: popupTheme.colors.textMuted, fontSize: "0.86rem" }}>
            {titleForPendingSubmission(autofillSavePrompt.submission)}
          </div>
          {autofillSaveError ? <div role="alert">{autofillSaveError}</div> : null}
          <div style={{ display: "flex", gap: popupTheme.spacing.sm, flexWrap: "wrap" }}>
            <button
              type="button"
              onClick={() => {
                if (autofillSavePrompt.mode === "retry") {
                  retryPendingAutofillPrompt();
                } else {
                  void handleSavePendingLogin();
                }
              }}
              disabled={savingAutofillPrompt}
              style={primaryActionStyle}
            >
              {autofillSavePrompt.mode === "update"
                ? pendingTransactionState(autofillSavePrompt.submission) ===
                  "persist_conflict"
                  ? autofillSavePrompt.submission.state === "persist_conflict" &&
                    autofillSavePrompt.submission.conflict.retryable
                    ? "Retry Update"
                    : "Replan Update"
                  : "Update Password"
                : autofillSavePrompt.mode === "retry"
                  ? "Retry"
                  : autofillSavePrompt.ambiguous
                    ? "Save New Login"
                    : "Save Login"}
            </button>
            {pendingTransactionState(autofillSavePrompt.submission) !==
            "persisting" ? (
              <button
                type="button"
                onClick={() => {
                  void dismissAutofillPrompt();
                }}
                disabled={savingAutofillPrompt}
                style={secondaryActionStyle}
              >
                Dismiss
              </button>
            ) : null}
          </div>
        </section>
      ) : null}
      <SiteCandidateList
        candidates={candidates}
        onFill={(entryId) =>
          fillEntry(session.activeVaultId ?? "", entryId, {
            requireSiteCandidate: true
          })
        }
      />
    </div>
    </I18nProvider>
  );
}

const shellStyle = {
  width: "460px",
  maxWidth: "100%",
  maxHeight: "600px",
  minWidth: 0,
  display: "grid",
  gap: popupTheme.spacing.md,
  padding: popupTheme.spacing.md,
  background: `linear-gradient(180deg, ${popupTheme.colors.surface} 0%, ${popupTheme.colors.accentSoft} 100%)`,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  boxSizing: "border-box" as const,
  overflowX: "hidden" as const,
  overflowY: "auto" as const
};

const primaryActionStyle = {
  border: `1px solid ${popupTheme.colors.accentStrong}`,
  borderRadius: popupTheme.radius.pill,
  padding: `${popupTheme.spacing.sm} ${popupTheme.spacing.md}`,
  background: popupTheme.colors.accentStrong,
  color: "#fffaf2",
  fontFamily: popupTheme.font.body,
  cursor: "pointer"
};

const secondaryActionStyle = {
  border: `1px solid ${popupTheme.colors.line}`,
  borderRadius: popupTheme.radius.pill,
  padding: `${popupTheme.spacing.sm} ${popupTheme.spacing.md}`,
  background: popupTheme.colors.surfaceMuted,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  cursor: "pointer"
};

const passkeyPromptStyle = {
  display: "grid",
  gap: popupTheme.spacing.xs,
  border: `1px solid ${popupTheme.colors.accentStrong}`,
  borderRadius: popupTheme.radius.panel,
  padding: popupTheme.spacing.sm,
  background: popupTheme.colors.surface,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  lineHeight: 1.45
};

const passkeyCredentialListStyle = {
  display: "grid",
  gap: popupTheme.spacing.xs,
  minWidth: 0
};

const passkeyCredentialOptionStyle = {
  display: "flex",
  alignItems: "center",
  gap: popupTheme.spacing.sm,
  border: `1px solid ${popupTheme.colors.line}`,
  borderRadius: popupTheme.radius.field,
  padding: popupTheme.spacing.sm,
  background: popupTheme.colors.surface,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  overflowWrap: "anywhere" as const
};

const messagePanelStyle = {
  borderRadius: popupTheme.radius.panel,
  padding: popupTheme.spacing.sm,
  background: popupTheme.colors.surfaceMuted,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body
};
