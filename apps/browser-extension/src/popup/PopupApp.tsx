import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import type {
  EntrySummary,
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
import { popupErrorMessage } from "./popupError";
import {
  popupMessagePanelStyle,
  popupPrimaryActionStyle,
  popupPromptStyle,
  popupSecondaryActionStyle,
  popupShellStyle,
  popupTheme
} from "./theme";
import type {
  PendingLoginPrompt,
  PendingLoginWorkflow
} from "./pendingLoginWorkflow";

type SessionStateLike = Pick<
  SessionState,
  "unlocked" | "activeVaultId"
>;

export interface PopupClientLike {
  getSessionState(): Promise<SessionStateLike>;
  recordUserActivity(): Promise<SessionStateLike>;
}

interface FillEntryOptions {
  requireSiteCandidate?: boolean;
}

export function PopupApp({
  client,
  findCandidates,
  fillEntry,
  activeSite,
  pendingLoginWorkflow,
  openResidentApp,
  extensionSettingsStore,
  renderRuntimeErrorHelp
}: {
  client: PopupClientLike;
  findCandidates: (vaultId: string, siteUrl?: string) => Promise<EntrySummary[]>;
  fillEntry: (vaultId: string, entryId: string, options?: FillEntryOptions) => Promise<void>;
  activeSite: () => Promise<string>;
  pendingLoginWorkflow: PendingLoginWorkflow;
  openResidentApp: (route: ResidentAppRoute) => Promise<void>;
  extensionSettingsStore?: Pick<ExtensionSettingsStore, "load">;
  renderRuntimeErrorHelp?: (error: unknown) => ReactNode;
}) {
  const [session, setSession] = useState<SessionStateLike | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [sessionErrorCause, setSessionErrorCause] = useState<unknown>(null);
  const [siteLabel, setSiteLabel] = useState("No active site");
  const [candidates, setCandidates] = useState<EntrySummary[]>([]);
  const [entriesError, setEntriesError] = useState<string | null>(null);
  const [autofillSavePrompt, setAutofillSavePrompt] =
    useState<PendingLoginPrompt | null>(null);
  const [autofillSaveError, setAutofillSaveError] = useState<string | null>(null);
  const [pendingAutofillRetryVersion, setPendingAutofillRetryVersion] =
    useState(0);
  const [savingAutofillPrompt, setSavingAutofillPrompt] = useState(false);
  const savingAutofillPromptRef = useRef(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [unlockErrorCause, setUnlockErrorCause] = useState<unknown>(null);
  const [extensionSettings, setExtensionSettings] = useState(
    DEFAULT_EXTENSION_SETTINGS
  );

  async function loadExtensionSettingsForPopup() {
    const loadedSettings =
      (await extensionSettingsStore?.load()) ?? DEFAULT_EXTENSION_SETTINGS;
    const normalizedSettings = normalizeBrowserExtensionSettings(loadedSettings);
    setExtensionSettings(normalizedSettings);
    return normalizedSettings;
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
    session?.unlocked
  ]);

  useEffect(() => {
    if (!session?.unlocked || !session.activeVaultId) {
      setAutofillSavePrompt(null);
      setAutofillSaveError(null);
      return;
    }

    let cancelled = false;
    const activeVaultId = session.activeVaultId;
    setAutofillSavePrompt(null);
    setAutofillSaveError(null);
    pendingLoginWorkflow
      .loadPrompt(activeVaultId)
      .then((loaded) => {
        if (cancelled) {
          return;
        }
        setAutofillSavePrompt(loaded.prompt);
        setAutofillSaveError(loaded.errorMessage ?? null);
      })
      .catch((loadFailure) => {
        if (cancelled) {
          return;
        }
        setAutofillSavePrompt(null);
        setAutofillSaveError(
          popupErrorMessage(
            loadFailure,
            "Failed to recover pending login save"
          )
        );
      });

    return () => {
      cancelled = true;
    };
  }, [
    pendingLoginWorkflow,
    pendingAutofillRetryVersion,
    session?.activeVaultId,
    session?.unlocked
  ]);

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
    setAutofillSavePrompt(null);
    setAutofillSaveError(null);
  }

  function retryPendingAutofillPrompt() {
    setAutofillSaveError(null);
    setPendingAutofillRetryVersion((version) => version + 1);
  }

  async function dismissAutofillPrompt() {
    if (!autofillSavePrompt) {
      return;
    }
    try {
      await pendingLoginWorkflow.dismiss(autofillSavePrompt);
      clearAutofillPromptLocally();
    } catch (dismissFailure) {
      setAutofillSaveError(
        popupErrorMessage(dismissFailure, "Failed to dismiss login save")
      );
    }
  }

  async function handleSavePendingLogin() {
    if (
      !session?.activeVaultId ||
      !autofillSavePrompt ||
      savingAutofillPromptRef.current
    ) {
      return;
    }
    if (session.activeVaultId !== autofillSavePrompt.vaultId) {
      clearAutofillPromptLocally();
      return;
    }

    savingAutofillPromptRef.current = true;
    setSavingAutofillPrompt(true);
    setAutofillSaveError(null);

    try {
      const result = await pendingLoginWorkflow.save(autofillSavePrompt);
      if (
        result.status === "saved" ||
        result.status === "dismissed" ||
        result.status === "expired"
      ) {
        clearAutofillPromptLocally();
        if (result.status === "saved" && result.candidates) {
          setCandidates(result.candidates);
        }
        return;
      }
      setAutofillSavePrompt(result.prompt);
      setAutofillSaveError(result.errorMessage);
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
        <div style={popupShellStyle}>
          <div role="alert">{sessionError}</div>
          {renderRuntimeErrorHelp?.(sessionErrorCause)}
        </div>
      );
    }

    return <div style={popupShellStyle}>Loading...</div>;
  }

  if (!session.unlocked) {
    const lockedBody =
      extensionSettings.language === "zh-CN"
        ? "数据库由 VaultKern 客户端持有。请在客户端完成解锁。"
        : "Your vault is held by the VaultKern app. Unlock it there to continue.";

    return (
      <I18nProvider language={extensionSettings.language}>
      <div style={popupShellStyle}>
        <PopupStatusStrip
          siteLabel={siteLabel}
          unlocked={false}
          onOpenExtensionSettings={handleOpenExtensionSettings}
        />
        <div style={popupMessagePanelStyle}>{lockedBody}</div>
        <div style={{ display: "grid", gap: popupTheme.spacing.sm }}>
          <button
            type="button"
            onClick={() => {
              void handleOpenResident("unlock");
            }}
            style={popupPrimaryActionStyle}
          >
            {extensionSettings.language === "zh-CN" ? "打开 VaultKern" : "Open VaultKern"}
          </button>
          <button
            type="button"
            onClick={handleOpenManager}
            style={popupSecondaryActionStyle}
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

  return (
    <I18nProvider language={extensionSettings.language}>
    <div style={popupShellStyle}>
      <PopupStatusStrip
        siteLabel={siteLabel}
        unlocked
        onOpenManager={handleOpenManager}
        onOpenExtensionSettings={handleOpenExtensionSettings}
      />
      {entriesError ? <div role="alert">{entriesError}</div> : null}
      {!autofillSavePrompt && autofillSaveError ? (
        <section style={popupPromptStyle} aria-live="polite">
          <div role="alert">{autofillSaveError}</div>
          <button
            type="button"
            onClick={retryPendingAutofillPrompt}
            style={popupPrimaryActionStyle}
          >
            Retry
          </button>
        </section>
      ) : null}
      {autofillSavePrompt ? (
        <section style={popupPromptStyle} aria-live="polite">
          <strong>
            {autofillSavePrompt.mode === "update"
              ? "Update password?"
              : autofillSavePrompt.mode === "cleanup"
                ? "Clear saved login prompt?"
              : autofillSavePrompt.mode === "retry"
                ? "Retry login lookup?"
                : autofillSavePrompt.ambiguous
                  ? "Save new login?"
                  : "Save login?"}
          </strong>
          <div style={{ color: popupTheme.colors.textMuted, fontSize: "0.86rem" }}>
            {autofillSavePrompt.siteLabel}
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
              style={popupPrimaryActionStyle}
            >
              {autofillSavePrompt.action === "retry_cleanup"
                ? "Retry Cleanup"
                : autofillSavePrompt.action === "update"
                    ? "Update Password"
                    : autofillSavePrompt.action === "retry_lookup"
                      ? "Retry"
                      : autofillSavePrompt.action === "save_new"
                        ? "Save New Login"
                        : "Save Login"}
            </button>
            {autofillSavePrompt.canDismiss ? (
              <button
                type="button"
                onClick={() => {
                  void dismissAutofillPrompt();
                }}
                disabled={savingAutofillPrompt}
                style={popupSecondaryActionStyle}
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
