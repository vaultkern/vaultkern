import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import {
  DEFAULT_EXTENSION_SETTINGS,
  I18nProvider,
  normalizeBrowserExtensionSettings
} from "@vaultkern/shared-web-ui";
import type { ExtensionSettingsStore } from "@vaultkern/shared-web-ui";

import { PopupStatusStrip } from "./PopupStatusStrip";
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
  BrowserPasskeyPromptWorkflow,
  PasskeyCredentialOption
} from "./passkeyPromptWorkflow";

export function PasskeyPromptApp({
  workflow,
  settingsStore,
  renderRuntimeErrorHelp
}: {
  workflow: BrowserPasskeyPromptWorkflow;
  settingsStore?: Pick<ExtensionSettingsStore, "load">;
  renderRuntimeErrorHelp?: (error: unknown) => ReactNode;
}) {
  const [session, setSession] = useState<Awaited<
    ReturnType<BrowserPasskeyPromptWorkflow["getSessionState"]>
  > | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [sessionErrorCause, setSessionErrorCause] = useState<unknown>(null);
  const [activationError, setActivationError] = useState<string | null>(null);
  const [activationErrorCause, setActivationErrorCause] = useState<unknown>(null);
  const [settings, setSettings] = useState(DEFAULT_EXTENSION_SETTINGS);
  const [submitting, setSubmitting] = useState(false);
  const [credentialOptions, setCredentialOptions] = useState<
    PasskeyCredentialOption[]
  >([]);
  const [selectedCredentialId, setSelectedCredentialId] = useState("");
  const [waitingForCredentialOptions, setWaitingForCredentialOptions] =
    useState(false);
  const unlockCompletionSent = useRef(false);
  const { mode, siteLabel } = workflow.request;

  useEffect(() => {
    let cancelled = false;
    Promise.resolve(settingsStore?.load() ?? DEFAULT_EXTENSION_SETTINGS)
      .then((loaded) => {
        if (!cancelled) {
          setSettings(normalizeBrowserExtensionSettings(loaded));
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setSessionError(
            popupErrorMessage(loadError, "Failed to load extension preferences")
          );
          setSessionErrorCause(loadError);
        }
      });

    workflow
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
            popupErrorMessage(loadError, "Failed to load session state")
          );
          setSessionErrorCause(loadError);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [settingsStore, workflow]);

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
      void workflow
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
  }, [session?.unlocked, workflow]);

  useEffect(() => {
    setSelectedCredentialId((currentCredentialId) => {
      if (
        currentCredentialId &&
        credentialOptions.some(
          (option) => option.credentialId === currentCredentialId
        )
      ) {
        return currentCredentialId;
      }
      return credentialOptions[0]?.credentialId ?? "";
    });
  }, [credentialOptions]);

  useEffect(() => {
    let cancelled = false;
    if (mode !== "approve") {
      setCredentialOptions([]);
      return () => {
        cancelled = true;
      };
    }
    workflow
      .loadCredentialOptions()
      .then((options) => {
        if (!cancelled) {
          setCredentialOptions(options);
          if (options.length > 0) {
            setWaitingForCredentialOptions(false);
          }
        }
      })
      .catch(() => {
        if (!cancelled) {
          setCredentialOptions([]);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [mode, workflow]);

  useEffect(() => {
    if (
      mode !== "approve" ||
      !waitingForCredentialOptions ||
      credentialOptions.length > 0
    ) {
      return undefined;
    }

    let cancelled = false;
    const timer = window.setInterval(() => {
      workflow
        .loadCredentialOptions()
        .then((options) => {
          if (cancelled || options.length === 0) {
            return;
          }
          setCredentialOptions(options);
          setWaitingForCredentialOptions(false);
        })
        .catch(() => undefined);
    }, 250);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [
    credentialOptions.length,
    mode,
    waitingForCredentialOptions,
    workflow
  ]);

  useEffect(() => {
    if (mode !== "unlock" || session?.unlocked) {
      return undefined;
    }
    let cancelled = false;
    let requestPending = false;
    const timer = window.setInterval(() => {
      if (requestPending) {
        return;
      }
      requestPending = true;
      void workflow
        .getSessionState()
        .then((nextSession) => {
          if (
            cancelled ||
            !nextSession.unlocked ||
            !nextSession.activeVaultId ||
            unlockCompletionSent.current
          ) {
            return;
          }
          unlockCompletionSent.current = true;
          setSession(nextSession);
          void workflow.complete({ type: "unlock" }).catch(() => undefined);
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
  }, [mode, session?.unlocked, workflow]);

  async function openResidentApp(
    route: "unlock" | "vaults" | "settings"
  ) {
    setActivationError(null);
    setActivationErrorCause(null);
    try {
      await workflow.activateResidentApp(route);
    } catch (activationFailure) {
      setActivationError(
        popupErrorMessage(activationFailure, "Failed to open VaultKern")
      );
      setActivationErrorCause(activationFailure);
    }
  }

  async function approvePresence() {
    if (!session?.unlocked || submitting) {
      return;
    }
    setSubmitting(true);
    try {
      const result = await workflow.complete({
        type: "presence",
        ...(credentialOptions.length > 0 && selectedCredentialId
          ? { credentialId: selectedCredentialId }
          : {})
      });
      if (result.keepOpen) {
        setCredentialOptions(result.credentialOptions);
        setWaitingForCredentialOptions(result.credentialOptions.length === 0);
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function verifyUser() {
    if (!session?.unlocked || submitting) {
      return;
    }
    setSubmitting(true);
    setActivationError(null);
    setActivationErrorCause(null);
    try {
      await workflow.complete({ type: "user_verification" });
    } catch (verificationFailure) {
      setActivationError(
        popupErrorMessage(
          verificationFailure,
          settings.language === "zh-CN" ? "用户验证失败" : "User verification failed"
        )
      );
      setActivationErrorCause(verificationFailure);
    } finally {
      setSubmitting(false);
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
    const promptTitle =
      settings.language === "zh-CN"
        ? "通行密钥请求等待中"
        : "Passkey request waiting";
    const promptBody =
      siteLabel === "No active site"
        ? settings.language === "zh-CN"
          ? "请解锁数据库以继续当前网站的通行密钥请求。"
          : "Unlock your vault to continue the website passkey request."
        : settings.language === "zh-CN"
          ? `请解锁数据库以继续 ${siteLabel} 的通行密钥请求。`
          : `Unlock your vault to continue the passkey request for ${siteLabel}.`;
    const lockedBody =
      settings.language === "zh-CN"
        ? "数据库由 VaultKern 客户端持有。请在客户端完成解锁。"
        : "Your vault is held by the VaultKern app. Unlock it there to continue.";

    return (
      <I18nProvider language={settings.language}>
        <div style={popupShellStyle}>
          <PopupStatusStrip
            siteLabel={siteLabel}
            unlocked={false}
            onOpenExtensionSettings={() => {
              void openResidentApp("settings");
            }}
          />
          {mode === "unlock" ? (
            <section style={popupPromptStyle} aria-live="polite">
              <strong>{promptTitle}</strong>
              <span>{promptBody}</span>
            </section>
          ) : null}
          <div style={popupMessagePanelStyle}>{lockedBody}</div>
          <div style={{ display: "grid", gap: popupTheme.spacing.sm }}>
            <button
              type="button"
              onClick={() => {
                void openResidentApp("unlock");
              }}
              style={popupPrimaryActionStyle}
            >
              {settings.language === "zh-CN" ? "打开 VaultKern" : "Open VaultKern"}
            </button>
            <button
              type="button"
              onClick={() => {
                void openResidentApp("vaults");
              }}
              style={popupSecondaryActionStyle}
            >
              {settings.language === "zh-CN" ? "管理数据库" : "Manage Vaults"}
            </button>
            {activationError ? <div role="alert">{activationError}</div> : null}
            {activationError && renderRuntimeErrorHelp
              ? renderRuntimeErrorHelp(activationErrorCause)
              : null}
          </div>
        </div>
      </I18nProvider>
    );
  }

  if (mode === "verify") {
    const promptTitle =
      settings.language === "zh-CN"
        ? "验证通行密钥请求"
        : "Verify passkey request";
    const promptBody =
      siteLabel === "No active site"
        ? settings.language === "zh-CN"
          ? "请使用 Windows Hello 验证以继续当前网站的通行密钥请求。"
          : "Verify with Windows Hello to continue this passkey request."
        : settings.language === "zh-CN"
          ? `请使用 Windows Hello 验证以继续 ${siteLabel} 的通行密钥请求。`
          : `Verify with Windows Hello to continue the passkey request for ${siteLabel}.`;

    return (
      <I18nProvider language={settings.language}>
        <div style={popupShellStyle}>
          <PopupStatusStrip siteLabel={siteLabel} unlocked />
          <section style={popupPromptStyle} aria-live="polite">
            <strong>{promptTitle}</strong>
            <span>{promptBody}</span>
          </section>
          <div style={{ display: "grid", gap: popupTheme.spacing.md }}>
            <button
              type="button"
              onClick={() => {
                void verifyUser();
              }}
              disabled={submitting}
              style={popupPrimaryActionStyle}
            >
              {submitting
                ? settings.language === "zh-CN"
                  ? "验证中..."
                  : "Verifying..."
                : settings.language === "zh-CN"
                  ? "使用 Windows Hello 验证"
                  : "Verify with Windows Hello"}
            </button>
            {activationError ? <div role="alert">{activationError}</div> : null}
            {activationError && renderRuntimeErrorHelp
              ? renderRuntimeErrorHelp(activationErrorCause)
              : null}
          </div>
        </div>
      </I18nProvider>
    );
  }

  if (mode === "approve") {
    const promptTitle =
      settings.language === "zh-CN"
        ? "确认通行密钥请求"
        : "Confirm passkey request";
    const promptBody =
      siteLabel === "No active site"
        ? settings.language === "zh-CN"
          ? "确认后继续当前网站的通行密钥请求。"
          : "Approve this passkey request to continue."
        : settings.language === "zh-CN"
          ? `确认后继续 ${siteLabel} 的通行密钥请求。`
          : `Approve this passkey request for ${siteLabel}.`;
    const promptAction = waitingForCredentialOptions
      ? settings.language === "zh-CN"
        ? "正在载入通行密钥账号..."
        : "Loading passkey accounts..."
      : settings.language === "zh-CN"
        ? "继续通行密钥请求"
        : "Continue passkey request";

    return (
      <I18nProvider language={settings.language}>
        <div style={popupShellStyle}>
          <PopupStatusStrip siteLabel={siteLabel} unlocked />
          <section style={popupPromptStyle} aria-live="polite">
            <strong>{promptTitle}</strong>
            <span>{promptBody}</span>
          </section>
          {credentialOptions.length > 0 ? (
            <div
              role="radiogroup"
              aria-label={
                settings.language === "zh-CN"
                  ? "选择通行密钥账号"
                  : "Choose passkey account"
              }
              style={credentialListStyle}
            >
              {credentialOptions.map((option) => (
                <label key={option.credentialId} style={credentialOptionStyle}>
                  <input
                    type="radio"
                    aria-label={option.username || option.credentialId}
                    checked={selectedCredentialId === option.credentialId}
                    onChange={() => setSelectedCredentialId(option.credentialId)}
                  />
                  <span>{option.username || option.credentialId}</span>
                </label>
              ))}
            </div>
          ) : null}
          <button
            type="button"
            onClick={() => {
              void approvePresence();
            }}
            disabled={
              submitting ||
              waitingForCredentialOptions ||
              (credentialOptions.length > 0 && !selectedCredentialId)
            }
            style={popupPrimaryActionStyle}
          >
            {promptAction}
          </button>
        </div>
      </I18nProvider>
    );
  }

  return (
    <I18nProvider language={settings.language}>
      <div style={popupShellStyle}>
        <PopupStatusStrip siteLabel={siteLabel} unlocked />
      </div>
    </I18nProvider>
  );
}

const credentialListStyle = {
  display: "grid",
  gap: popupTheme.spacing.xs,
  minWidth: 0
};

const credentialOptionStyle = {
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
