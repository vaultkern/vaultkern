import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import type {
  EntryDetail,
  EntrySummary,
  SessionState,
  UnlockCredentials,
  VaultReference
} from "@vaultkern/runtime-web-client";
import {
  DEFAULT_EXTENSION_SETTINGS,
  I18nProvider,
  normalizeExtensionSettings,
  translate
} from "@vaultkern/shared-web-ui";
import type { ExtensionSettingsStore } from "@vaultkern/shared-web-ui";

import { PopupRecordCard } from "./PopupRecordCard";
import { PopupSearch } from "./PopupSearch";
import { PopupStatusStrip } from "./PopupStatusStrip";
import { SiteCandidateList } from "./SiteCandidateList";
import { PopupVaultList } from "./PopupVaultList";
import { popupErrorMessage, popupTheme } from "./theme";

type SessionStateLike = Pick<
  SessionState,
  "unlocked" | "activeVaultId" | "currentVaultRefId" | "supportsBiometricUnlock"
>;

type PasskeyCredentialOption = {
  credentialId: string;
  username: string;
};

export interface PopupClientLike {
  getSessionState(): Promise<SessionStateLike>;
  listRecentVaults(): Promise<VaultReference[]>;
  preloadCurrentVault(): Promise<SessionStateLike>;
  addLocalVaultReference(path?: string): Promise<VaultReference>;
  setCurrentVault(vaultRefId: string): Promise<SessionStateLike>;
  lockSession(): Promise<SessionStateLike>;
  unlockCurrentVaultWithPassword(password: string): Promise<SessionStateLike>;
  unlockCurrentVault(credentials: UnlockCredentials): Promise<SessionStateLike>;
  enableQuickUnlockForCurrentVault(): Promise<SessionStateLike>;
  unlockCurrentVaultWithQuickUnlock(): Promise<SessionStateLike>;
  listEntries(vaultId: string): Promise<EntrySummary[]>;
  getEntryDetail(vaultId: string, entryId: string): Promise<EntryDetail>;
}

function limitRecentVaults(vaults: VaultReference[], limit: number) {
  return [...vaults]
    .sort((left, right) => (right.lastUsedAt ?? 0) - (left.lastUsedAt ?? 0))
    .slice(0, limit);
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
  extensionSettingsStore,
  renderRuntimeErrorHelp,
  onUnlockComplete,
  onWebAuthnPresenceComplete,
  onWebAuthnUserVerificationComplete
}: {
  client: PopupClientLike;
  findCandidates: (vaultId: string) => Promise<EntrySummary[]>;
  fillEntry: (vaultId: string, entryId: string) => Promise<void>;
  activeSite: () => Promise<string>;
  extensionSettingsStore?: ExtensionSettingsStore;
  renderRuntimeErrorHelp?: (error: unknown) => ReactNode;
  onUnlockComplete?: (
    session: SessionStateLike,
    options?: { method: "master_password" | "quick_unlock"; password?: string }
  ) => void | Promise<void>;
  onWebAuthnPresenceComplete?: (
    session: SessionStateLike,
    options?: { credentialId?: string }
  ) => unknown | Promise<unknown>;
  onWebAuthnUserVerificationComplete?: (
    session: SessionStateLike,
    options: { method: "master_password" | "quick_unlock"; password?: string }
  ) => void | Promise<void>;
}) {
  const [session, setSession] = useState<SessionStateLike | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [sessionErrorCause, setSessionErrorCause] = useState<unknown>(null);
  const [siteLabel, setSiteLabel] = useState("No active site");
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [candidates, setCandidates] = useState<EntrySummary[]>([]);
  const [entriesError, setEntriesError] = useState<string | null>(null);
  const [searchValue, setSearchValue] = useState("");
  const [selectedEntryId, setSelectedEntryId] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<EntryDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [unlockErrorCause, setUnlockErrorCause] = useState<unknown>(null);
  const [recentVaults, setRecentVaults] = useState<VaultReference[]>([]);
  const [recentVaultsLoading, setRecentVaultsLoading] = useState(true);
  const [recentVaultsError, setRecentVaultsError] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [keyFilePath, setKeyFilePath] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [locking, setLocking] = useState(false);
  const [extensionSettings, setExtensionSettings] = useState(
    DEFAULT_EXTENSION_SETTINGS
  );
  const currentVaultPreload = useRef<Promise<void> | null>(null);
  const webAuthnQuickUnlockAttempted = useRef(false);
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

  function currentVaultForSession() {
    return (
      recentVaults.find((vault) => vault.vaultRefId === session?.currentVaultRefId) ??
      recentVaults.find((vault) => vault.isCurrent) ??
      null
    );
  }

  function canQuickUnlockVault(vault: VaultReference | null) {
    return Boolean(
      session?.supportsBiometricUnlock &&
        vault?.supportsQuickUnlock &&
        vault.availability !== "needs_repair"
    );
  }

  async function enableQuickUnlockAfterPasswordUnlock(
    unlockedSession: SessionStateLike
  ) {
    if (!extensionSettings.quickUnlockEnabled) {
      return unlockedSession;
    }

    const currentVault =
      recentVaults.find(
        (vault) => vault.vaultRefId === unlockedSession.currentVaultRefId
      ) ??
      recentVaults.find((vault) => vault.isCurrent) ??
      null;

    if (!currentVault || currentVault.supportsQuickUnlock) {
      return unlockedSession;
    }

    try {
      const nextSession = await client.enableQuickUnlockForCurrentVault();
      const vaults = await client.listRecentVaults();
      setRecentVaults(limitRecentVaults(vaults, extensionSettings.recentVaultLimit));
      setRecentVaultsError(null);
      return nextSession;
    } catch (quickUnlockFailure) {
      setUnlockError(
        popupErrorMessage(
          quickUnlockFailure,
          translate(extensionSettings.language, "Failed to update quick unlock")
        )
      );
      setUnlockErrorCause(quickUnlockFailure);
      return unlockedSession;
    }
  }

  function notifyWebAuthnUnlockCompleteOnce(
    nextSession: SessionStateLike,
    options?: { method: "master_password" | "quick_unlock"; password?: string }
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

  function startCurrentVaultPreload() {
    if (currentVaultPreload.current) {
      return currentVaultPreload.current;
    }

    const preload = client
      .preloadCurrentVault()
      .then(() => undefined)
      .finally(() => {
        if (currentVaultPreload.current === preload) {
          currentVaultPreload.current = null;
        }
      });

    currentVaultPreload.current = preload;
    void preload.catch(() => undefined);
    return preload;
  }

  useEffect(() => {
    let cancelled = false;

    const settingsPromise =
      extensionSettingsStore?.load() ?? Promise.resolve(DEFAULT_EXTENSION_SETTINGS);

    settingsPromise
      .then((loadedSettings) => {
        const normalizedSettings = normalizeExtensionSettings(loadedSettings);
        if (!cancelled) {
          setExtensionSettings(normalizedSettings);
        }
        return normalizedSettings;
      })
      .then((normalizedSettings) =>
        client.listRecentVaults().then((vaults) => ({
          normalizedSettings,
          vaults
        }))
      )
      .then(({ normalizedSettings, vaults }) => {
        if (!cancelled) {
          setRecentVaults(limitRecentVaults(vaults, normalizedSettings.recentVaultLimit));
          setRecentVaultsError(null);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setRecentVaults([]);
          setRecentVaultsError(
            popupErrorMessage(
              loadError,
              translate(extensionSettings.language, "Failed to load popup data")
            )
          );
        }
      })
      .finally(() => {
        if (!cancelled) {
          setRecentVaultsLoading(false);
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
    if (!session?.currentVaultRefId || session.unlocked || recentVaultsLoading) {
      return;
    }

    startCurrentVaultPreload();
  }, [recentVaultsLoading, session?.currentVaultRefId, session?.unlocked]);

  useEffect(() => {
    setSelectedPasskeyCredentialId(
      passkeyCredentialOptions[0]?.credentialId ?? ""
    );
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
    if (
      typeof window === "undefined" ||
      !session?.unlocked ||
      extensionSettings.idleLockMinutes <= 0
    ) {
      return undefined;
    }

    let timer = window.setTimeout(handleTimeout, extensionSettings.idleLockMinutes * 60_000);

    function resetTimer() {
      window.clearTimeout(timer);
      timer = window.setTimeout(handleTimeout, extensionSettings.idleLockMinutes * 60_000);
    }

    function handleTimeout() {
      void client.lockSession().then((nextSession) => {
        setSession(nextSession);
      });
    }

    const events = ["pointerdown", "keydown", "wheel", "scroll"];
    for (const eventName of events) {
      window.addEventListener(eventName, resetTimer, { passive: true });
    }

    return () => {
      window.clearTimeout(timer);
      for (const eventName of events) {
        window.removeEventListener(eventName, resetTimer);
      }
    };
  }, [client, extensionSettings.idleLockMinutes, session?.unlocked]);

  useEffect(() => {
    if (webAuthnCeremonyPrompt) {
      setEntries([]);
      setCandidates([]);
      setSelectedEntryId(null);
      setSelectedDetail(null);
      setDetailError(null);
      return;
    }

    if (!session?.unlocked || !session.activeVaultId) {
      setEntries([]);
      setCandidates([]);
      setSelectedEntryId(null);
      setSelectedDetail(null);
      setDetailError(null);
      return;
    }

    let cancelled = false;
    Promise.allSettled([
      client.listEntries(session.activeVaultId),
      findCandidates(session.activeVaultId)
    ]).then(([entriesResult, candidatesResult]) => {
      if (cancelled) {
        return;
      }

      const loadedEntries =
        entriesResult.status === "fulfilled" ? entriesResult.value : [];
      const loadedCandidates =
        candidatesResult.status === "fulfilled" ? candidatesResult.value : [];

      setEntries(loadedEntries);
      setCandidates(loadedCandidates);

      const nextError =
        entriesResult.status === "rejected"
          ? popupErrorMessage(
              entriesResult.reason,
              translate(extensionSettings.language, "Failed to load popup data")
            )
          : candidatesResult.status === "rejected"
            ? popupErrorMessage(
                candidatesResult.reason,
                translate(extensionSettings.language, "Failed to load site candidates")
              )
            : null;

      setEntriesError(nextError);

      const nextSelectedId = loadedCandidates[0]?.id ?? null;
      setSelectedEntryId(nextSelectedId);
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
    if (webAuthnCeremonyPrompt) {
      setSelectedDetail(null);
      setDetailError(null);
      return;
    }

    if (!session?.activeVaultId || !selectedEntryId) {
      setSelectedDetail(null);
      setDetailError(null);
      return;
    }

    let cancelled = false;

    Promise.resolve(client.getEntryDetail(session.activeVaultId, selectedEntryId))
      .then((detail) => {
        if (!cancelled) {
          setSelectedDetail(detail ?? null);
          setDetailError(null);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setSelectedDetail(null);
          setDetailError(
            popupErrorMessage(
              loadError,
              translate(extensionSettings.language, "Failed to load record detail")
            )
          );
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    client,
    extensionSettings.language,
    selectedEntryId,
    session?.activeVaultId,
    webAuthnCeremonyPrompt
  ]);

  async function handleUnlock() {
    if (submitting) {
      return;
    }

    setSubmitting(true);
    setUnlockError(null);
    setUnlockErrorCause(null);

    try {
      const preload =
        currentVaultPreload.current ??
        (session?.currentVaultRefId && !unlockError
          ? startCurrentVaultPreload()
          : null);
      if (preload) {
        await preload;
      }
      const unlockPassword = password;
      const unlockKeyFilePath = keyFilePath;
      const unlockedSession = await client.unlockCurrentVault({
        password,
        keyFilePath
      });
      const shouldEnableQuickUnlock =
        unlockPassword !== "" || unlockKeyFilePath !== "";
      const nextSession =
        shouldEnableQuickUnlock
          ? await enableQuickUnlockAfterPasswordUnlock(unlockedSession)
          : unlockedSession;
      setSession(nextSession);
      setPassword("");
      setKeyFilePath("");
      notifyWebAuthnUnlockCompleteOnce(
        nextSession,
        unlockPassword !== ""
          ? { method: "master_password", password: unlockPassword }
          : undefined
      );
    } catch (unlockFailure) {
      setUnlockError(
        popupErrorMessage(
          unlockFailure,
          translate(extensionSettings.language, "Failed to unlock vault")
        )
      );
      setUnlockErrorCause(unlockFailure);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleQuickUnlock() {
    if (submitting) {
      return;
    }

    setSubmitting(true);
    setUnlockError(null);
    setUnlockErrorCause(null);

    try {
      const preload =
        currentVaultPreload.current ??
        (session?.currentVaultRefId && !unlockError
          ? startCurrentVaultPreload()
          : null);
      if (preload) {
        await preload;
      }
      const nextSession = await client.unlockCurrentVaultWithQuickUnlock();
      setSession(nextSession);
      setPassword("");
      setKeyFilePath("");
      notifyWebAuthnUnlockCompleteOnce(nextSession, { method: "quick_unlock" });
    } catch (unlockFailure) {
      setUnlockError(
        popupErrorMessage(
          unlockFailure,
          translate(extensionSettings.language, "Failed to unlock vault")
        )
      );
      setUnlockErrorCause(unlockFailure);
    } finally {
      setSubmitting(false);
    }
  }

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

  async function handleWebAuthnUserVerification(
    method: "master_password" | "quick_unlock"
  ) {
    if (!session?.unlocked || submitting) {
      return;
    }
    if (method === "master_password" && password.trim() === "") {
      setUnlockError(
        extensionSettings.language === "zh-CN"
          ? "请输入主密码"
          : "Enter your master password"
      );
      return;
    }

    setSubmitting(true);
    setUnlockError(null);
    setUnlockErrorCause(null);
    try {
      await Promise.resolve(
        onWebAuthnUserVerificationComplete?.(session, {
          method,
          ...(method === "master_password" ? { password } : {})
        })
      );
      setPassword("");
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
    if (
      !webAuthnUnlockPrompt ||
      webAuthnQuickUnlockAttempted.current ||
      submitting ||
      recentVaultsLoading ||
      !session ||
      session.unlocked ||
      !canQuickUnlockVault(currentVaultForSession())
    ) {
      return;
    }

    webAuthnQuickUnlockAttempted.current = true;
    void handleQuickUnlock();
  }, [
    recentVaults,
    recentVaultsLoading,
    session,
    submitting,
    webAuthnUnlockPrompt
  ]);

  useEffect(() => {
    if (
      !webAuthnVerifyPrompt ||
      webAuthnQuickUnlockAttempted.current ||
      submitting ||
      recentVaultsLoading ||
      !session?.unlocked ||
      !canQuickUnlockVault(currentVaultForSession())
    ) {
      return;
    }

    webAuthnQuickUnlockAttempted.current = true;
    void handleWebAuthnUserVerification("quick_unlock");
  }, [
    recentVaults,
    recentVaultsLoading,
    session,
    submitting,
    webAuthnVerifyPrompt
  ]);

  async function handleOpenManager() {
    const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
    const runtime = chromeApi?.runtime;
    const tabs = chromeApi?.tabs;

    if (!tabs?.create || !runtime?.getURL) {
      return;
    }

    await tabs.create({ url: runtime.getURL("manager.html") });
  }

  async function handleOpenExtensionSettings() {
    const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
    const runtime = chromeApi?.runtime;
    const tabs = chromeApi?.tabs;

    if (tabs?.create && runtime?.getURL) {
      await tabs.create({ url: runtime.getURL("options.html") });
      return;
    }

    if (runtime?.openOptionsPage) {
      await runtime.openOptionsPage();
    }
  }

  async function handleLock() {
    setLocking(true);

    try {
      const nextSession = await client.lockSession();
      setSession(nextSession);
      setEntriesError(null);
      setDetailError(null);
      setUnlockError(null);
      setUnlockErrorCause(null);
      setPassword("");
      setKeyFilePath("");
    } finally {
      setLocking(false);
    }
  }

  async function handleSelectVault(vaultRefId: string) {
    const nextSession = await client.setCurrentVault(vaultRefId);
    setSession(nextSession);
    currentVaultPreload.current = null;
    if (nextSession.currentVaultRefId) {
      startCurrentVaultPreload();
    }
    setRecentVaults(await client.listRecentVaults());
    setPassword("");
    setKeyFilePath("");
    setUnlockError(null);
    setUnlockErrorCause(null);
  }

  const filteredEntries = searchValue.trim()
    ? entries.filter((entry) =>
        [entry.title, entry.username, entry.url].some((field) =>
          field.toLowerCase().includes(searchValue.trim().toLowerCase())
        )
      )
    : [];

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
    const text = (key: Parameters<typeof translate>[1]) =>
      translate(extensionSettings.language, key);
    const currentVault = currentVaultForSession();
    const needsRepair = currentVault?.availability === "needs_repair";
    const canUnlockCurrentVault = Boolean(currentVault || session.currentVaultRefId);
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
    const canQuickUnlock = canQuickUnlockVault(currentVault);

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
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void handleUnlock();
          }}
          style={{ display: "grid", gap: popupTheme.spacing.md }}
        >
          {recentVaults.length > 0 ? (
            <PopupVaultList
              recentVaults={recentVaults}
              currentVaultRefId={session.currentVaultRefId}
              onSelectVault={handleSelectVault}
              disabled={submitting}
            />
          ) : recentVaultsLoading ? (
            <div style={messagePanelStyle}>Loading...</div>
          ) : recentVaultsError ? (
            <div role="alert" style={messagePanelStyle}>
              {recentVaultsError}
            </div>
          ) : (
            <div style={messagePanelStyle}>
              {text("No recent vaults")}
            </div>
          )}
          {needsRepair ? (
            <div role="alert" style={messagePanelStyle}>
              {text("Needs repair in manager")}
            </div>
          ) : null}
          <label style={labelStyle}>
            {text("Master Password")}
            <input
              aria-label={text("Master Password")}
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  void handleUnlock();
                }
              }}
              disabled={submitting || !canUnlockCurrentVault || needsRepair}
              style={fieldStyle}
            />
          </label>
          <label style={labelStyle}>
            {text("Key File Path")}
            <input
              aria-label={text("Key File Path")}
              type="text"
              value={keyFilePath}
              onChange={(event) => setKeyFilePath(event.target.value)}
              disabled={submitting || !canUnlockCurrentVault || needsRepair}
              style={fieldStyle}
            />
          </label>
          <button
            type="submit"
            disabled={submitting || !canUnlockCurrentVault || needsRepair}
            style={primaryActionStyle}
          >
            {submitting ? text("Unlocking...") : text("Unlock Vault")}
          </button>
          {canQuickUnlock ? (
            <button
              type="button"
              onClick={() => {
                void handleQuickUnlock();
              }}
              disabled={submitting}
              style={primaryActionStyle}
            >
              {text("Unlock with Windows Hello")}
            </button>
          ) : null}
          <button
            type="button"
            onClick={handleOpenManager}
            disabled={submitting}
            style={secondaryActionStyle}
          >
            {text("Manage vaults")}
          </button>
          {unlockError ? <div role="alert">{unlockError}</div> : null}
          {unlockError && renderRuntimeErrorHelp
            ? renderRuntimeErrorHelp(unlockErrorCause)
            : null}
        </form>
      </div>
      </I18nProvider>
    );
  }

  if (webAuthnVerifyPrompt) {
    const currentVault = currentVaultForSession();
    const canQuickUnlock = canQuickUnlockVault(currentVault);
    const passkeyPromptTitle =
      extensionSettings.language === "zh-CN"
        ? "验证通行密钥请求"
        : "Verify passkey request";
    const passkeyPromptBody =
      siteLabel === "No active site"
        ? extensionSettings.language === "zh-CN"
          ? "请验证主密码以继续当前网站的通行密钥请求。"
          : "Verify your master password to continue this passkey request."
        : extensionSettings.language === "zh-CN"
          ? `请验证主密码以继续 ${siteLabel} 的通行密钥请求。`
          : `Verify your master password to continue the passkey request for ${siteLabel}.`;

    return (
      <I18nProvider language={extensionSettings.language}>
      <div style={shellStyle}>
        <PopupStatusStrip
          siteLabel={siteLabel}
          unlocked
          onLock={undefined}
          onOpenManager={undefined}
        />
        <section style={passkeyPromptStyle} aria-live="polite">
          <strong>{passkeyPromptTitle}</strong>
          <span>{passkeyPromptBody}</span>
        </section>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void handleWebAuthnUserVerification("master_password");
          }}
          style={{ display: "grid", gap: popupTheme.spacing.md }}
        >
          <label style={labelStyle}>
            {extensionSettings.language === "zh-CN" ? "主密码" : "Master Password"}
            <input
              aria-label={
                extensionSettings.language === "zh-CN" ? "主密码" : "Master Password"
              }
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={submitting}
              style={fieldStyle}
            />
          </label>
          <button type="submit" disabled={submitting} style={primaryActionStyle}>
            {submitting
              ? extensionSettings.language === "zh-CN"
                ? "验证中..."
                : "Verifying..."
              : extensionSettings.language === "zh-CN"
                ? "验证并继续"
                : "Verify and continue"}
          </button>
          {canQuickUnlock ? (
            <button
              type="button"
              onClick={() => {
                void handleWebAuthnUserVerification("quick_unlock");
              }}
              disabled={submitting}
              style={primaryActionStyle}
            >
              {extensionSettings.language === "zh-CN"
                ? "使用 Windows Hello 验证"
                : "Verify with Windows Hello"}
            </button>
          ) : null}
          {unlockError ? <div role="alert">{unlockError}</div> : null}
          {unlockError && renderRuntimeErrorHelp
            ? renderRuntimeErrorHelp(unlockErrorCause)
            : null}
        </form>
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
          onLock={undefined}
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
        onLock={locking ? undefined : handleLock}
        onOpenManager={handleOpenManager}
        onOpenExtensionSettings={handleOpenExtensionSettings}
      />
      {entriesError ? <div role="alert">{entriesError}</div> : null}
      <SiteCandidateList
        candidates={candidates}
        onFill={(entryId) => fillEntry(session.activeVaultId ?? "", entryId)}
        onSelectEntry={setSelectedEntryId}
      />
      <PopupSearch
        searchValue={searchValue}
        onSearchChange={setSearchValue}
        results={filteredEntries}
        selectedEntryId={selectedEntryId}
        onSelectEntry={setSelectedEntryId}
      />
      {detailError ? <div role="alert">{detailError}</div> : null}
      <PopupRecordCard
        detail={selectedDetail}
        clearClipboardSeconds={extensionSettings.clearClipboardSeconds}
        onFill={() =>
          selectedEntryId
            ? fillEntry(session.activeVaultId ?? "", selectedEntryId)
            : Promise.resolve()
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

const labelStyle = {
  display: "grid",
  gap: popupTheme.spacing.xs,
  fontFamily: popupTheme.font.body
};

const fieldStyle = {
  width: "100%",
  borderRadius: popupTheme.radius.field,
  border: `1px solid ${popupTheme.colors.line}`,
  padding: `${popupTheme.spacing.sm} ${popupTheme.spacing.md}`,
  background: popupTheme.colors.surface,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  boxSizing: "border-box" as const
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
