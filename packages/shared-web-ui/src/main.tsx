import { createRoot } from "react-dom/client";

import { App, type RuntimeClientLike } from "./App";

const unsupported = async () => {
  throw new Error("unsupported in standalone demo");
};

const unsupportedClient = {
  async getSessionState() {
    return { unlocked: false, activeVaultId: null, currentVaultRefId: null };
  },
  async listRecentVaults() {
    return [];
  },
  addLocalVaultReference: unsupported,
  beginOneDriveLogin: unsupported,
  completePendingOneDriveLogin: unsupported,
  async listOneDriveChildren() {
    return [];
  },
  addOneDriveVaultReference: unsupported,
  async setCurrentVault() {
    return { unlocked: false, activeVaultId: null, currentVaultRefId: null };
  },
  async retryVaultSourceSync() {
    return {
      type: "vault_source_status" as const,
      sourceKind: "local",
      remoteState: "unknown",
      lastSyncAt: null,
      cachedAt: null,
      lastError: null
    };
  },
  async deleteRecentVault() {
    return [];
  },
  async deleteRecentVaultIfNotCurrent() {
    return [];
  },
  openLocalVault: unsupported,
  async unlockCurrentVaultWithPassword() {
    return { unlocked: false, activeVaultId: null, currentVaultRefId: null };
  },
  async unlockCurrentVault() {
    return { unlocked: false, activeVaultId: null, currentVaultRefId: null };
  },
  async enableQuickUnlockForCurrentVault() {
    return { unlocked: false, activeVaultId: null, currentVaultRefId: null };
  },
  async unlockCurrentVaultWithQuickUnlock() {
    return { unlocked: false, activeVaultId: null, currentVaultRefId: null };
  },
  async disableQuickUnlockForCurrentVault() {
    return { unlocked: false, activeVaultId: null, currentVaultRefId: null };
  },
  unlockWithPassword: unsupported,
  unlockVault: unsupported,
  async lockSession() {
    return { unlocked: false, activeVaultId: null, currentVaultRefId: null };
  },
  async listGroups() {
    return {
      type: "group_tree" as const,
      root: {
        id: "root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    };
  },
  async listEntries() {
    return [];
  },
  async getEntryDetail() {
    return {
      type: "entry_detail" as const,
      id: "",
      title: "",
      username: "",
      password: "",
      url: "",
      notes: "",
      totp: null,
      totpUri: null
    };
  },
  createEntry: unsupported,
  updateEntryFields: unsupported,
  setEntryPasskey: unsupported,
  clearEntryPasskey: unsupported,
  deleteEntry: unsupported,
  getDatabaseSettings: unsupported,
  updateDatabaseSettings: unsupported,
  getEntryAttachmentContent: unsupported,
  addEntryAttachment: unsupported,
  updateEntryAttachmentMetadata: unsupported,
  replaceEntryAttachmentContent: unsupported,
  deleteEntryAttachment: unsupported,
  async listEntryHistory() {
    return [];
  },
  getEntryHistoryDetail: unsupported
} satisfies RuntimeClientLike;

const container = document.getElementById("root");

if (container) {
  createRoot(container).render(<App client={unsupportedClient} />);
}
