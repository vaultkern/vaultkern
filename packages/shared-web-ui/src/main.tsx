import { createRoot } from "react-dom/client";

import { App } from "./App";

const unsupportedClient = {
  async getSessionState() {
    return { unlocked: false, activeVaultId: null, currentVaultRefId: null };
  },
  async listRecentVaults() {
    return [];
  },
  async addLocalVaultReference() {
    throw new Error("unsupported in standalone demo");
  },
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
  async unlockCurrentVaultWithPassword() {
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
  async createEntry() {
    throw new Error("unsupported in standalone demo");
  },
  async updateEntryFields() {
    throw new Error("unsupported in standalone demo");
  },
  async deleteEntry() {
    throw new Error("unsupported in standalone demo");
  },
  async saveVault() {
    return { type: "save_vault_result" as const, status: "saved" as const };
  },
  async getEntryAttachmentContent() {
    throw new Error("unsupported in standalone demo");
  },
  async addEntryAttachment() {
    throw new Error("unsupported in standalone demo");
  },
  async updateEntryAttachmentMetadata() {
    throw new Error("unsupported in standalone demo");
  },
  async replaceEntryAttachmentContent() {
    throw new Error("unsupported in standalone demo");
  },
  async deleteEntryAttachment() {
    throw new Error("unsupported in standalone demo");
  },
  async listEntryHistory() {
    return [];
  },
  async getEntryHistoryDetail() {
    throw new Error("unsupported in standalone demo");
  }
};

const container = document.getElementById("root");

if (container) {
  createRoot(container).render(<App client={unsupportedClient} />);
}
