import { describe, expect, it, vi } from "vitest";
import {
  RuntimeClient,
  runtimeMutationOperationId,
  type PersistAutofillMutationRequest
} from "../index";

describe("RuntimeClient", () => {
  it("does not expose the superseded conditional create command", () => {
    const client = new RuntimeClient({ send: vi.fn() });

    expect("createEntryIfMatchingEntryIds" in client).toBe(false);
  });

  it("requests session state through the configured transport", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "session_state",
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: null,
        supportsBiometricUnlock: false
      })
    };

    const client = new RuntimeClient(transport);
    const session = await client.getSessionState();

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: { type: "get_session_state" }
    });
    expect(session.unlocked).toBe(false);
  });

  it("opens a local vault and returns the handle", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "vault_opened",
        vaultId: "vault-1",
        name: "Demo",
        path: "/tmp/demo.kdbx"
      })
    };

    const client = new RuntimeClient(transport);
    const handle = await client.openLocalVault("/tmp/demo.kdbx");

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: { type: "open_local_vault", path: "/tmp/demo.kdbx" }
    });
    expect(handle).toEqual({
      type: "vault_opened",
      vaultId: "vault-1",
      name: "Demo",
      path: "/tmp/demo.kdbx"
    });
  });

  it("lists recent vaults through the configured transport", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "vault_reference_list",
        vaults: [
          {
            vaultRefId: "vault-ref-1",
            displayName: "Demo Vault",
            sourceKind: "local",
            sourceSummary: "demo.kdbx",
            lastUsedAt: 1776500000,
            availability: "ready",
            supportsQuickUnlock: false,
            isCurrent: true
          }
        ]
      })
    };

    const client = new RuntimeClient(transport);
    const vaults = await client.listRecentVaults();

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: { type: "list_recent_vaults" }
    });
    expect(vaults[0]?.vaultRefId).toBe("vault-ref-1");
  });

  it("preloads the current vault through the configured transport", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "session_state",
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: false
      })
    };

    const client = new RuntimeClient(transport);
    const session = await client.preloadCurrentVault();

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: { type: "preload_current_vault" }
    });
    expect(session.currentVaultRefId).toBe("vault-ref-1");
  });

  it("requests local vault selection without exposing a UI path field", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "vault_reference",
        vaultRefId: "vault-ref-1",
        displayName: "Demo Vault",
        sourceKind: "local",
        sourceSummary: "demo.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      })
    };

    const client = new RuntimeClient(transport);
    await client.addLocalVaultReference();

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: { type: "add_local_vault_reference", path: undefined }
    });
  });

  it("requests OneDrive login and vault selection commands", async () => {
    const transport = {
      send: vi
        .fn()
        .mockResolvedValueOnce({
          type: "one_drive_auth_session",
          authUrl: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
          redirectUri: "http://127.0.0.1:53121/callback",
          expiresInSeconds: 600
        })
        .mockResolvedValueOnce({
          type: "one_drive_auth_status",
          status: "authorized",
          accountLabel: "alice@example.com"
        })
        .mockResolvedValueOnce({
          type: "one_drive_item_list",
          items: [
            {
              driveId: "drive-1",
              itemId: "item-1",
              name: "Vault.kdbx",
              folder: false,
              size: 42
            }
          ]
        })
        .mockResolvedValueOnce({
          type: "vault_reference",
          vaultRefId: "onedrive-item-1",
          displayName: "Vault",
          sourceKind: "onedrive",
          sourceSummary: "alice@example.com / Vault.kdbx",
          lastUsedAt: 1776500000,
          availability: "ready",
          supportsQuickUnlock: false,
          isCurrent: true
        })
    };

    const client = new RuntimeClient(transport);

    await expect(client.beginOneDriveLogin()).resolves.toMatchObject({
      type: "one_drive_auth_session"
    });
    await expect(client.completePendingOneDriveLogin()).resolves.toMatchObject({
      status: "authorized"
    });
    await expect(client.listOneDriveChildren("folder-1")).resolves.toHaveLength(1);
    await expect(
      client.addOneDriveVaultReference("drive-1", "item-1")
    ).resolves.toMatchObject({ sourceKind: "onedrive" });

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      command: { type: "begin_one_drive_login" }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      command: { type: "complete_pending_one_drive_login" }
    });
    expect(transport.send).toHaveBeenNthCalledWith(3, {
      version: 2,
      command: { type: "list_one_drive_children", parent_item_id: "folder-1" }
    });
    expect(transport.send).toHaveBeenNthCalledWith(4, {
      version: 2,
      command: {
        type: "add_one_drive_vault_reference",
        drive_id: "drive-1",
        item_id: "item-1"
      }
    });
  });

  it("unlocks with password and returns the session state", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      })
    };

    const client = new RuntimeClient(transport);
    const session = await client.unlockWithPassword("vault-1", "demo-password");

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "unlock_with_password",
        vault_id: "vault-1",
        password: "demo-password"
      }
    });
    expect(session.activeVaultId).toBe("vault-1");
  });

  it("unlocks selected and current vaults with key file paths", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      })
    };

    const client = new RuntimeClient(transport);
    await client.unlockVault("vault-1", {
      password: "",
      keyFilePath: "/tmp/demo.keyx"
    });
    await client.unlockCurrentVault({
      password: "demo-password",
      keyFilePath: "/tmp/demo.keyx"
    });

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      command: {
        type: "unlock_vault",
        vault_id: "vault-1",
        password: null,
        key_file_path: "/tmp/demo.keyx"
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      command: {
        type: "unlock_current_vault",
        password: "demo-password",
        key_file_path: "/tmp/demo.keyx"
      }
    });
  });

  it("sends quick unlock commands for the current vault", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      })
    };

    const client = new RuntimeClient(transport);
    await client.enableQuickUnlockForCurrentVault({
      password: "demo-password",
      keyFilePath: "/tmp/demo.keyx"
    });
    await client.unlockCurrentVaultWithQuickUnlock();
    await client.disableQuickUnlockForCurrentVault();

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      command: {
        type: "enable_quick_unlock_for_current_vault",
        password: "demo-password",
        key_file_path: "/tmp/demo.keyx"
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      command: { type: "unlock_current_vault_with_quick_unlock" }
    });
    expect(transport.send).toHaveBeenNthCalledWith(3, {
      version: 2,
      command: { type: "disable_quick_unlock_for_current_vault" }
    });
  });

  it("locks the active session and returns the locked session state", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "session_state",
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      })
    };

    const client = new RuntimeClient(transport);
    const session = await client.lockSession();

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: { type: "lock_session" }
    });
    expect(session.unlocked).toBe(false);
    expect(session.activeVaultId).toBeNull();
  });

  it("records foreground user activity without changing session state", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      })
    };

    const client = new RuntimeClient(transport);
    const session = await client.recordUserActivity();

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: { type: "record_user_activity" }
    });
    expect(session.unlocked).toBe(true);
  });

  it("sets the current vault and unlocks it by current selection", async () => {
    const transport = {
      send: vi
        .fn()
        .mockResolvedValueOnce({
          type: "session_state",
          unlocked: false,
          activeVaultId: null,
          currentVaultRefId: "vault-ref-2",
          supportsBiometricUnlock: false
        })
        .mockResolvedValueOnce({
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-ref-2",
          currentVaultRefId: "vault-ref-2",
          supportsBiometricUnlock: false
        })
    };

    const client = new RuntimeClient(transport);
    await client.setCurrentVault("vault-ref-2");
    await client.unlockCurrentVaultWithPassword("demo-password");

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      command: { type: "set_current_vault", vault_ref_id: "vault-ref-2" }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      command: {
        type: "unlock_current_vault_with_password",
        password: "demo-password"
      }
    });
  });

  it("deletes a recent vault record through the command envelope", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "vault_reference_list",
        vaults: []
      })
    };

    const client = new RuntimeClient(transport);
    const vaults = await client.deleteRecentVault("vault-ref-1");

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "delete_vault_reference",
        vault_ref_id: "vault-ref-1"
      }
    });
    expect(vaults).toEqual([]);
  });

  it("requests an atomic non-current guard when trimming a recent vault", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "vault_reference_list",
        vaults: []
      })
    };

    const client = new RuntimeClient(transport);
    const vaults = await client.deleteRecentVaultIfNotCurrent("vault-ref-1");

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "delete_vault_reference_if_not_current",
        vault_ref_id: "vault-ref-1"
      }
    });
    expect(vaults).toEqual([]);
  });

  it("requests entry detail through the configured transport", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "entry_detail",
        id: "entry-1",
        title: "Email",
        username: "user@example.com",
        password: "secret",
        url: "https://example.com",
        notes: "demo",
        totp: "123456",
        totpUri:
          "otpauth://totp/Test:user@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test"
      })
    };

    const client = new RuntimeClient(transport);
    const detail = await client.getEntryDetail("vault-1", "entry-1");

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "get_entry_detail",
        vault_id: "vault-1",
        entry_id: "entry-1"
      }
    });
    expect(detail.password).toBe("secret");
    expect(detail.totp).toBe("123456");
    expect(detail.totpUri).toBe(
      "otpauth://totp/Test:user@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test"
    );
  });

  it("requests only an origin-scoped autofill credential for browser filling", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "autofill_credential",
        id: "entry-1",
        username: "user@example.com",
        password: "secret",
        totp: "123456"
      })
    };

    const client = new RuntimeClient(transport);
    const credential = await client.getAutofillCredential(
      "vault-1",
      "entry-1",
      "https://example.com/login"
    );

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "get_autofill_credential",
        vault_id: "vault-1",
        entry_id: "entry-1",
        url: "https://example.com/login"
      }
    });
    expect(credential).toEqual({
      type: "autofill_credential",
      id: "entry-1",
      username: "user@example.com",
      password: "secret",
      totp: "123456"
    });
  });

  it("requests candidate-scoped fields and the root create context for login saving", async () => {
    const transport = {
      send: vi
        .fn()
        .mockResolvedValueOnce({
          type: "autofill_entry_fields",
          id: "entry-1",
          fields: {
            title: "Example",
            username: "alice",
            password: "old-secret",
            url: "https://example.com/login",
            notes: "kept",
            totpUri: null,
            customFields: []
          }
        })
        .mockResolvedValueOnce({
          type: "autofill_create_context",
          rootGroupId: "group-root"
        })
    };
    const client = new RuntimeClient(transport);

    await client.getAutofillEntryFields(
      "vault-1",
      "entry-1",
      "https://example.com/login"
    );
    await client.getAutofillCreateContext("vault-1");

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      command: {
        type: "get_autofill_entry_fields",
        vault_id: "vault-1",
        entry_id: "entry-1",
        url: "https://example.com/login"
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      command: {
        type: "get_autofill_create_context",
        vault_id: "vault-1"
      }
    });
  });

  it("requests resident app activation with a fixed route", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({ type: "resident_app_activated" })
    };

    const client = new RuntimeClient(transport);
    await client.activateResidentApp("settings");

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "activate_resident_app",
        route: "settings"
      }
    });
  });

  it("reads browser integration desired state from the resident app", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "browser_integration_settings",
        language: "zh-CN",
        autofillOnPageLoadEnabled: true,
        browserPasskeyProxyEnabled: true
      })
    };

    const client = new RuntimeClient(transport);
    await expect(client.getBrowserIntegrationSettings()).resolves.toMatchObject({
      language: "zh-CN",
      autofillOnPageLoadEnabled: true,
      browserPasskeyProxyEnabled: true
    });
    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: { type: "get_browser_integration_settings" }
    });
  });

  it("requests the group tree through the configured transport", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "group_tree",
        root: {
          id: "group-root",
          title: "Archive",
          entryCount: 0,
          childCount: 1,
          children: [
            {
              id: "group-child",
              title: "General",
              entryCount: 1,
              childCount: 0,
              children: []
            }
          ]
        }
      })
    };

    const client = new RuntimeClient(transport);
    const groups = await client.listGroups("vault-1");

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "list_groups",
        vault_id: "vault-1"
      }
    });
    expect(groups.root.children[0]?.title).toBe("General");
  });

  it("returns fill candidates as entry summaries", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "fill_candidates",
        entries: [
          {
            id: "entry-1",
            title: "Email",
            username: "user@example.com",
            url: "https://example.com",
            groupId: "group-1"
          }
        ]
      })
    };

    const client = new RuntimeClient(transport);
    const entries = await client.findFillCandidates(
      "vault-1",
      "https://example.com/login"
    );

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "find_fill_candidates",
        vault_id: "vault-1",
        url: "https://example.com/login"
      }
    });
    expect(entries).toEqual([
      {
        id: "entry-1",
        title: "Email",
        username: "user@example.com",
        url: "https://example.com",
        groupId: "group-1"
      }
    ]);
  });

  it("serializes listEntries through the command envelope", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "entry_list",
        entries: [
          {
            id: "entry-1",
            title: "Email",
            username: "user@example.com",
            url: "https://example.com",
            groupId: "group-root"
          }
        ]
      })
    };

    const client = new RuntimeClient(transport);
    const entries = await client.listEntries("vault-1");

    expect(transport.send).toHaveBeenCalledTimes(1);
    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: { type: "list_entries", vault_id: "vault-1" }
    });
    expect(entries).toEqual([
      {
        id: "entry-1",
        title: "Email",
        username: "user@example.com",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]);
  });

  it("creates an entry through the command envelope", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "entry_detail",
        id: "entry-1",
        title: "Example",
        username: "alice",
        password: "secret",
        url: "https://example.com",
        notes: "demo",
        totp: "287082"
      })
    };

    const client = new RuntimeClient(transport);
    await client.createEntry("vault-1", {
      parentGroupId: "group-root",
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: "demo",
      customFields: [],
      totpUri:
        "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test"
    });

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "create_entry",
        vault_id: "vault-1",
        parent_group_id: "group-root",
        entry_id: expect.any(String),
        title: "Example",
        username: "alice",
        password: "secret",
        url: "https://example.com",
        notes: "demo",
        totp_uri:
          "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test"
      }
    });
  });

  it("replays an ambiguous mutation once with the same operation and planned entry ids", async () => {
    const disconnect = Object.assign(new Error("native port disconnected"), {
      code: "native_port_disconnected"
    });
    const transport = {
      send: vi
        .fn()
        .mockRejectedValueOnce(disconnect)
        .mockResolvedValueOnce({ type: "entry_detail", id: "entry-1" })
        .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
    };

    const client = new RuntimeClient(transport);
    await client.createEntry("vault-1", {
      parentGroupId: "group-root",
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: "",
      customFields: [],
      totpUri: null
    });

    expect(transport.send).toHaveBeenCalledTimes(3);
    const first = transport.send.mock.calls[0]?.[0];
    const second = transport.send.mock.calls[1]?.[0];
    expect(second).toEqual(first);
    expect(first).toMatchObject({
      operationId: expect.any(String),
      command: {
        type: "create_entry",
        entry_id: expect.any(String)
      }
    });
    expect(first.command.entry_id).toBe(first.operationId);
    expect(transport.send.mock.calls[2]?.[0]).toEqual({
      version: 2,
      operationId: first.operationId,
      command: { type: "save_vault", vault_id: "vault-1" }
    });
  });

  it("keeps the mutation outcome unknown when an ambiguous attempt is followed by a business error", async () => {
    const disconnect = Object.assign(new Error("native port disconnected"), {
      code: "native_port_disconnected"
    });
    const transport = {
      send: vi
        .fn()
        .mockRejectedValueOnce(disconnect)
        .mockResolvedValueOnce({
          type: "error",
          code: "runtime_error",
          message: "entry not found"
        })
    };
    const client = new RuntimeClient(transport);

    let failure: unknown;
    try {
      await client.deleteEntry(
        "vault-1",
        "12345678-1234-4abc-8def-1234567890ab"
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toMatchObject({
      name: "RuntimeMutationOutcomeUnknownError",
      code: "request_outcome_unknown",
      message: expect.stringContaining("outcome is unknown")
    });
    expect(runtimeMutationOperationId(failure)).toEqual(expect.any(String));
    expect(transport.send).toHaveBeenCalledTimes(2);
    expect(transport.send.mock.calls[1]?.[0]).toEqual(
      transport.send.mock.calls[0]?.[0]
    );
  });

  it("returns the save receipt bound to the exact mutation instead of a vault-wide queue", async () => {
    const mutationResults = [
      { type: "entry_detail", id: "entry-a" },
      { type: "entry_detail", id: "entry-b" }
    ];
    const saveResults = [
      { type: "save_vault_result", status: "saved" },
      { type: "save_vault_result", status: "merged" }
    ];
    const transport = {
      send: vi.fn(async (request: { operationId?: string; command: { type: string } }) => {
        if (request.command.type === "save_vault") {
          return saveResults.shift();
        }
        return mutationResults.shift();
      })
    };
    const client = new RuntimeClient(transport);
    const input = {
      parentGroupId: "group-root",
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: "",
      customFields: [],
      totpUri: null
    };

    const first = await client.createEntry("vault-1", input);
    const second = await client.createEntry("vault-1", input);

    expect(first.saveResult.status).toBe("saved");
    expect(second.saveResult.status).toBe("merged");
    expect(transport.send).toHaveBeenCalledTimes(4);
    for (const index of [0, 2]) {
      const mutation = transport.send.mock.calls[index]?.[0];
      const save = transport.send.mock.calls[index + 1]?.[0];
      expect(save.operationId).toBe(mutation.operationId);
      expect(save.command).toEqual({ type: "save_vault", vault_id: "vault-1" });
    }
  });

  it("lets the caller keep one logical create id across repeated ambiguous transports", async () => {
    const timeout = Object.assign(new Error("native request timed out"), {
      code: "native_timeout"
    });
    const transport = {
      send: vi
        .fn()
        .mockRejectedValueOnce(timeout)
        .mockRejectedValueOnce(timeout)
        .mockResolvedValueOnce({ type: "entry_detail", id: "entry-replayed" })
        .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
    };
    const input = {
      parentGroupId: "group-root",
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: "",
      customFields: [],
      totpUri: null
    };
    const client = new RuntimeClient(transport);

    let operationId: string | null = null;
    try {
      await client.createEntry("vault-1", input);
    } catch (error) {
      operationId = runtimeMutationOperationId(error);
    }
    expect(operationId).toEqual(expect.any(String));

    await client.createEntry("vault-1", input, operationId!);

    const messages = transport.send.mock.calls.map(([message]) => message);
    expect(messages).toHaveLength(4);
    expect(new Set(messages.map((message) => message.operationId))).toEqual(
      new Set([operationId])
    );
    expect(
      new Set(
        messages
          .filter((message) => message.command.type === "create_entry")
          .map((message) => message.command.entry_id)
      )
    ).toEqual(new Set([operationId]));
    expect(messages[3]?.command).toEqual({
      type: "save_vault",
      vault_id: "vault-1"
    });
  });

  it("updates and deletes entries through dedicated helpers", async () => {
    const transport = {
      send: vi
        .fn()
        .mockResolvedValueOnce({
          type: "entry_detail",
          id: "entry-1",
          title: "Example 2",
          username: "alice",
          password: "secret-2",
          url: "https://example.com/app",
          notes: "updated",
          totp: null,
          customFields: [
            {
              key: "RecoveryCode",
              value: "edited-code",
              protected: true
            }
          ]
        })
        .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
        .mockResolvedValueOnce({ type: "saved" })
        .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
    };

    const client = new RuntimeClient(transport);
    await client.updateEntryFields("vault-1", "entry-1", {
      title: "Example 2",
      username: "alice",
      password: "secret-2",
      url: "https://example.com/app",
      notes: "updated",
      totpUri: null,
      customFields: [
        {
          key: "RecoveryCode",
          value: "edited-code",
          protected: true
        }
      ]
    });
    await client.deleteEntry("vault-1", "entry-1");

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "update_entry_fields",
        vault_id: "vault-1",
        entry_id: "entry-1",
        title: "Example 2",
        username: "alice",
        password: "secret-2",
        url: "https://example.com/app",
        notes: "updated",
        totp_uri: null,
        custom_fields: [
          {
            key: "RecoveryCode",
            value: "edited-code",
            protected: true
          }
        ]
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      operationId: expect.any(String),
      command: { type: "save_vault", vault_id: "vault-1" }
    });
    expect(transport.send).toHaveBeenNthCalledWith(3, {
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "delete_entry",
        vault_id: "vault-1",
        entry_id: "entry-1"
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(4, {
      version: 2,
      operationId: expect.any(String),
      command: { type: "save_vault", vault_id: "vault-1" }
    });
  });

  it("sends the atomic autofill update precondition and matching lookup", async () => {
    const transport = {
      send: vi
        .fn()
        .mockResolvedValueOnce({ type: "entry_detail", id: "entry-1" })
        .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
        .mockResolvedValueOnce({
          type: "entry_id_list",
          entryIds: ["entry-existing"]
        })
    };
    const client = new RuntimeClient(transport);
    const expectedFields = {
      title: "Example",
      username: "alice",
      password: "old-secret",
      url: "https://example.com/login",
      notes: "",
      totpUri: null,
      customFields: []
    };
    const desiredFields = { ...expectedFields, password: "new-secret" };

    await client.compareAndUpdateEntryFields(
      "vault-1",
      "entry-1",
      expectedFields,
      desiredFields
    );
    await expect(
      client.findExactMatchingEntryIds("vault-1", desiredFields)
    ).resolves.toEqual(["entry-existing"]);

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "compare_and_update_entry_fields",
        vault_id: "vault-1",
        entry_id: "entry-1",
        expected_fields: {
          title: "Example",
          username: "alice",
          password: "old-secret",
          url: "https://example.com/login",
          notes: "",
          totpUri: null,
          customFields: []
        },
        desired_fields: {
          title: "Example",
          username: "alice",
          password: "new-secret",
          url: "https://example.com/login",
          notes: "",
          totpUri: null,
          customFields: []
        }
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      operationId: expect.any(String),
      command: { type: "save_vault", vault_id: "vault-1" }
    });
    expect(transport.send).toHaveBeenNthCalledWith(3, {
      version: 2,
      command: {
        type: "find_exact_matching_entry_ids",
        vault_id: "vault-1",
        fields: {
          title: "Example",
          username: "alice",
          password: "new-secret",
          url: "https://example.com/login",
          notes: "",
          totpUri: null,
          customFields: []
        }
      }
    });
  });

  it("sends one atomic autofill persist envelope and validates its durable binding", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "autofill_persist_result",
        transactionId: "transaction-1",
        operationId: "operation-1",
        vaultId: "vault-1",
        outcome: "durable",
        disposition: "committed",
        entryId: "entry-1",
        durability: "source",
        cacheState: "current",
        committedFingerprint: {
          contentSha256:
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          sizeBytes: 4096
        },
        mergeSummary: {
          mergedEntries: 2,
          historySnapshotsAdded: 1
        },
        receiptVersion: 1
      })
    };
    const client = new RuntimeClient(transport);
    const expectedFields = {
      username: "alice",
      password: "old-secret",
      url: "https://example.com/login"
    };

    await expect(
      client.persistAutofillMutation({
        transactionId: "transaction-1",
        operationId: "operation-1",
        vaultId: "vault-1",
        plan: {
          mode: "update",
          entryId: "entry-1",
          expectedFields,
          desiredFields: { ...expectedFields, password: "new-secret" }
        }
      })
    ).resolves.toMatchObject({
      outcome: "durable",
      entryId: "entry-1",
      durability: "source"
    });

    expect(transport.send).toHaveBeenCalledTimes(1);
    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "persist_autofill_mutation",
        transaction_id: "transaction-1",
        operation_id: "operation-1",
        vault_id: "vault-1",
        plan: {
          mode: "update",
          entry_id: "entry-1",
          expected_fields: {
            username: "alice",
            password: "old-secret",
            url: "https://example.com/login"
          },
          desired_fields: {
            username: "alice",
            password: "new-secret",
            url: "https://example.com/login"
          }
        }
      }
    });
  });

  it("sends a preplanned UUID and exact matching baseline for atomic create", async () => {
    const plannedEntryId = "12345678-1234-4abc-8def-1234567890ab";
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "autofill_persist_result",
        transactionId: "transaction-2",
        operationId: "operation-2",
        vaultId: "vault-1",
        outcome: "durable",
        disposition: "replayed",
        entryId: plannedEntryId,
        durability: "pending_remote_cache",
        cacheState: "pending_sync",
        committedFingerprint: {
          contentSha256:
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
          sizeBytes: 2048
        },
        mergeSummary: null,
        receiptVersion: 1
      })
    };
    const client = new RuntimeClient(transport);
    const desiredFields = {
      title: "Example",
      username: "alice",
      password: "new-secret",
      url: "https://example.com/login",
      notes: "",
      totpUri: null,
      customFields: []
    };

    await expect(
      client.persistAutofillMutation({
        transactionId: "transaction-2",
        operationId: "operation-2",
        vaultId: "vault-1",
        plan: {
          mode: "create",
          parentGroupId: "group-root",
          plannedEntryId,
          expectedMatchingEntryIds: ["entry-a", "entry-b"],
          desiredFields
        }
      })
    ).resolves.toMatchObject({ disposition: "replayed", entryId: plannedEntryId });

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "persist_autofill_mutation",
        transaction_id: "transaction-2",
        operation_id: "operation-2",
        vault_id: "vault-1",
        plan: {
          mode: "create",
          parent_group_id: "group-root",
          planned_entry_id: plannedEntryId,
          expected_matching_entry_ids: ["entry-a", "entry-b"],
          desired_fields: {
            title: "Example",
            username: "alice",
            password: "new-secret",
            url: "https://example.com/login",
            notes: "",
            totpUri: null,
            customFields: []
          }
        }
      }
    });
  });

  it("rejects nil and noncanonical planned entry UUIDs before transport", async () => {
    const send = vi.fn().mockResolvedValue({
      type: "autofill_persist_result",
      transactionId: "transaction-2",
      operationId: "operation-2",
      vaultId: "vault-1",
      outcome: "conflict",
      code: "create_matching_set_changed",
      retryable: false
    });
    const client = new RuntimeClient({ send });
    const desiredFields = {
      title: "Example",
      username: "alice",
      password: "new-secret",
      url: "https://example.com/login",
      notes: "",
      totpUri: null,
      customFields: []
    };

    for (const plannedEntryId of [
      "00000000-0000-0000-0000-000000000000",
      "12345678-1234-4ABC-8DEF-1234567890AB",
      "1234567812344abc8def1234567890ab"
    ]) {
      await expect(
        client.persistAutofillMutation({
          transactionId: "transaction-2",
          operationId: "operation-2",
          vaultId: "vault-1",
          plan: {
            mode: "create",
            parentGroupId: "group-root",
            plannedEntryId,
            expectedMatchingEntryIds: [],
            desiredFields
          }
        })
      ).rejects.toThrow(/canonical|uuid/i);
    }

    expect(send).not.toHaveBeenCalled();
  });

  it("validates a delayed response against the immutable sent identity and mode", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const transport = {
      send: vi.fn(async () => {
        await gate;
        return {
          type: "autofill_persist_result",
          transactionId: "transaction-original",
          operationId: "operation-original",
          vaultId: "vault-original",
          outcome: "conflict",
          code: "create_matching_set_changed",
          retryable: false
        };
      })
    };
    const fields = {
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com/login",
      notes: "",
      totpUri: null,
      customFields: []
    };
    const request: PersistAutofillMutationRequest = {
      transactionId: "transaction-original",
      operationId: "operation-original",
      vaultId: "vault-original",
      plan: {
        mode: "create",
        parentGroupId: "group-root",
        plannedEntryId: "12345678-1234-4abc-8def-1234567890ab",
        expectedMatchingEntryIds: [],
        desiredFields: fields
      }
    };
    const pending = new RuntimeClient(transport).persistAutofillMutation(request);

    request.transactionId = "transaction-mutated";
    request.operationId = "operation-mutated";
    request.vaultId = "vault-mutated";
    request.plan = {
      mode: "update",
      entryId: "entry-mutated",
      expectedFields: fields,
      desiredFields: fields
    };
    release();

    await expect(pending).resolves.toMatchObject({
      transactionId: "transaction-original",
      operationId: "operation-original",
      vaultId: "vault-original",
      code: "create_matching_set_changed"
    });
  });

  it("deeply snapshots the command plan before deferred transport serialization", async () => {
    let release!: () => void;
    let observedMessage: unknown;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const transport = {
      send: vi.fn(async (message: unknown) => {
        await gate;
        observedMessage = structuredClone(message);
        return {
          type: "autofill_persist_result",
          transactionId: "transaction-2",
          operationId: "operation-2",
          vaultId: "vault-1",
          outcome: "conflict",
          code: "create_matching_set_changed",
          retryable: false
        };
      })
    };
    const request: PersistAutofillMutationRequest = {
      transactionId: "transaction-2",
      operationId: "operation-2",
      vaultId: "vault-1",
      plan: {
        mode: "create",
        parentGroupId: "group-root",
        plannedEntryId: "12345678-1234-4abc-8def-1234567890ab",
        expectedMatchingEntryIds: ["entry-existing"],
        desiredFields: {
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com/login",
          notes: "",
          totpUri: null,
          customFields: [
            { key: "Tenant", value: "original", protected: false }
          ]
        }
      }
    };
    if (request.plan.mode !== "create") {
      throw new Error("expected create plan fixture");
    }
    const plan = request.plan;
    const pending = new RuntimeClient(transport).persistAutofillMutation(request);

    plan.expectedMatchingEntryIds.push("entry-late");
    plan.desiredFields.customFields[0]!.value = "mutated";
    plan.desiredFields.customFields.push({
      key: "Late",
      value: "added",
      protected: true
    });
    release();
    await pending;

    expect(observedMessage).toMatchObject({
      command: {
        plan: {
          expected_matching_entry_ids: ["entry-existing"],
          desired_fields: {
            customFields: [
              { key: "Tenant", value: "original", protected: false }
            ]
          }
        }
      }
    });
  });

  it("rejects malformed, mismatched, legacy, and impossible atomic persist results", async () => {
    const request = {
      transactionId: "transaction-1",
      operationId: "operation-1",
      vaultId: "vault-1",
      plan: {
        mode: "update" as const,
        entryId: "entry-1",
        expectedFields: {
          title: "Example",
          username: "alice",
          password: "old-secret",
          url: "https://example.com/login",
          notes: "",
          totpUri: null,
          customFields: []
        },
        desiredFields: {
          title: "Example",
          username: "alice",
          password: "new-secret",
          url: "https://example.com/login",
          notes: "",
          totpUri: null,
          customFields: []
        }
      }
    };
    const valid = {
      type: "autofill_persist_result",
      transactionId: "transaction-1",
      operationId: "operation-1",
      vaultId: "vault-1",
      outcome: "durable",
      disposition: "committed",
      entryId: "entry-1",
      durability: "source",
      cacheState: "current",
      committedFingerprint: {
        contentSha256:
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        sizeBytes: 4096
      },
      mergeSummary: null,
      receiptVersion: 1
    };
    const { operationId: _operationId, ...missingOperationId } = valid;
    const { entryId: _entryId, ...missingEntryId } = valid;
    const invalidResponses = [
      missingOperationId,
      missingEntryId,
      { ...valid, transactionId: "transaction-other" },
      { ...valid, operationId: "operation-other" },
      { ...valid, vaultId: "vault-other" },
      { ...valid, entryId: "entry-other" },
      { ...valid, durability: "pending_remote_cache", cacheState: "current" },
      { ...valid, durability: "source", cacheState: "pending_sync" },
      {
        ...valid,
        committedFingerprint: { contentSha256: "not-a-sha", sizeBytes: -1 }
      },
      { ...valid, receiptVersion: 2 },
      { type: "save_vault_result", status: "saved" },
      { ...valid, outcome: "eventually_durable" }
    ];

    for (const response of invalidResponses) {
      const client = new RuntimeClient({ send: vi.fn().mockResolvedValue(response) });
      await expect(client.persistAutofillMutation(request)).rejects.toThrow();
    }
  });

  it("accepts only plan-compatible atomic persist conflicts with fixed retryability", async () => {
    const fields = {
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com/login",
      notes: "",
      totpUri: null,
      customFields: []
    };
    const updateRequest = {
      transactionId: "transaction-1",
      operationId: "operation-1",
      vaultId: "vault-1",
      plan: {
        mode: "update" as const,
        entryId: "entry-1",
        expectedFields: fields,
        desiredFields: fields
      }
    };
    const createRequest = {
      transactionId: "transaction-1",
      operationId: "operation-1",
      vaultId: "vault-1",
      plan: {
        mode: "create" as const,
        parentGroupId: "group-root",
        plannedEntryId: "12345678-1234-4abc-8def-1234567890ab",
        expectedMatchingEntryIds: ["entry-existing"],
        desiredFields: fields
      }
    };
    const response = (code: string, retryable: boolean) => ({
      type: "autofill_persist_result",
      transactionId: "transaction-1",
      operationId: "operation-1",
      vaultId: "vault-1",
      outcome: "conflict",
      code,
      retryable
    });
    const validCases = [
      [updateRequest, "active_vault_mismatch", true],
      [updateRequest, "update_precondition_failed", false],
      [updateRequest, "operation_binding_mismatch", false],
      [updateRequest, "concurrent_vault_changes", false],
      [updateRequest, "source_changed_retry_exhausted", true],
      [createRequest, "active_vault_mismatch", true],
      [createRequest, "create_matching_set_changed", false],
      [createRequest, "planned_entry_id_collision", false],
      [createRequest, "operation_binding_mismatch", false],
      [createRequest, "concurrent_vault_changes", false],
      [createRequest, "source_changed_retry_exhausted", true],
      [createRequest, "legacy_create_outcome_ambiguous", false]
    ] as const;

    for (const [request, code, retryable] of validCases) {
      const client = new RuntimeClient({
        send: vi.fn().mockResolvedValue(response(code, retryable))
      });
      await expect(client.persistAutofillMutation(request)).resolves.toEqual(
        response(code, retryable)
      );
    }

    const invalidCases = [
      [updateRequest, "create_matching_set_changed", false],
      [updateRequest, "planned_entry_id_collision", false],
      [updateRequest, "legacy_create_outcome_ambiguous", false],
      [createRequest, "update_precondition_failed", false],
      [updateRequest, "active_vault_mismatch", false],
      [updateRequest, "source_changed_retry_exhausted", false],
      [updateRequest, "concurrent_vault_changes", true],
      [updateRequest, "update_precondition_failed", true],
      [updateRequest, "overwrite_anyway", true]
    ] as const;
    for (const [request, code, retryable] of invalidCases) {
      const client = new RuntimeClient({
        send: vi.fn().mockResolvedValue(response(code, retryable))
      });
      await expect(client.persistAutofillMutation(request)).rejects.toThrow();
    }
  });

  it("sets and clears entry passkeys through dedicated helpers", async () => {
    const passkey = {
      username: "alice@example.com",
      credentialId: "credential-base64url",
      generatedUserId: "generated-user",
      relyingParty: "example.com",
      userHandle: "user-handle",
      backupEligible: true,
      backupState: false
    };
    const transport = {
      send: vi
        .fn()
        .mockResolvedValueOnce({
          type: "entry_detail",
          id: "entry-1",
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com",
          notes: "demo",
          totp: null,
          passkey
        })
        .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
        .mockResolvedValueOnce({
          type: "entry_detail",
          id: "entry-1",
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com",
          notes: "demo",
          totp: null,
          passkey: null
        })
        .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
    };

    const client = new RuntimeClient(transport);
    await client.setEntryPasskey("vault-1", "entry-1", passkey);
    await client.clearEntryPasskey("vault-1", "entry-1");

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "set_entry_passkey",
        vault_id: "vault-1",
        entry_id: "entry-1",
        passkey
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      operationId: expect.any(String),
      command: { type: "save_vault", vault_id: "vault-1" }
    });
    expect(transport.send).toHaveBeenNthCalledWith(3, {
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "clear_entry_passkey",
        vault_id: "vault-1",
        entry_id: "entry-1"
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(4, {
      version: 2,
      operationId: expect.any(String),
      command: { type: "save_vault", vault_id: "vault-1" }
    });
  });

  it("saves a vault and returns the save status", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "save_vault_result",
        status: "merged",
        mergeSummary: {
          mergedEntries: 1,
          historySnapshotsAdded: 1
        }
      })
    };

    const client = new RuntimeClient(transport);
    await expect(client.saveVault("vault-1")).resolves.toEqual({
      type: "save_vault_result",
      status: "merged",
      mergeSummary: {
        mergedEntries: 1,
        historySnapshotsAdded: 1
      }
    });

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "save_vault",
        vault_id: "vault-1"
      }
    });
  });

  it("correlates a mutation with only its own follow-up save", async () => {
    const messages: Array<Record<string, unknown>> = [];
    const transport = {
      send: vi.fn(async (message: unknown) => {
        messages.push(message as Record<string, unknown>);
        return messages.length === 1
          ? {
              type: "entry_detail",
              id: "entry-1",
              title: "Example",
              username: "alice",
              password: "secret",
              url: "https://example.com",
              notes: "",
              totp: null,
              customFields: []
            }
          : {
              type: "save_vault_result",
              status: "saved",
              mergeSummary: null
            };
      })
    };
    const client = new RuntimeClient(transport);

    await client.updateEntryFields("vault-1", "entry-1", {
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: "",
      totpUri: null,
      customFields: []
    });
    await client.saveVault("vault-1");

    expect(messages[0]?.operationId).toEqual(expect.any(String));
    expect(messages[1]?.operationId).toBe(messages[0]?.operationId);
  });

  it("retries an ambiguous mutation save inline with the same operation id", async () => {
    const timeout = Object.assign(new Error("native request timed out"), {
      code: "native_timeout"
    });
    const transport = {
      send: vi
        .fn()
        .mockResolvedValueOnce({ type: "entry_detail", id: "entry-1" })
        .mockRejectedValueOnce(timeout)
        .mockResolvedValueOnce({
          type: "save_vault_result",
          status: "conflict_copy",
          conflictCopyPath: "vault.conflict.kdbx"
        })
    };
    const client = new RuntimeClient(transport);

    await expect(client.updateEntryFields("vault-1", "entry-1", {
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: "",
      totpUri: null,
      customFields: []
    })).resolves.toMatchObject({
      value: { id: "entry-1" },
      saveResult: {
      status: "conflict_copy"
      }
    });

    const mutationId = transport.send.mock.calls[0]?.[0].operationId;
    expect(transport.send.mock.calls[1]?.[0].operationId).toBe(mutationId);
    expect(transport.send.mock.calls[2]?.[0].operationId).toBe(mutationId);
  });

  it("returns local cache save status", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "save_vault_result",
        status: "saved_to_cache",
        mergeSummary: null
      })
    };

    const client = new RuntimeClient(transport);
    await expect(client.saveVault("vault-1")).resolves.toEqual({
      type: "save_vault_result",
      status: "saved_to_cache",
      mergeSummary: null
    });
  });

  it("retries remote vault source sync through the command envelope", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "vault_source_status",
        sourceKind: "onedrive",
        remoteState: "online",
        lastSyncAt: 1776500060,
        cachedAt: 1776500030,
        lastError: null
      })
    };

    const client = new RuntimeClient(transport);
    await expect(client.retryVaultSourceSync("vault-1")).resolves.toEqual({
      type: "vault_source_status",
      sourceKind: "onedrive",
      remoteState: "online",
      lastSyncAt: 1776500060,
      cachedAt: 1776500030,
      lastError: null
    });

    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "retry_vault_source_sync",
        vault_id: "vault-1"
      }
    });
  });

  it("manages entry attachments through dedicated helpers", async () => {
    const transport = {
      send: vi.fn(async (request: { command: { type: string } }) => {
        if (request.command.type === "get_entry_attachment_content") {
          return {
          type: "entry_attachment_content",
          name: "backup.txt",
          dataBase64: "aGVsbG8=",
          protectInMemory: true
          };
        }
        if (request.command.type === "save_vault") {
          return { type: "save_vault_result", status: "saved" };
        }
        return {
          type: "entry_detail",
          id: "entry-1",
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com",
          notes: "demo",
          totp: null,
          attachments: []
        };
      })
    };

    const client = new RuntimeClient(transport);
    await client.getEntryAttachmentContent("vault-1", "entry-1", "backup.txt");
    await client.addEntryAttachment("vault-1", "entry-1", {
      name: "backup.txt",
      dataBase64: "aGVsbG8=",
      protectInMemory: true
    });
    await client.updateEntryAttachmentMetadata("vault-1", "entry-1", {
      oldName: "backup.txt",
      newName: "backup-renamed.txt",
      protectInMemory: false
    });
    await client.replaceEntryAttachmentContent("vault-1", "entry-1", {
      name: "backup-renamed.txt",
      dataBase64: "dXBkYXRlZA=="
    });
    await client.deleteEntryAttachment("vault-1", "entry-1", "backup-renamed.txt");

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      command: {
        type: "get_entry_attachment_content",
        vault_id: "vault-1",
        entry_id: "entry-1",
        name: "backup.txt"
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "add_entry_attachment",
        vault_id: "vault-1",
        entry_id: "entry-1",
        name: "backup.txt",
        data_base64: "aGVsbG8=",
        protect_in_memory: true
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(3, {
      version: 2,
      operationId: expect.any(String),
      command: { type: "save_vault", vault_id: "vault-1" }
    });
    expect(transport.send).toHaveBeenNthCalledWith(4, {
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "update_entry_attachment_metadata",
        vault_id: "vault-1",
        entry_id: "entry-1",
        old_name: "backup.txt",
        new_name: "backup-renamed.txt",
        protect_in_memory: false
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(6, {
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "replace_entry_attachment_content",
        vault_id: "vault-1",
        entry_id: "entry-1",
        name: "backup-renamed.txt",
        data_base64: "dXBkYXRlZA=="
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(8, {
      version: 2,
      operationId: expect.any(String),
      command: {
        type: "delete_entry_attachment",
        vault_id: "vault-1",
        entry_id: "entry-1",
        name: "backup-renamed.txt"
      }
    });
  });

  it("reads entry history through dedicated helpers", async () => {
    const transport = {
      send: vi
        .fn()
        .mockResolvedValueOnce({
          type: "entry_history_list",
          items: [
            {
              index: 0,
              title: "Old Example",
              username: "alice",
              modifiedAt: 42,
              attachmentCount: 1,
              customFieldCount: 1
            }
          ]
        })
        .mockResolvedValueOnce({
          type: "entry_history_detail",
          entryId: "entry-1",
          historyIndex: 0,
          title: "Old Example",
          username: "alice",
          url: "https://example.com",
          notes: "old note",
          customFields: [],
          attachments: []
        })
    };

    const client = new RuntimeClient(transport);
    await client.listEntryHistory("vault-1", "entry-1");
    await client.getEntryHistoryDetail("vault-1", "entry-1", 0);

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      command: {
        type: "list_entry_history",
        vault_id: "vault-1",
        entry_id: "entry-1"
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      command: {
        type: "get_entry_history_detail",
        vault_id: "vault-1",
        entry_id: "entry-1",
        history_index: 0
      }
    });
  });

  it("rejects in-band runtime errors for every command helper", async () => {
    const transport = {
      send: vi
        .fn()
        .mockResolvedValue({
          type: "error",
          code: "invalid_request",
          message: "vault is locked"
        })
    };

    const client = new RuntimeClient(transport);

    await expect(client.getSessionState()).rejects.toThrow("vault is locked");
    await expect(client.listRecentVaults()).rejects.toThrow("vault is locked");
    await expect(client.addLocalVaultReference()).rejects.toThrow("vault is locked");
    await expect(client.setCurrentVault("vault-ref-1")).rejects.toThrow(
      "vault is locked"
    );
    await expect(client.deleteRecentVault("vault-ref-1")).rejects.toThrow(
      "vault is locked"
    );
    await expect(client.openLocalVault("/tmp/demo.kdbx")).rejects.toThrow(
      "vault is locked"
    );
    await expect(
      client.unlockCurrentVaultWithPassword("demo-password")
    ).rejects.toThrow("vault is locked");
    await expect(
      client.unlockWithPassword("vault-1", "demo-password")
    ).rejects.toThrow("vault is locked");
    await expect(client.getEntryDetail("vault-1", "entry-1")).rejects.toThrow(
      "vault is locked"
    );
    await expect(client.listEntries("vault-1")).rejects.toThrow(
      "vault is locked"
    );
    await expect(client.listGroups("vault-1")).rejects.toThrow(
      "vault is locked"
    );
    await expect(
      client.findFillCandidates("vault-1", "https://example.com/login")
    ).rejects.toThrow("vault is locked");
    await expect(client.lockSession()).rejects.toThrow("vault is locked");
    await expect(
      client.createEntry("vault-1", {
        parentGroupId: "group-root",
        title: "Example",
        username: "alice",
        password: "secret",
        url: "https://example.com",
        notes: "demo",
        customFields: [],
        totpUri: null
      })
    ).rejects.toThrow("vault is locked");
    await expect(
      client.updateEntryFields("vault-1", "entry-1", {
        title: "Example",
        username: "alice",
        password: "secret",
        url: "https://example.com",
        notes: "demo",
        customFields: [],
        totpUri: null
      })
    ).rejects.toThrow("vault is locked");
    await expect(client.deleteEntry("vault-1", "entry-1")).rejects.toThrow(
      "vault is locked"
    );
    await expect(client.saveVault("vault-1")).rejects.toThrow("vault is locked");
    await expect(
      client.getEntryAttachmentContent("vault-1", "entry-1", "backup.txt")
    ).rejects.toThrow("vault is locked");
    await expect(
      client.addEntryAttachment("vault-1", "entry-1", {
        name: "backup.txt",
        dataBase64: "aGVsbG8=",
        protectInMemory: true
      })
    ).rejects.toThrow("vault is locked");
    await expect(
      client.updateEntryAttachmentMetadata("vault-1", "entry-1", {
        oldName: "backup.txt",
        newName: "backup-renamed.txt",
        protectInMemory: false
      })
    ).rejects.toThrow("vault is locked");
    await expect(
      client.replaceEntryAttachmentContent("vault-1", "entry-1", {
        name: "backup-renamed.txt",
        dataBase64: "dXBkYXRlZA=="
      })
    ).rejects.toThrow("vault is locked");
    await expect(
      client.deleteEntryAttachment("vault-1", "entry-1", "backup-renamed.txt")
    ).rejects.toThrow("vault is locked");
    await expect(client.listEntryHistory("vault-1", "entry-1")).rejects.toThrow(
      "vault is locked"
    );
    await expect(
      client.getEntryHistoryDetail("vault-1", "entry-1", 0)
    ).rejects.toThrow("vault is locked");
  });
});
