import { describe, expect, it, vi } from "vitest";
import { RuntimeClient } from "../index";

function committedEntryMutation(
  entry: Record<string, unknown> | undefined,
  status: "saved" | "merged" | "saved_to_cache" | "conflict_copy" = "saved"
) {
  return {
    type: "entry_mutation_result",
    commit: "committed",
    publication: {
      status,
      mergeSummary: null
    },
    ...(entry ? { entry } : {})
  };
}

function committedVaultMutation(createdGroupId?: string) {
  return {
    type: "vault_mutation_result",
    commit: "committed",
    publication: {
      status: "saved",
      mergeSummary: null
    },
    ...(createdGroupId === undefined ? {} : { createdGroupId })
  };
}

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
      send: vi.fn().mockResolvedValue(
        committedEntryMutation({
          id: "entry-1",
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com",
          notes: "demo",
          totp: "287082"
        })
      )
    };

    const client = new RuntimeClient(transport);
    const result = await client.createEntry("vault-1", {
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
      command: {
        type: "create_entry",
        vault_id: "vault-1",
        parent_group_id: "group-root",
        title: "Example",
        username: "alice",
        password: "secret",
        url: "https://example.com",
        notes: "demo",
        totp_uri:
          "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test"
      }
    });
    expect(result.value).toMatchObject({
      type: "entry_detail",
      id: "entry-1"
    });
  });

  it("commits a browser login create once without a logical operation id", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue(
        committedEntryMutation(undefined, "saved_to_cache")
      )
    };
    const client = new RuntimeClient(transport);

    await expect(
      client.createAutofillEntry("vault-1", {
        parentGroupId: "group-root",
        title: "Example",
        username: "alice",
        password: "secret",
        url: "https://example.com/login",
        notes: "",
        customFields: [],
        totpUri: null
      })
    ).resolves.toEqual({
      commit: "committed",
      saveResult: {
        type: "save_vault_result",
        status: "saved_to_cache",
        mergeSummary: null
      }
    });
    expect(transport.send).toHaveBeenCalledTimes(1);
    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "create_autofill_entry",
        vault_id: "vault-1",
        parent_group_id: "group-root",
        title: "Example",
        username: "alice",
        password: "secret",
        url: "https://example.com/login",
        notes: "",
        totp_uri: null
      }
    });
  });

  it("commits a browser login update once without replaying an ambiguous response", async () => {
    const timeout = Object.assign(new Error("native request timed out"), {
      code: "native_timeout"
    });
    const transport = { send: vi.fn().mockRejectedValue(timeout) };
    const client = new RuntimeClient(transport);
    const expectedFields = {
      username: "alice",
      password: "old-secret",
      url: "https://example.com/login"
    };

    await expect(
      client.updateAutofillEntryFields(
        "vault-1",
        "entry-1",
        expectedFields,
        { ...expectedFields, password: "new-secret" }
      )
    ).rejects.toBe(timeout);
    expect(transport.send).toHaveBeenCalledTimes(1);
    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "update_autofill_entry_fields",
        vault_id: "vault-1",
        entry_id: "entry-1",
        expected_fields: expectedFields,
        desired_fields: {
          ...expectedFields,
          password: "new-secret"
        }
      }
    });
  });

  it("does not replay an ambiguous ordinary mutation or attach logical identity", async () => {
    const disconnect = Object.assign(new Error("native port disconnected"), {
      code: "native_port_disconnected"
    });
    const transport = {
      send: vi.fn().mockRejectedValue(disconnect)
    };

    const client = new RuntimeClient(transport);
    await expect(
      client.createEntry("vault-1", {
        parentGroupId: "group-root",
        title: "Example",
        username: "alice",
        password: "secret",
        url: "https://example.com",
        notes: "",
        customFields: [],
        totpUri: null
      })
    ).rejects.toBe(disconnect);

    expect(transport.send).toHaveBeenCalledTimes(1);
    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "create_entry",
        vault_id: "vault-1",
        parent_group_id: "group-root",
        title: "Example",
        username: "alice",
        password: "secret",
        url: "https://example.com",
        notes: "",
        totp_uri: null
      }
    });
  });

  it("updates and deletes entries through dedicated helpers", async () => {
    const transport = {
      send: vi
        .fn()
        .mockResolvedValueOnce(
          committedEntryMutation({
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
        )
        .mockResolvedValueOnce(committedEntryMutation(undefined))
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
      command: {
        type: "delete_entry",
        vault_id: "vault-1",
        entry_id: "entry-1"
      }
    });
  });

  it("commits TOTP and passkey mutations without follow-up saves", async () => {
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
        .mockResolvedValueOnce(committedEntryMutation({
          id: "entry-1",
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com",
          notes: "demo",
          totp: null,
          passkey
        }))
        .mockResolvedValueOnce(committedEntryMutation({
          id: "entry-1",
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com",
          notes: "demo",
          totp: null,
          passkey
        }))
        .mockResolvedValueOnce(committedEntryMutation({
          id: "entry-1",
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com",
          notes: "demo",
          totp: null,
          passkey: null
        }))
    };

    const client = new RuntimeClient(transport);
    await client.clearEntryTotp("vault-1", "entry-1");
    await client.setEntryPasskey("vault-1", "entry-1", passkey);
    await client.clearEntryPasskey("vault-1", "entry-1");

    expect(transport.send).toHaveBeenNthCalledWith(1, {
      version: 2,
      command: {
        type: "clear_entry_totp",
        vault_id: "vault-1",
        entry_id: "entry-1"
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(2, {
      version: 2,
      command: {
        type: "set_entry_passkey",
        vault_id: "vault-1",
        entry_id: "entry-1",
        passkey
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(3, {
      version: 2,
      command: {
        type: "clear_entry_passkey",
        vault_id: "vault-1",
        entry_id: "entry-1"
      }
    });
    expect(transport.send).toHaveBeenCalledTimes(3);
  });

  it("commits group, tree, history, and recycle mutations without follow-up saves", async () => {
    const transport = {
      send: vi.fn(
        async (request: { command: { type: string } }) =>
        request.command.type === "create_group"
          ? committedVaultMutation("group-created")
          : committedVaultMutation()
      )
    };
    const client = new RuntimeClient(transport);

    await expect(
      client.createGroup("vault-1", "group-root", "Work")
    ).resolves.toMatchObject({ createdGroupId: "group-created" });
    await client.renameGroup("vault-1", "group-created", "Archive");
    await client.moveGroup("vault-1", "group-created", "group-parent");
    await client.moveEntryToGroup("vault-1", "entry-1", "group-created");
    await client.restoreEntryHistory("vault-1", "entry-1", 2);
    await client.clearEntryHistory("vault-1", "entry-1");
    await client.recycleEntry("vault-1", "entry-1");
    await client.restoreRecycledEntry(
      "vault-1",
      "entry-1",
      "group-root"
    );
    await client.deleteGroup("vault-1", "group-created");

    expect(
      transport.send.mock.calls.map(([request]) => request.command)
    ).toEqual([
      {
        type: "create_group",
        vault_id: "vault-1",
        parent_group_id: "group-root",
        title: "Work"
      },
      {
        type: "rename_group",
        vault_id: "vault-1",
        group_id: "group-created",
        title: "Archive"
      },
      {
        type: "move_group",
        vault_id: "vault-1",
        group_id: "group-created",
        target_parent_group_id: "group-parent"
      },
      {
        type: "move_entry_to_group",
        vault_id: "vault-1",
        entry_id: "entry-1",
        target_group_id: "group-created"
      },
      {
        type: "restore_entry_history",
        vault_id: "vault-1",
        entry_id: "entry-1",
        history_index: 2
      },
      {
        type: "clear_entry_history",
        vault_id: "vault-1",
        entry_id: "entry-1"
      },
      {
        type: "recycle_entry",
        vault_id: "vault-1",
        entry_id: "entry-1"
      },
      {
        type: "restore_recycled_entry",
        vault_id: "vault-1",
        entry_id: "entry-1",
        target_group_id: "group-root"
      },
      {
        type: "delete_group",
        vault_id: "vault-1",
        group_id: "group-created"
      }
    ]);
    expect(
      transport.send.mock.calls.some(
        ([request]) => request.command.type === "save_vault"
      )
    ).toBe(false);
  });

  it("normalizes the publication bundled with a database settings commit", async () => {
    const transport = {
      send: vi.fn().mockResolvedValue({
        type: "database_settings_commit_result",
        commit: "committed",
        settings: {},
        saveResult: {
          status: "saved_to_cache",
          mergeSummary: null
        }
      })
    };
    const client = new RuntimeClient(transport);

    await expect(
      client.updateDatabaseSettings("vault-1", { autosaveDelaySeconds: 20 })
    ).resolves.toMatchObject({
      commit: "committed",
      saveResult: {
        type: "save_vault_result",
        status: "saved_to_cache"
      }
    });
    expect(transport.send).toHaveBeenCalledWith({
      version: 2,
      command: {
        type: "update_database_settings",
        vault_id: "vault-1",
        update: { autosaveDelaySeconds: 20 }
      }
    });
    expect(transport.send).toHaveBeenCalledTimes(1);
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

  it("uses the publication bundled with a committed entry mutation", async () => {
    const messages: Array<Record<string, unknown>> = [];
    const transport = {
      send: vi.fn(async (message: unknown) => {
        messages.push(message as Record<string, unknown>);
        return messages.length === 1
          ? committedEntryMutation({
              type: "entry_detail",
              id: "entry-1",
              title: "Example",
              username: "alice",
              password: "secret",
              url: "https://example.com",
              notes: "",
              totp: null,
              customFields: []
            })
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

    expect(Object.keys(messages[0] ?? {}).sort()).toEqual(["command", "version"]);
    expect(Object.keys(messages[1] ?? {}).sort()).toEqual(["command", "version"]);
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
        return committedEntryMutation({
          id: "entry-1",
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com",
          notes: "demo",
          totp: null,
          attachments: []
        });
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
      command: {
        type: "update_entry_attachment_metadata",
        vault_id: "vault-1",
        entry_id: "entry-1",
        old_name: "backup.txt",
        new_name: "backup-renamed.txt",
        protect_in_memory: false
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(4, {
      version: 2,
      command: {
        type: "replace_entry_attachment_content",
        vault_id: "vault-1",
        entry_id: "entry-1",
        name: "backup-renamed.txt",
        data_base64: "dXBkYXRlZA=="
      }
    });
    expect(transport.send).toHaveBeenNthCalledWith(5, {
      version: 2,
      command: {
        type: "delete_entry_attachment",
        vault_id: "vault-1",
        entry_id: "entry-1",
        name: "backup-renamed.txt"
      }
    });
    expect(transport.send).toHaveBeenCalledTimes(5);
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
