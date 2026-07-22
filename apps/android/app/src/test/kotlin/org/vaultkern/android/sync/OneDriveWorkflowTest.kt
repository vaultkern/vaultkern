package org.vaultkern.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.core.OneDriveAuthSessionDto
import org.vaultkern.core.OneDriveAuthStatusDto
import org.vaultkern.core.OneDriveItemDto
import org.vaultkern.core.VaultReferenceDto
import org.vaultkern.core.VaultSourceStatusDto

class OneDriveWorkflowTest {
    @Test
    fun loginPresentationBrowseAndSelectionStayInTheResidentGateway() {
        val core = RecordingOneDriveGateway()
        val opened = mutableListOf<String>()
        val workflow = OneDriveWorkflow(core, OneDriveAuthPresenter(opened::add))

        val pending = workflow.beginLogin()
        val account = workflow.completeLogin()
        val items = workflow.browse(null)
        val selected = workflow.select(items.single { !it.folder })

        assertEquals("http://127.0.0.1:53121/callback", pending.redirectUri)
        assertEquals(listOf("https://login.example/authorize"), opened)
        assertEquals("alice@example.com", account.accountLabel)
        assertEquals("Cloud Vault.kdbx", selected.displayName)
        assertEquals(
            listOf("begin-login", "complete-login", "list:root", "add:item-vault", "set:ref-1"),
            core.events,
        )
    }

    @Test
    fun onlyKdbxFilesCanBecomeVaultReferences() {
        val workflow = OneDriveWorkflow(RecordingOneDriveGateway(), OneDriveAuthPresenter {})
        val items = workflow.browse(null)

        assertThrows(IllegalArgumentException::class.java) {
            workflow.select(items.single { it.folder })
        }
        assertThrows(IllegalArgumentException::class.java) {
            workflow.select(
                OneDriveBrowserItem("drive-1", "item-text", "notes.txt", false, 8uL),
            )
        }
    }

    @Test
    fun syncUsesTheActiveVaultAndPreservesConflictFallbackDiagnostics() {
        val core = RecordingOneDriveGateway()
        val workflow = OneDriveWorkflow(core, OneDriveAuthPresenter {})

        val status = workflow.sync()

        assertEquals("online", status.remoteState)
        assertTrue(status.conflictCopyCreated)
        assertEquals("sync:vault-1", core.events.single())
        assertTrue(status.toString().contains("lastError=[REDACTED]"))
    }
}

private class RecordingOneDriveGateway : OneDriveCoreGateway {
    val events = mutableListOf<String>()

    override fun beginLogin(): OneDriveAuthSessionDto {
        events += "begin-login"
        return OneDriveAuthSessionDto(
            "https://login.example/authorize",
            "http://127.0.0.1:53121/callback",
            600u,
        )
    }

    override fun completeLogin(): OneDriveAuthStatusDto {
        events += "complete-login"
        return OneDriveAuthStatusDto("authorized", "alice@example.com")
    }

    override fun listChildren(parentItemId: String?): List<OneDriveItemDto> {
        events += "list:${parentItemId ?: "root"}"
        return listOf(
            OneDriveItemDto("drive-1", "folder-1", "Vaults", true, null),
            OneDriveItemDto("drive-1", "item-vault", "Cloud Vault.kdbx", false, 1_024u),
        )
    }

    override fun addVault(driveId: String, itemId: String): VaultReferenceDto {
        events += "add:$itemId"
        return VaultReferenceDto(
            "ref-1",
            "Cloud Vault.kdbx",
            "onedrive",
            "OneDrive",
            1,
            "available",
            true,
            false,
        )
    }

    override fun setCurrent(vaultRefId: String) {
        events += "set:$vaultRefId"
    }

    override fun activeVaultId(): String? = "vault-1"

    override fun sync(vaultId: String): VaultSourceStatusDto {
        events += "sync:$vaultId"
        return VaultSourceStatusDto(
            "onedrive",
            "online",
            123,
            123,
            "recoverable OneDrive conflict copy: onedrive:item-conflict",
        )
    }

    override fun status(): VaultSourceStatusDto? = null
}
