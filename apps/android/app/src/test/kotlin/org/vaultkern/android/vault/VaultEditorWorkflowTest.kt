package org.vaultkern.android.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultEditorWorkflowTest {
    @Test
    fun browseEditAndDurableSaveFlowUsesOneResidentPort() {
        val port = FakeResidentVaultPort()
        val workflow = VaultEditorWorkflow(port)

        val listed = workflow.browse()
        val draft = workflow.open(listed.single().id).copy(title = "Edited title")
        val result = workflow.save(draft)

        assertEquals(listOf("list", "read:entry-1", "save:entry-1:Edited title"), port.events)
        assertEquals(VaultSaveStatus.SAVED, result.status)
    }

    @Test
    fun conflictCopyIsAnExplicitRecoverableOutcome() {
        val port = FakeResidentVaultPort(
            saveResult = VaultSaveResult(
                status = VaultSaveStatus.CONFLICT_COPY,
                conflictCopyPath = "/vaults/demo (conflict).kdbx",
            ),
        )
        val workflow = VaultEditorWorkflow(port)

        val result = workflow.save(port.draft)

        assertEquals(VaultSaveStatus.CONFLICT_COPY, result.status)
        assertEquals("/vaults/demo (conflict).kdbx", result.conflictCopyPath)
    }

    @Test
    fun editorDraftDiagnosticRenderingRedactsEntrySecrets() {
        val draft = VaultEntryDraft(
            id = "entry-1",
            title = "Example",
            username = "alice",
            password = "never-print-entry-password",
            url = "https://example.test",
            notes = "private notes",
            totpUri = "otpauth://totp/example?secret=NEVERPRINT",
            customFields = listOf(VaultCustomField("token", "never-print-token", true)),
        )

        val rendered = draft.toString()

        assertFalse(rendered.contains("never-print-entry-password"))
        assertFalse(rendered.contains("NEVERPRINT"))
        assertFalse(rendered.contains("never-print-token"))
        assertTrue(rendered.contains("[REDACTED]"))
    }
}

private class FakeResidentVaultPort(
    private val saveResult: VaultSaveResult = VaultSaveResult(VaultSaveStatus.SAVED),
) : ResidentVaultPort {
    val events = mutableListOf<String>()
    val draft = VaultEntryDraft(
        id = "entry-1",
        title = "Original",
        username = "alice",
        password = "secret",
        url = "https://example.test",
        notes = "notes",
        totpUri = null,
        customFields = emptyList(),
    )

    override fun listEntries(): List<VaultEntryListItem> {
        events += "list"
        return listOf(VaultEntryListItem("entry-1", "Original", "alice", false))
    }

    override fun readEntry(entryId: String): VaultEntryDraft {
        events += "read:$entryId"
        return draft
    }

    override fun editAndSave(draft: VaultEntryDraft): VaultSaveResult {
        events += "save:${draft.id}:${draft.title}"
        return saveResult
    }

    override fun lock() = Unit
}
