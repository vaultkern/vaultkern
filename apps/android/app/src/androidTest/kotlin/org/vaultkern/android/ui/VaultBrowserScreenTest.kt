package org.vaultkern.android.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.vaultkern.android.sync.AndroidSyncStatus
import org.vaultkern.android.vault.VaultEntryDraft
import org.vaultkern.android.vault.VaultEntryListItem

class VaultBrowserScreenTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun entryListOpensTheSelectedEditor() {
        var selected: String? = null
        compose.setContent {
            VaultBrowserScreen(
                entries = listOf(VaultEntryListItem("entry-1", "Example", "alice", true)),
                editor = null,
                busy = false,
                status = "Vault unlocked",
                conflictCopyPath = null,
                onEntrySelected = { selected = it },
                onDraftChanged = {},
                onSave = {},
                onCloseEditor = {},
                onLock = {},
            )
        }

        compose.onNodeWithText("Example").performClick()

        assertEquals("entry-1", selected)
    }

    @Test
    fun editorAndConflictCopyRecoveryPathAreVisible() {
        compose.setContent {
            VaultBrowserScreen(
                entries = emptyList(),
                editor = VaultEntryDraft(
                    id = "entry-1",
                    title = "Edited",
                    username = "alice",
                    password = "secret",
                    url = "https://example.test",
                    notes = "notes",
                    totpUri = null,
                    customFields = emptyList(),
                ),
                busy = false,
                status = "Foreign change detected",
                conflictCopyPath = "/vaults/demo (conflict).kdbx",
                onEntrySelected = {},
                onDraftChanged = {},
                onSave = {},
                onCloseEditor = {},
                onLock = {},
            )
        }

        compose.onNodeWithTag("entry-editor").assertIsDisplayed()
        compose.onNodeWithTag("save-entry").assertIsDisplayed()
        compose.onNodeWithTag("conflict-copy-path").assertIsDisplayed()
        compose.onNodeWithText("/vaults/demo (conflict).kdbx").assertIsDisplayed()
    }

    @Test
    fun pendingSyncAndRecoverableConflictCopyOfferAnExplicitRetry() {
        var syncs = 0
        compose.setContent {
            VaultBrowserScreen(
                entries = emptyList(),
                editor = null,
                busy = false,
                status = "Vault unlocked",
                conflictCopyPath = null,
                syncStatus = AndroidSyncStatus(
                    sourceKind = "onedrive",
                    remoteState = "pending_sync",
                    lastSyncAt = null,
                    cachedAt = 123,
                    lastError = "recoverable OneDrive conflict copy: onedrive:item-conflict",
                ),
                onEntrySelected = {},
                onDraftChanged = {},
                onSave = {},
                onCloseEditor = {},
                onSync = { syncs += 1 },
                onLock = {},
            )
        }

        compose.onNodeWithTag("sync-state").assertIsDisplayed()
        compose.onNodeWithTag("sync-conflict-copy").assertIsDisplayed()
        compose.onNodeWithTag("sync-now").performClick()
        assertEquals(1, syncs)
    }
}
