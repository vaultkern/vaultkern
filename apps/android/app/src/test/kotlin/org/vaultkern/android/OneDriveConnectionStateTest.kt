package org.vaultkern.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.android.sync.OneDriveBrowserItem
import org.vaultkern.android.ui.UnlockUiState

class OneDriveConnectionStateTest {
    @Test
    fun missingTokenClearsStaleAccountBrowseStateButKeepsTheSelectedVault() {
        val state = UnlockUiState(
            oneDriveConnected = true,
            oneDriveAccountLabel = "alice@example.com",
            oneDriveItems = listOf(
                OneDriveBrowserItem("drive", "item", "Cloud.kdbx", false, 42u),
            ),
            oneDriveFolderId = "folder",
            oneDriveVaultSelected = true,
            oneDriveSelectedName = "Cloud.kdbx",
        )

        val reconciled = state.reconcileOneDriveTokenPresence(false)

        assertFalse(reconciled.oneDriveConnected)
        assertEquals(null, reconciled.oneDriveAccountLabel)
        assertTrue(reconciled.oneDriveItems.isEmpty())
        assertEquals(null, reconciled.oneDriveFolderId)
        assertTrue(reconciled.oneDriveVaultSelected)
        assertEquals("Cloud.kdbx", reconciled.oneDriveSelectedName)
    }

    @Test
    fun storedTokenMarksConnectedWithoutDroppingBrowseState() {
        val item = OneDriveBrowserItem("drive", "item", "Cloud.kdbx", false, 42u)
        val state = UnlockUiState(oneDriveItems = listOf(item), oneDriveFolderId = "folder")

        val reconciled = state.reconcileOneDriveTokenPresence(true)

        assertTrue(reconciled.oneDriveConnected)
        assertEquals(listOf(item), reconciled.oneDriveItems)
        assertEquals("folder", reconciled.oneDriveFolderId)
    }
}
