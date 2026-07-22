package org.vaultkern.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.security.UnlockKeySecurityLevel
import org.vaultkern.android.sync.OneDriveBrowserItem
import org.vaultkern.android.ui.UnlockUiState
import org.vaultkern.android.vault.CurrentVaultSelection

class OneDriveConnectionStateTest {
    @Test
    fun changingCurrentVaultRefreshesItsQuickUnlockActualState() {
        val previous = UnlockUiState(
            enrollmentState = UnlockEnrollmentState.ENROLLED,
            keySecurityLevel = UnlockKeySecurityLevel.STRONGBOX,
        )

        val selected = previous.withCurrentVaultUnlockState(
            UnlockEnrollmentState.NOT_ENROLLED,
            null,
        )

        assertEquals(UnlockEnrollmentState.NOT_ENROLLED, selected.enrollmentState)
        assertEquals(null, selected.keySecurityLevel)
    }

    @Test
    fun absentCurrentReferenceClearsEveryStaleAuthorityProjection() {
        val staleStatus = org.vaultkern.android.sync.AndroidSyncStatus(
            "onedrive",
            "pending_sync",
            null,
            1,
            "retry",
        )
        val stale = UnlockUiState(
            vaultPath = "/private/stale.kdbx",
            selectedVaultName = "Stale local.kdbx",
            currentVaultSelected = true,
            oneDriveVaultSelected = true,
            oneDriveSelectedName = "Stale remote.kdbx",
            syncStatus = staleStatus,
        )

        val restored = stale.withRestoredVaultSelection(null, staleStatus)

        assertEquals("", restored.vaultPath)
        assertEquals(null, restored.selectedVaultName)
        assertFalse(restored.currentVaultSelected)
        assertFalse(restored.oneDriveVaultSelected)
        assertEquals(null, restored.oneDriveSelectedName)
        assertEquals(null, restored.syncStatus)
    }

    @Test
    fun processRestartRestoresCurrentLocalSelectionWithoutAPathInUiState() {
        val restored = UnlockUiState().withRestoredVaultSelection(
            CurrentVaultSelection("Personal.kdbx", "local"),
            null,
        )

        assertTrue(restored.currentVaultSelected)
        assertEquals("", restored.vaultPath)
        assertEquals("Personal.kdbx", restored.selectedVaultName)
        assertFalse(restored.oneDriveVaultSelected)
    }

    @Test
    fun processRestartRestoresCurrentRemoteSelectionWithoutAnOpenSession() {
        val restored = UnlockUiState().withRestoredVaultSelection(
            CurrentVaultSelection("Cloud.kdbx", "onedrive"),
            null,
        )

        assertTrue(restored.currentVaultSelected)
        assertEquals(null, restored.selectedVaultName)
        assertTrue(restored.oneDriveVaultSelected)
        assertEquals("Cloud.kdbx", restored.oneDriveSelectedName)
    }

    @Test
    fun choosingLocalAuthorityClearsTheRemoteVaultSelection() {
        val state = UnlockUiState(
            oneDriveVaultSelected = true,
            oneDriveSelectedName = "Cloud.kdbx",
            syncStatus = org.vaultkern.android.sync.AndroidSyncStatus(
                "onedrive",
                "online",
                1,
                1,
                null,
            ),
        )

        val selected = state.withSelectedLocalVault("/private/local/vault.kdbx", "Local.kdbx")

        assertEquals("/private/local/vault.kdbx", selected.vaultPath)
        assertEquals("Local.kdbx", selected.selectedVaultName)
        assertFalse(selected.oneDriveVaultSelected)
        assertEquals(null, selected.oneDriveSelectedName)
        assertEquals(null, selected.syncStatus)
    }

    @Test
    fun choosingRemoteAuthorityClearsTheLocalVaultSelection() {
        val state = UnlockUiState(
            vaultPath = "/private/local/vault.kdbx",
            selectedVaultName = "Local.kdbx",
        )
        val sync = org.vaultkern.android.sync.AndroidSyncStatus(
            "onedrive",
            "online",
            2,
            2,
            null,
        )

        val selected = state.withSelectedOneDriveVault("Cloud.kdbx", sync)

        assertEquals("", selected.vaultPath)
        assertEquals(null, selected.selectedVaultName)
        assertTrue(selected.oneDriveVaultSelected)
        assertEquals("Cloud.kdbx", selected.oneDriveSelectedName)
        assertEquals(sync, selected.syncStatus)
    }

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
