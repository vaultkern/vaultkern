package org.vaultkern.android.ui

import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.security.UnlockKeySecurityLevel

class UnlockScreenTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun invalidatedEnrollmentIsVisibleAndDesiredToggleOnlyEmitsTheNewSetting() {
        var requested = true
        compose.setContent {
            VaultKernUnlockScreen(
                state = UnlockUiState(
                    quickUnlockDesired = true,
                    enrollmentState = UnlockEnrollmentState.INVALIDATED,
                    keySecurityLevel = UnlockKeySecurityLevel.TRUSTED_ENVIRONMENT,
                ),
                onPasswordChanged = {},
                onInteractiveUnlock = {},
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = { requested = it },
            )
        }

        compose.onNodeWithTag("unlock-enrollment-state")
            .assertTextContains("invalidated", substring = true, ignoreCase = true)
        compose.onNodeWithTag("unlock-security-level")
            .assertTextContains("trusted environment", substring = true, ignoreCase = true)
        compose.onNodeWithTag("quick-unlock-toggle").assertIsOn().performClick()
        assertFalse(requested)
    }

    @Test
    fun enrolledStateHasDistinctUserFacingText() {
        compose.setContent {
            VaultKernUnlockScreen(
                state = UnlockUiState(enrollmentState = UnlockEnrollmentState.ENROLLED),
                onPasswordChanged = {},
                onInteractiveUnlock = {},
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = {},
            )
        }
        compose.onNodeWithTag("unlock-enrollment-state")
            .assertTextContains("enrolled", substring = true, ignoreCase = true)
    }

    @Test
    fun notEnrolledStateHasDistinctUserFacingText() {
        compose.setContent {
            VaultKernUnlockScreen(
                state = UnlockUiState(enrollmentState = UnlockEnrollmentState.NOT_ENROLLED),
                onPasswordChanged = {},
                onInteractiveUnlock = {},
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = {},
            )
        }
        compose.onNodeWithTag("unlock-enrollment-state")
            .assertTextContains("not enrolled", substring = true, ignoreCase = true)
    }

    @Test
    fun localVaultButtonLaunchesTheDocumentPickerCallback() {
        var launches = 0
        compose.setContent {
            VaultKernUnlockScreen(
                state = UnlockUiState(),
                onPasswordChanged = {},
                onInteractiveUnlock = {},
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = {},
                onChooseLocalVault = { launches += 1 },
            )
        }

        compose.onNodeWithTag("choose-local-vault").performClick()

        assertEquals(1, launches)
    }

    @Test
    fun pendingOneDriveLoginAndRemoteVaultSelectionRemainActionable() {
        var unlocks = 0
        var completions = 0
        compose.setContent {
            VaultKernUnlockScreen(
                state = UnlockUiState(
                    oneDriveAuthPending = true,
                    currentVaultSelected = true,
                    oneDriveVaultSelected = true,
                    oneDriveSelectedName = "Cloud Vault.kdbx",
                ),
                onPasswordChanged = {},
                onInteractiveUnlock = { unlocks += 1 },
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = {},
                onCompleteOneDriveLogin = { completions += 1 },
            )
        }

        compose.onNodeWithTag("interactive-unlock").performClick()
        compose.onNodeWithTag("onedrive-complete-login").performScrollTo().performClick()

        assertEquals(1, unlocks)
        assertEquals(1, completions)
    }
}
