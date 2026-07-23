package org.vaultkern.android.ui

import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.withHint
import androidx.test.espresso.matcher.ViewMatchers.withText
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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
                onInteractiveUnlock = { it.fill('\u0000') },
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
                onInteractiveUnlock = { it.fill('\u0000') },
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
                onInteractiveUnlock = { it.fill('\u0000') },
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = {},
            )
        }
        compose.onNodeWithTag("unlock-enrollment-state")
            .assertTextContains("not enrolled", substring = true, ignoreCase = true)
    }

    @Test
    fun keyFileSelectionShowsOnlyItsLabelAndUsesTheSystemPickerAction() {
        var chooseKeyFile = false
        compose.setContent {
            VaultKernUnlockScreen(
                state = UnlockUiState(selectedKeyFileName = "login.key"),
                onInteractiveUnlock = { it.fill('\u0000') },
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = {},
                onChooseKeyFile = { chooseKeyFile = true },
            )
        }

        compose.onNodeWithTag("selected-key-file")
            .assertTextContains("login.key", substring = true)
        compose.onNodeWithTag("choose-key-file").performClick()
        assertTrue(chooseKeyFile)
    }

    @Test
    fun localVaultSelectionUsesTheSystemPickerInsteadOfAPathField() {
        var chooseLocalVault = false
        compose.setContent {
            VaultKernUnlockScreen(
                state = UnlockUiState(selectedVaultName = "personal.kdbx"),
                onInteractiveUnlock = { it.fill('\u0000') },
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = {},
                onChooseLocalVault = { chooseLocalVault = true },
            )
        }

        compose.onNodeWithTag("selected-vault-name")
            .assertTextContains("personal.kdbx", substring = true)
        compose.onNodeWithTag("choose-local-vault").performClick()
        assertTrue(chooseLocalVault)
        compose.onNode(hasTestTag("vault-path")).assertDoesNotExist()
    }

    @Test
    fun unlockActionsStayDisabledUntilThereIsACurrentVault() {
        compose.setContent {
            VaultKernUnlockScreen(
                state = UnlockUiState(currentVaultSelected = false),
                onInteractiveUnlock = { it.fill('\u0000') },
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = {},
            )
        }

        compose.onNodeWithTag("interactive-unlock").assertIsNotEnabled()
        compose.onNodeWithTag("biometric-unlock").assertIsNotEnabled()
    }

    @Test
    fun quickUnlockDropsAnyUnsubmittedInteractiveCredential() {
        var quickUnlockRequested = false
        compose.setContent {
            VaultKernUnlockScreen(
                state = UnlockUiState(currentVaultSelected = true),
                onInteractiveUnlock = { it.fill('\u0000') },
                onQuickUnlock = { quickUnlockRequested = true },
                onQuickUnlockDesiredChanged = {},
            )
        }
        onView(withHint("Master password")).perform(replaceText("must-not-linger"))

        compose.onNodeWithTag("biometric-unlock").performClick()

        assertTrue(quickUnlockRequested)
        onView(withHint("Master password")).check(matches(withText("")))
    }
}
