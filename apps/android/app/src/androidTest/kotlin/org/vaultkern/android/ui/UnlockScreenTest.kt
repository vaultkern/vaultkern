package org.vaultkern.android.ui

import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
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
                onPathChanged = {},
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
                onPathChanged = {},
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
                onPathChanged = {},
                onPasswordChanged = {},
                onInteractiveUnlock = {},
                onQuickUnlock = {},
                onQuickUnlockDesiredChanged = {},
            )
        }
        compose.onNodeWithTag("unlock-enrollment-state")
            .assertTextContains("not enrolled", substring = true, ignoreCase = true)
    }
}
