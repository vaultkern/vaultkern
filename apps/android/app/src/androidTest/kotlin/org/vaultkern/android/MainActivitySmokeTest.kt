package org.vaultkern.android

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onNodeWithTag
import org.junit.Rule
import org.junit.Test

class MainActivitySmokeTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun composeShellStartsWithPersistedDesiredStateAndEnrollmentStatus() {
        compose.onNodeWithText("VaultKern").assertExists()
        compose.onNodeWithTag("quick-unlock-toggle").assertExists()
        compose.onNodeWithTag("unlock-enrollment-state").assertExists()
    }
}
