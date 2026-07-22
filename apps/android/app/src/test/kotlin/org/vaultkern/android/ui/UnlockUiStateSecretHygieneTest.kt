package org.vaultkern.android.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UnlockUiStateSecretHygieneTest {
    @Test
    fun diagnosticRenderingRedactsThePlaintextCredential() {
        val state = UnlockUiState(password = "never-print-this-password")

        val rendered = state.toString()

        assertFalse(rendered.contains("never-print-this-password"))
        assertTrue(rendered.contains("[REDACTED]"))
    }
}
