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

    @Test
    fun diagnosticRenderingDoesNotExposeThePrivatePathOrVaultDisplayName() {
        val state = UnlockUiState(
            vaultPath = "/data/user/0/org.vaultkern.android/no_backup/private-name.kdbx",
            selectedVaultName = "personal-finances.kdbx",
        )

        val rendered = state.toString()

        assertFalse(rendered.contains("private-name.kdbx"))
        assertFalse(rendered.contains("personal-finances.kdbx"))
        assertTrue(rendered.contains("[REDACTED]"))
    }
}
