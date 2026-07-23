package org.vaultkern.android.ui

import org.junit.Assert.assertFalse
import org.junit.Test

class UnlockUiStateSecretHygieneTest {
    @Test
    fun durableUiStateHasNoMasterCredentialField() {
        val fields = UnlockUiState::class.java.declaredFields.map { it.name }

        assertFalse(fields.contains("password"))
        assertFalse(fields.contains("vaultPath"))
        assertFalse(UnlockUiState().toString().contains("password", ignoreCase = true))
    }
}
