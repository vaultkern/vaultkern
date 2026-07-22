package org.vaultkern.android.vault

import org.junit.Assert.assertEquals
import org.junit.Test
import org.vaultkern.core.VaultReferenceDto

class ResidentVaultSelectionTest {
    @Test
    fun currentReferenceRestoresTheSelectedSourceWithoutOpeningIt() {
        val selection = ResidentVaultSelection(
            CurrentVaultReferenceGateway {
                VaultReferenceDto(
                    "ref-local",
                    "Personal.kdbx",
                    "local",
                    "Local file",
                    12,
                    "available",
                    true,
                    true,
                )
            },
        )

        assertEquals(
            CurrentVaultSelection("Personal.kdbx", "local"),
            selection.current(),
        )
    }

    @Test
    fun absentCurrentReferenceDoesNotInventASelection() {
        val selection = ResidentVaultSelection(CurrentVaultReferenceGateway { null })

        assertEquals(null, selection.current())
    }
}
