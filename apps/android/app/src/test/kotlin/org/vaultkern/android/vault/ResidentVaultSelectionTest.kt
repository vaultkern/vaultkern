package org.vaultkern.android.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.vaultkern.core.VaultReferenceDto

class ResidentVaultSelectionTest {
    @Test
    fun currentReferenceBecomesRedactedUiSelectionMetadata() {
        val selection = ResidentVaultSelection(
            CurrentVaultReferenceGateway {
                VaultReferenceDto(
                    vaultRefId = "local-sensitive-id",
                    displayName = "personal",
                    sourceKind = "local",
                    sourceSummary = "vault.kdbx",
                    lastUsedAt = 1,
                    availability = "available",
                    supportsQuickUnlock = true,
                    isCurrent = true,
                )
            },
        ).current()!!

        assertEquals("personal", selection.displayName)
        assertEquals("local", selection.sourceKind)
        assertFalse(selection.toString().contains("personal"))
    }
}
