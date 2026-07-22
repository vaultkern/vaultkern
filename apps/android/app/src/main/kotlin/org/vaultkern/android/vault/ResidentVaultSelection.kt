package org.vaultkern.android.vault

import org.vaultkern.core.VaultReferenceDto
import org.vaultkern.core.VaultSession

data class CurrentVaultSelection(
    val displayName: String,
    val sourceKind: String,
) {
    override fun toString(): String =
        "CurrentVaultSelection(displayName=[REDACTED], sourceKind=$sourceKind)"
}

internal fun interface CurrentVaultReferenceGateway {
    fun current(): VaultReferenceDto?
}

class ResidentVaultSelection internal constructor(
    private val references: CurrentVaultReferenceGateway,
) {
    constructor(session: VaultSession) : this(
        CurrentVaultReferenceGateway {
            session.sources().use { sources ->
                sources.listRecent().vaults.firstOrNull { it.isCurrent }
            }
        },
    )

    fun current(): CurrentVaultSelection? = references.current()?.let { reference ->
        CurrentVaultSelection(reference.displayName, reference.sourceKind)
    }
}
