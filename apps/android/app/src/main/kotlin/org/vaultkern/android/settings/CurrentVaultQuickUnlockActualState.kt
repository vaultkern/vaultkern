package org.vaultkern.android.settings

import java.security.MessageDigest
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.core.VaultSession

class CurrentVaultQuickUnlockActualState(
    private val session: VaultSession,
    private val storedState: (String) -> UnlockEnrollmentState,
    private val revokeAll: () -> Unit,
) : QuickUnlockActualState {
    override fun enrollmentState(): UnlockEnrollmentState {
        val current = currentReference()
        if (current?.supportsQuickUnlock == true) {
            return UnlockEnrollmentState.ENROLLED
        }
        return current?.vaultRefId
            ?.let(::quickUnlockStorageKey)
            ?.let(storedState)
            ?: UnlockEnrollmentState.NOT_ENROLLED
    }

    fun currentStorageKey(): String? =
        currentReference()?.vaultRefId?.let(::quickUnlockStorageKey)

    override fun vaultIsUnlocked(): Boolean = session.sessionState().unlocked

    override fun revokeAll() {
        revokeAll.invoke()
    }

    private fun currentReference() = session.sources().use { sources ->
        sources.listRecent().vaults.firstOrNull { it.isCurrent }
    }

    private fun quickUnlockStorageKey(vaultRefId: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(vaultRefId.encodeToByteArray())
        return buildString(QUICK_UNLOCK_PREFIX.length + digest.size * 2) {
            append(QUICK_UNLOCK_PREFIX)
            digest.forEach { byte -> append("%02x".format(byte.toInt() and 0xff)) }
        }
    }

    companion object {
        private const val QUICK_UNLOCK_PREFIX = "quick_unlock_"
    }
}
