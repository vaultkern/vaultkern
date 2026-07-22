package org.vaultkern.android

import org.vaultkern.android.unlock.ResidentUnlockPort
import org.vaultkern.android.unlock.UnlockAttemptOutcome
import org.vaultkern.core.UnlockBlobStatusDto
import org.vaultkern.core.VaultKernSensitiveString
import org.vaultkern.core.VaultSession

class VaultKernResidentUnlockPort(
    private val session: VaultSession,
) : ResidentUnlockPort {
    override fun interactiveUnlock(path: String, credential: CharArray) {
        val handle = session.openVault(path)
        sensitiveCredential(credential).use { password ->
            session.unlock().use { unlock ->
                unlock.unlockVault(handle.vaultId, password, null, false)
            }
        }
    }

    override fun quickUnlock(): UnlockAttemptOutcome = session.unlock().use { unlock ->
        when (unlock.unlockWithBlob(false).status) {
            UnlockBlobStatusDto.UNLOCKED -> UnlockAttemptOutcome.UNLOCKED
            UnlockBlobStatusDto.NOT_ENROLLED -> UnlockAttemptOutcome.NOT_ENROLLED
            UnlockBlobStatusDto.CANCELLED -> UnlockAttemptOutcome.CANCELLED
            UnlockBlobStatusDto.OPEN_APP_REQUIRED -> UnlockAttemptOutcome.OPEN_APP_REQUIRED
            UnlockBlobStatusDto.CREDENTIAL_REQUIRED -> UnlockAttemptOutcome.CREDENTIAL_REQUIRED
            UnlockBlobStatusDto.UNSUPPORTED -> UnlockAttemptOutcome.UNSUPPORTED
        }
    }

    override fun enrollQuickUnlock(credential: CharArray) {
        sensitiveCredential(credential).use { password ->
            session.unlock().use { unlock ->
                unlock.enroll(password, null, false)
            }
        }
    }

    private fun sensitiveCredential(chars: CharArray): VaultKernSensitiveString {
        return VaultKernSensitiveString.fromString(String(chars))
    }
}
