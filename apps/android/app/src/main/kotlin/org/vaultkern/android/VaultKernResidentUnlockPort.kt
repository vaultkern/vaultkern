package org.vaultkern.android

import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
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
        return withClearableUtf8Bytes(chars, VaultKernSensitiveString::fromUtf8Bytes)
    }
}

internal fun <T> withClearableUtf8Bytes(
    value: CharArray,
    use: (ByteArray) -> T,
): T {
    val encoded = Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
        .encode(CharBuffer.wrap(value))
    val bytes = ByteArray(encoded.remaining())
    encoded.get(bytes)
    return try {
        use(bytes)
    } finally {
        bytes.fill(0)
        if (encoded.hasArray()) encoded.array().fill(0)
    }
}
