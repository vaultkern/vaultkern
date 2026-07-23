package org.vaultkern.android

import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import org.vaultkern.android.unlock.ResidentUnlockPort
import org.vaultkern.android.unlock.UnlockAttemptOutcome
import org.vaultkern.core.UnlockBlobStatusDto
import org.vaultkern.core.VaultKernSensitiveBytes
import org.vaultkern.core.VaultKernSensitiveString
import org.vaultkern.core.VaultSession

class VaultKernResidentUnlockPort(
    private val session: VaultSession,
) : ResidentUnlockPort {
    override fun interactiveUnlockCurrent(
        credential: CharArray,
        keyFile: VaultKernSensitiveBytes?,
    ) {
        withSensitiveCredential(credential) { password ->
            session.unlock().use { unlock ->
                if (keyFile == null) {
                    unlock.unlockCurrent(password, null, false)
                } else {
                    unlock.unlockCurrentWithKeyFile(password, keyFile, false)
                }
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

    override fun enrollQuickUnlock(
        credential: CharArray,
        keyFile: VaultKernSensitiveBytes?,
    ) {
        withSensitiveCredential(credential) { password ->
            session.unlock().use { unlock ->
                if (keyFile == null) {
                    unlock.enroll(password, null, false)
                } else {
                    unlock.enrollWithKeyFile(password, keyFile, false)
                }
            }
        }
    }

    private fun sensitiveCredential(chars: CharArray): VaultKernSensitiveString? =
        chars.takeIf(CharArray::isNotEmpty)
            ?.let { withClearableUtf8Bytes(it, VaultKernSensitiveString::fromUtf8Bytes) }

    private inline fun <T> withSensitiveCredential(
        chars: CharArray,
        block: (VaultKernSensitiveString?) -> T,
    ): T {
        val password = sensitiveCredential(chars)
        return try {
            block(password)
        } finally {
            password?.close()
        }
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
