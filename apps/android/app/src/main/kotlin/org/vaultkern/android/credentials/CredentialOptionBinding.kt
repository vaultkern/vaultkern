package org.vaultkern.android.credentials

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

internal object CredentialOptionBinding {
    fun key(requestJson: String, clientDataHash: ByteArray?): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(requestJson.toByteArray(StandardCharsets.UTF_8))
        digest.update(0.toByte())
        if (clientDataHash == null) {
            digest.update(0.toByte())
        } else {
            digest.update(1.toByte())
            digest.update(clientDataHash)
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest())
    }
}
