package org.vaultkern.android.security

data class UnlockBlobRecord(
    val keyAlias: String,
    val iv: ByteArray,
    val ciphertext: ByteArray,
    val securityLevel: UnlockKeySecurityLevel,
)
