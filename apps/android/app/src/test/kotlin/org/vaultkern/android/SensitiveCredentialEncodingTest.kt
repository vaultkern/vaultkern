package org.vaultkern.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SensitiveCredentialEncodingTest {
    @Test
    fun utf8CredentialBytesAreClearedAfterSuccessfulUse() {
        val credential = "密码🔐".toCharArray()
        var borrowed: ByteArray? = null

        val copied = withClearableUtf8Bytes(credential) { bytes ->
            borrowed = bytes
            bytes.copyOf()
        }

        assertArrayEquals("密码🔐".toByteArray(Charsets.UTF_8), copied)
        assertTrue(borrowed!!.all { it == 0.toByte() })
        copied.fill(0)
        credential.fill('\u0000')
    }

    @Test
    fun utf8CredentialBytesAreClearedWhenUseFails() {
        val credential = "failure-path".toCharArray()
        var borrowed: ByteArray? = null

        val result = runCatching {
            withClearableUtf8Bytes(credential) { bytes ->
                borrowed = bytes
                error("injected failure")
            }
        }

        assertEquals("injected failure", result.exceptionOrNull()?.message)
        assertTrue(borrowed!!.all { it == 0.toByte() })
        credential.fill('\u0000')
    }
}
