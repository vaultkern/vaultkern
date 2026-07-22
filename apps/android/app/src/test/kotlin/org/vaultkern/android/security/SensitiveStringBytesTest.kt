package org.vaultkern.android.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.vaultkern.core.VaultKernSensitiveString

class SensitiveStringBytesTest {
    @Test
    fun sensitiveStringCrossesProtectedStorageAsClearableUtf8Bytes() {
        val source = "refresh-token".toByteArray()
        val expected = source.copyOf()
        val sensitive = VaultKernSensitiveString.fromUtf8Bytes(source)

        assertArrayEquals(ByteArray(source.size), source)
        val copied = sensitive.copyUtf8Bytes()
        assertArrayEquals(expected, copied)

        sensitive.close()
        assertEquals(0, sensitive.copyUtf8Bytes().size)
        copied.fill(0)
        expected.fill(0)
    }
}
