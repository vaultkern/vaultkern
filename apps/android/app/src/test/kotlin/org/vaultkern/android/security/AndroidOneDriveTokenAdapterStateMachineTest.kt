package org.vaultkern.android.security

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.VaultKernSensitiveString

class AndroidOneDriveTokenAdapterStateMachineTest {
    @Test
    fun committedRecordSurvivesAnAmbiguousWriteReturn() {
        val records = InMemoryOneDriveTokenRecordStorage().apply {
            throwAfterNextCommit = true
        }
        val ciphers = InMemoryOneDriveTokenCipherBackend()
        val adapter = AndroidOneDriveTokenAdapter(records, ciphers)
        val expected = "rotated-refresh-token".encodeToByteArray()
        val source = expected.copyOf()

        adapter.storeRefreshToken(VaultKernSensitiveString.fromUtf8Bytes(source))

        val loaded = requireNotNull(adapter.loadRefreshToken())
        val actual = loaded.copyUtf8Bytes()
        loaded.close()
        try {
            assertArrayEquals(expected, actual)
            assertTrue(ciphers.aliases().contains(requireNotNull(records.read()).keyAlias))
        } finally {
            actual.fill(0)
            expected.fill(0)
        }
    }

    @Test
    fun failedBrokenRecordDeletionKeepsMaintenancePending() {
        val records = InMemoryOneDriveTokenRecordStorage()
        val ciphers = InMemoryOneDriveTokenCipherBackend()
        val adapter = AndroidOneDriveTokenAdapter(records, ciphers)
        val source = "damaged-refresh-token".encodeToByteArray()
        adapter.storeRefreshToken(VaultKernSensitiveString.fromUtf8Bytes(source))
        records.damageCiphertext()
        records.failDelete = true

        assertThrows(PlatformAdapterException.Failure::class.java) {
            adapter.loadRefreshToken()
        }

        assertTrue(adapter.maintenanceRequired())
    }

    @Test
    fun unreadableAmbiguousCommitRetainsTheOnlyPossibleDecryptionKey() {
        val records = InMemoryOneDriveTokenRecordStorage()
        val ciphers = InMemoryOneDriveTokenCipherBackend()
        val adapter = AndroidOneDriveTokenAdapter(records, ciphers)
        records.throwAfterNextCommit = true
        records.failReadAfterNextCommit = true
        val source = "ambiguous-refresh-token".encodeToByteArray()

        assertThrows(PlatformAdapterException.Failure::class.java) {
            adapter.storeRefreshToken(VaultKernSensitiveString.fromUtf8Bytes(source))
        }

        assertFalse(ciphers.aliases().isEmpty())
        assertTrue(adapter.maintenanceRequired())
    }

    @Test
    fun transientCleanupReadFailureNeverDeletesTheCommittedKey() {
        val records = InMemoryOneDriveTokenRecordStorage()
        val ciphers = InMemoryOneDriveTokenCipherBackend()
        val adapter = AndroidOneDriveTokenAdapter(records, ciphers)
        records.failReadAfterNextCommit = true
        val expected = "durable-refresh-token".encodeToByteArray()

        adapter.storeRefreshToken(
            VaultKernSensitiveString.fromUtf8Bytes(expected.copyOf()),
        )

        assertTrue(adapter.maintenanceRequired())
        assertFalse(ciphers.aliases().isEmpty())
        val loaded = requireNotNull(adapter.loadRefreshToken())
        val actual = loaded.copyUtf8Bytes()
        loaded.close()
        try {
            assertArrayEquals(expected, actual)
        } finally {
            actual.fill(0)
            expected.fill(0)
        }
    }
}

private class InMemoryOneDriveTokenRecordStorage : OneDriveTokenRecordStorage {
    private var record: OneDriveTokenRecord? = null

    var throwAfterNextCommit = false
    var failDelete = false
    var failReadAfterNextCommit = false
    private var failNextRead = false

    override fun write(record: OneDriveTokenRecord) {
        this.record = record.deepCopy()
        if (failReadAfterNextCommit) {
            failReadAfterNextCommit = false
            failNextRead = true
        }
        if (throwAfterNextCommit) {
            throwAfterNextCommit = false
            throw IllegalStateException("injected ambiguous record commit")
        }
    }

    override fun read(): OneDriveTokenRecord? {
        if (failNextRead) {
            failNextRead = false
            throw IllegalStateException("injected record read failure")
        }
        return record?.deepCopy()
    }

    override fun delete() {
        if (failDelete) throw IllegalStateException("injected record delete failure")
        record = null
    }

    override fun discardUncommittedWrite() = Unit

    fun damageCiphertext() {
        val current = requireNotNull(record)
        val damaged = current.ciphertext.copyOf()
        damaged[damaged.lastIndex] = (damaged.last() + 1).toByte()
        record = current.copy(ciphertext = damaged)
    }

    private fun OneDriveTokenRecord.deepCopy(): OneDriveTokenRecord = copy(
        iv = iv.copyOf(),
        ciphertext = ciphertext.copyOf(),
    )
}

private class InMemoryOneDriveTokenCipherBackend : OneDriveTokenCipherBackend {
    private val nextAlias = AtomicInteger()
    private val keys = ConcurrentHashMap<String, SecretKeySpec>()

    override fun prepareEncryption(): PreparedOneDriveTokenCipher {
        val alias = "test-token-${nextAlias.incrementAndGet()}"
        val material = ByteArray(32) { 0x5a }
        val key = try {
            SecretKeySpec(material, "AES")
        } finally {
            material.fill(0)
        }
        keys[alias] = key
        return PreparedOneDriveTokenCipher(
            alias,
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, key)
            },
            UnlockKeySecurityLevel.SOFTWARE,
        )
    }

    override fun prepareDecryption(record: OneDriveTokenRecord): PreparedOneDriveTokenCipher {
        val key = requireNotNull(keys[record.keyAlias])
        return PreparedOneDriveTokenCipher(
            record.keyAlias,
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, record.iv))
            },
            UnlockKeySecurityLevel.SOFTWARE,
        )
    }

    override fun contains(alias: String): Boolean = keys.containsKey(alias)

    override fun delete(alias: String) {
        keys.remove(alias)
    }

    override fun aliases(): Set<String> = keys.keys.toSet()
}
