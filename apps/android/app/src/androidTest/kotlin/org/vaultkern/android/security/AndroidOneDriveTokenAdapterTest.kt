package org.vaultkern.android.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.OneDriveTokenAdapter
import org.vaultkern.core.ResidentPlatform
import org.vaultkern.core.UnlockBlobAdapter
import org.vaultkern.core.VaultKernSensitiveBytes
import org.vaultkern.core.VaultKernSensitiveString
import org.vaultkern.core.VaultSession
import org.vaultkern.core.VaultSessionConfig

@RunWith(AndroidJUnit4::class)
class AndroidOneDriveTokenAdapterTest {
    @Test
    fun tokenCommitAndStorageReconciliationAreSerialized() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val nonce = UUID.randomUUID().toString()
        val store = AtomicOneDriveTokenRecordStore(context, "onedrive-token-race-$nonce")
        val backend = BlockingOneDriveTokenCipherBackend()
        val adapter = AndroidOneDriveTokenAdapter(store, backend)
        val expected = "refresh-token-$nonce".toByteArray()
        val source = expected.copyOf()
        val storeFailure = AtomicReference<Throwable?>()
        val reconcileFailure = AtomicReference<Throwable?>()
        backend.blockEncryption = true
        val storeThread = Thread {
            runCatching {
                adapter.storeRefreshToken(VaultKernSensitiveString.fromUtf8Bytes(source))
            }.exceptionOrNull()?.let(storeFailure::set)
        }
        val reconcileThread = Thread {
            runCatching { adapter.reconcileStorage() }.exceptionOrNull()?.let(reconcileFailure::set)
        }

        val reconciledInsideCommit = try {
            storeThread.start()
            assertTrue(backend.encryptionPrepared.await(5, TimeUnit.SECONDS))
            reconcileThread.start()
            backend.aliasesReadDuringCommit.await(500, TimeUnit.MILLISECONDS)
        } finally {
            backend.releaseEncryption.countDown()
            storeThread.join(5_000)
            reconcileThread.join(5_000)
        }

        try {
            assertFalse(reconciledInsideCommit)
            storeFailure.get()?.let { throw AssertionError("token store failed", it) }
            reconcileFailure.get()?.let { throw AssertionError("reconciliation failed", it) }
            val loaded = adapter.loadRefreshToken() ?: error("stored token missing")
            val actual = loaded.copyUtf8Bytes()
            loaded.close()
            try {
                assertArrayEquals(expected, actual)
            } finally {
                actual.fill(0)
            }
        } finally {
            expected.fill(0)
            source.fill(0)
            runCatching { adapter.deleteRefreshToken() }
            store.deleteDirectory()
        }
    }

    @Test
    fun refreshTokenSurvivesAdapterRestartWithoutAJvmString() {
        val fixture = fixture()
        try {
            val source = "refresh-token-${UUID.randomUUID()}".toByteArray()
            val expected = source.copyOf()
            fixture.adapter.storeRefreshToken(VaultKernSensitiveString.fromUtf8Bytes(source))
            assertArrayEquals(ByteArray(source.size), source)

            val restarted = AndroidOneDriveTokenAdapter(fixture.store, fixture.backend)
            val loaded = restarted.loadRefreshToken() ?: error("stored token missing")
            val actual = loaded.copyUtf8Bytes()
            loaded.close()

            assertArrayEquals(expected, actual)
            restarted.deleteRefreshToken()
            assertFalse(fixture.store.exists())
            assertTrue(fixture.backend.aliases().isEmpty())
            actual.fill(0)
            expected.fill(0)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun invalidCiphertextIsRevokedAndRequiresAccountReconnect() {
        val fixture = fixture()
        try {
            val source = "refresh-token-${UUID.randomUUID()}".toByteArray()
            fixture.adapter.storeRefreshToken(VaultKernSensitiveString.fromUtf8Bytes(source))
            val record = fixture.store.read() ?: error("stored token missing")
            val damaged = record.ciphertext.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }
            fixture.store.write(record.copy(ciphertext = damaged))
            damaged.fill(0)

            try {
                fixture.adapter.loadRefreshToken()
                error("damaged token must fail")
            } catch (_: PlatformAdapterException.Failure) {
                // Expected: the account must be connected again.
            }
            assertFalse(fixture.store.exists())
            assertTrue(fixture.backend.aliases().isEmpty())
        } finally {
            fixture.close()
        }
    }

    @Test
    fun uniffiCallbackClosesTheSensitiveTokenOwnerAfterLowering() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val root = java.io.File(context.noBackupFilesDir, "onedrive-callback-${UUID.randomUUID()}")
        val returned = VaultKernSensitiveString.fromUtf8Bytes("callback-token".toByteArray())
        val adapter = object : OneDriveTokenAdapter {
            override fun loadRefreshToken(): VaultKernSensitiveString = returned
            override fun storeRefreshToken(token: VaultKernSensitiveString) = token.close()
            override fun deleteRefreshToken() = Unit
        }
        try {
            VaultSession(
                VaultSessionConfig(
                    ResidentPlatform.ANDROID,
                    root.resolve("state").absolutePath,
                    root.resolve("temporary").absolutePath,
                ),
                CallbackTestUnlockBlobAdapter(),
                adapter,
            ).close()

            assertTrue(returned.copyUtf8Bytes().isEmpty())
        } finally {
            returned.close()
            root.deleteRecursively()
        }
    }

    private fun fixture(): TokenFixture {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val nonce = UUID.randomUUID().toString()
        val store = AtomicOneDriveTokenRecordStore(context, "onedrive-token-test-$nonce")
        val backend = AndroidKeystoreOneDriveTokenCipherBackend(
            context,
            aliasPrefix = "vaultkern.test.onedrive.$nonce.",
        )
        return TokenFixture(store, backend, AndroidOneDriveTokenAdapter(store, backend))
    }
}

private class BlockingOneDriveTokenCipherBackend : OneDriveTokenCipherBackend {
    private val keys = ConcurrentHashMap<String, SecretKeySpec>()
    val encryptionPrepared = CountDownLatch(1)
    val aliasesReadDuringCommit = CountDownLatch(1)
    val releaseEncryption = CountDownLatch(1)

    @Volatile
    var blockEncryption = false

    override fun prepareEncryption(): PreparedOneDriveTokenCipher {
        val alias = "test-${UUID.randomUUID()}"
        val key = SecretKeySpec(ByteArray(32) { 7 }, "AES")
        keys[alias] = key
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
        if (blockEncryption) {
            encryptionPrepared.countDown()
            check(releaseEncryption.await(5, TimeUnit.SECONDS)) {
                "timed out releasing token encryption"
            }
        }
        return PreparedOneDriveTokenCipher(alias, cipher, UnlockKeySecurityLevel.SOFTWARE)
    }

    override fun prepareDecryption(record: OneDriveTokenRecord): PreparedOneDriveTokenCipher {
        val key = requireNotNull(keys[record.keyAlias])
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, record.iv))
        }
        return PreparedOneDriveTokenCipher(
            record.keyAlias,
            cipher,
            UnlockKeySecurityLevel.SOFTWARE,
        )
    }

    override fun contains(alias: String): Boolean = keys.containsKey(alias)

    override fun delete(alias: String) {
        keys.remove(alias)
    }

    override fun aliases(): Set<String> {
        if (blockEncryption && releaseEncryption.count > 0) {
            aliasesReadDuringCommit.countDown()
        }
        return keys.keys.toSet()
    }
}

private class CallbackTestUnlockBlobAdapter : UnlockBlobAdapter {
    override fun supportsUnlockBlob(): Boolean = false
    override fun authorize(reason: String) = Unit
    override fun storeRequiresUserPresence(): Boolean = false
    override fun loadRequiresUserPresence(): Boolean = false
    override fun authorizeStoreUserPresence() = Unit
    override fun storeBlob(key: String, value: VaultKernSensitiveBytes) = value.close()
    override fun loadBlob(key: String): VaultKernSensitiveBytes? = null
    override fun containsBlob(key: String): Boolean = false
    override fun deleteBlob(key: String) = Unit
}

private class TokenFixture(
    val store: AtomicOneDriveTokenRecordStore,
    val backend: OneDriveTokenCipherBackend,
    val adapter: AndroidOneDriveTokenAdapter,
) {
    fun close() {
        runCatching { adapter.deleteRefreshToken() }
        backend.aliases().forEach { alias -> runCatching { backend.delete(alias) } }
        store.deleteDirectory()
    }
}
