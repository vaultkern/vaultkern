package org.vaultkern.android.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
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
