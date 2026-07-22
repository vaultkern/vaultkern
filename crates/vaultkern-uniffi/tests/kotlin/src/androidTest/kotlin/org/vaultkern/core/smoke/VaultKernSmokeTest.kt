package org.vaultkern.core.smoke

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.vaultkern.core.OneDriveTokenAdapter
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.ResidentPlatform
import org.vaultkern.core.UnlockBlobAdapter
import org.vaultkern.core.UnlockBlobStatusDto
import org.vaultkern.core.VaultKernSensitiveBytes
import org.vaultkern.core.VaultKernSensitiveString
import org.vaultkern.core.VaultSession
import org.vaultkern.core.VaultSessionConfig

private class FakeUnlockBlobAdapter : UnlockBlobAdapter {
    private val blobs = ConcurrentHashMap<String, ByteArray>()
    private val cancelNextLoad = AtomicBoolean(false)

    override fun supportsUnlockBlob() = true
    override fun authorize(reason: String) = Unit
    override fun storeRequiresUserPresence() = false
    override fun loadRequiresUserPresence() = false
    override fun authorizeStoreUserPresence() = Unit

    fun cancelNextBlobLoad() {
        cancelNextLoad.set(true)
    }

    override fun storeBlob(key: String, value: VaultKernSensitiveBytes) {
        val owned = value.copyBytes()
        value.close()
        blobs.put(key, owned)?.fill(0)
    }

    override fun loadBlob(key: String): VaultKernSensitiveBytes? {
        if (cancelNextLoad.getAndSet(false)) {
            throw PlatformAdapterException.Cancelled()
        }
        return blobs[key]?.copyOf()?.let { VaultKernSensitiveBytes.fromByteArray(it) }
    }

    override fun containsBlob(key: String) = blobs.containsKey(key)

    override fun deleteBlob(key: String) {
        blobs.remove(key)?.fill(0)
    }
}

private class FakeOneDriveTokenAdapter : OneDriveTokenAdapter {
    private var token: VaultKernSensitiveString? = null

    override fun loadRefreshToken(): VaultKernSensitiveString? =
        token?.reveal()?.let { VaultKernSensitiveString.fromString(it) }

    override fun storeRefreshToken(token: VaultKernSensitiveString) {
        this.token?.close()
        this.token = VaultKernSensitiveString.fromString(token.reveal())
        token.close()
    }

    override fun deleteRefreshToken() {
        token?.close()
        token = null
    }
}

@RunWith(AndroidJUnit4::class)
class VaultKernSmokeTest {
    @Test
    fun opensListsAndExercisesUnlockBlobOnAndroid14() {
        assertEquals(34, android.os.Build.VERSION.SDK_INT)
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.noBackupFilesDir, "vaultkern-uniffi-smoke-${System.nanoTime()}")
        val vault = File(root, "smoke.kdbx")
        root.mkdirs()
        context.assets.open("keepassxc-2.7.6-kdbx4.1.kdbx").use { input ->
            vault.outputStream().use(input::copyTo)
        }

        val password = VaultKernSensitiveString.fromString("vaultkern-external-fixture")
        val adapter = FakeUnlockBlobAdapter()
        val session = VaultSession(
            VaultSessionConfig(
                ResidentPlatform.ANDROID,
                File(root, "state").absolutePath,
                File(root, "temporary").absolutePath,
            ),
            adapter,
            FakeOneDriveTokenAdapter(),
        )

        try {
            val unlock = session.unlock()
            val opened = session.openVault(vault.absolutePath)
            unlock.unlockVault(opened.vaultId, password, null, false)
            assertTrue(session.listEntries(opened.vaultId).isNotEmpty())

            unlock.enroll(password, null, false)
            assertFalse(session.lockSession().unlocked)
            val blobUnlocked = unlock.unlockWithBlob(false)
            assertEquals(UnlockBlobStatusDto.UNLOCKED, blobUnlocked.status)
            assertTrue(blobUnlocked.state.unlocked)
            assertTrue(session.listEntries(opened.vaultId).isNotEmpty())

            session.lockSession()
            adapter.cancelNextBlobLoad()
            assertEquals(
                UnlockBlobStatusDto.CANCELLED,
                unlock.unlockWithBlob(false).status,
            )
            assertEquals(
                UnlockBlobStatusDto.UNLOCKED,
                unlock.unlockWithBlob(false).status,
            )
            unlock.revoke()
            session.lockSession()
            assertEquals(
                UnlockBlobStatusDto.NOT_ENROLLED,
                unlock.unlockWithBlob(false).status,
            )
            session.closeVault(opened.vaultId)
        } finally {
            session.close()
            password.close()
            root.deleteRecursively()
        }
    }
}
