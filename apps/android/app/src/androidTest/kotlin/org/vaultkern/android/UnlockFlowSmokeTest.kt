package org.vaultkern.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.settings.CurrentVaultQuickUnlockActualState
import org.vaultkern.core.OneDriveTokenAdapter
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.ResidentPlatform
import org.vaultkern.core.UnlockBlobAdapter
import org.vaultkern.core.UnlockBlobStatusDto
import org.vaultkern.core.VaultKernSensitiveBytes
import org.vaultkern.core.VaultKernSensitiveString
import org.vaultkern.core.VaultSession
import org.vaultkern.core.VaultSessionConfig

@RunWith(AndroidJUnit4::class)
class UnlockFlowSmokeTest {
    @Test
    fun interactiveUnlockEnrollBiometricUnlockAndRevokeUseTheResidentCore() {
        assertEquals(34, android.os.Build.VERSION.SDK_INT)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val root = File(context.noBackupFilesDir, "m1-flow-${System.nanoTime()}")
        val vault = File(root, "m1.kdbx")
        root.mkdirs()
        instrumentation.context.assets.open("keepassxc-2.7.6-kdbx4.1.kdbx").use { input ->
            vault.outputStream().use(input::copyTo)
        }
        val adapter = InMemoryUnlockBlobAdapter()
        val session = VaultSession(
            VaultSessionConfig(
                ResidentPlatform.ANDROID,
                File(root, "state").absolutePath,
                File(root, "temporary").absolutePath,
            ),
            adapter,
            NoOneDriveTokenAdapter(),
        )

        try {
            val handle = session.openVault(vault.absolutePath)
            VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
                session.unlock().unlockVault(handle.vaultId, password, null, false)
            }
            assertTrue(session.sessionState().unlocked)

            VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
                session.unlock().enroll(password, null, false)
            }
            assertEquals(UnlockEnrollmentState.ENROLLED, adapter.state)
            assertFalse(session.lockSession().unlocked)
            assertEquals(
                UnlockBlobStatusDto.UNLOCKED,
                session.unlock().unlockWithBlob(false).status,
            )

            session.unlock().revoke()
            assertEquals(UnlockEnrollmentState.NOT_ENROLLED, adapter.state)
            session.lockSession()
            assertEquals(
                UnlockBlobStatusDto.NOT_ENROLLED,
                session.unlock().unlockWithBlob(false).status,
            )
        } finally {
            session.close()
            root.deleteRecursively()
        }
    }

    @Test
    fun enrollmentStateIsScopedToTheCurrentVaultInsteadOfAnyStoredBlob() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val root = File(context.noBackupFilesDir, "m1-two-vaults-${System.nanoTime()}")
        val first = File(root, "first.kdbx")
        val second = File(root, "second.kdbx")
        root.mkdirs()
        instrumentation.context.assets.open("keepassxc-2.7.6-kdbx4.1.kdbx").use { input ->
            first.outputStream().use(input::copyTo)
        }
        first.copyTo(second)
        val adapter = InMemoryUnlockBlobAdapter()
        val session = VaultSession(
            VaultSessionConfig(
                ResidentPlatform.ANDROID,
                File(root, "state").absolutePath,
                File(root, "temporary").absolutePath,
            ),
            adapter,
            NoOneDriveTokenAdapter(),
        )

        try {
            val firstHandle = session.openVault(first.absolutePath)
            VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
                session.unlock().unlockVault(firstHandle.vaultId, password, null, false)
            }
            VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
                session.unlock().enroll(password, null, false)
            }
            assertEquals(UnlockEnrollmentState.ENROLLED, adapter.state)

            val secondHandle = session.openVault(second.absolutePath)
            VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
                session.unlock().unlockVault(secondHandle.vaultId, password, null, false)
            }
            val actual = CurrentVaultQuickUnlockActualState(
                session = session,
                storedState = adapter::enrollmentState,
                revokeAll = adapter::deleteAll,
            )

            assertEquals(UnlockEnrollmentState.NOT_ENROLLED, actual.enrollmentState())
        } finally {
            session.close()
            root.deleteRecursively()
        }
    }

    @Test
    fun invalidationStateRemainsScopedToTheVaultWhoseBlobFailed() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val root = File(context.noBackupFilesDir, "m1-invalidated-vault-${System.nanoTime()}")
        val first = File(root, "first.kdbx")
        val second = File(root, "second.kdbx")
        root.mkdirs()
        instrumentation.context.assets.open("keepassxc-2.7.6-kdbx4.1.kdbx").use { input ->
            first.outputStream().use(input::copyTo)
        }
        first.copyTo(second)
        val adapter = InMemoryUnlockBlobAdapter()
        val session = VaultSession(
            VaultSessionConfig(
                ResidentPlatform.ANDROID,
                File(root, "state").absolutePath,
                File(root, "temporary").absolutePath,
            ),
            adapter,
            NoOneDriveTokenAdapter(),
        )

        try {
            val firstHandle = session.openVault(first.absolutePath)
            VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
                session.unlock().unlockVault(firstHandle.vaultId, password, null, false)
            }
            VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
                session.unlock().enroll(password, null, false)
            }
            adapter.invalidateOnlyStoredBlob()
            val actual = CurrentVaultQuickUnlockActualState(
                session = session,
                storedState = adapter::enrollmentState,
                revokeAll = adapter::deleteAll,
            )
            assertEquals(UnlockEnrollmentState.INVALIDATED, actual.enrollmentState())

            val secondHandle = session.openVault(second.absolutePath)
            VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
                session.unlock().unlockVault(secondHandle.vaultId, password, null, false)
            }
            assertEquals(UnlockEnrollmentState.NOT_ENROLLED, actual.enrollmentState())
        } finally {
            session.close()
            root.deleteRecursively()
        }
    }

    companion object {
        private const val FIXTURE_PASSWORD = "vaultkern-external-fixture"
    }
}

private class InMemoryUnlockBlobAdapter : UnlockBlobAdapter {
    private val values = ConcurrentHashMap<String, ByteArray>()
    private val invalidated = ConcurrentHashMap.newKeySet<String>()
    var state = UnlockEnrollmentState.NOT_ENROLLED
        private set

    override fun supportsUnlockBlob(): Boolean = true
    override fun authorize(reason: String) = Unit
    override fun storeRequiresUserPresence(): Boolean = false
    override fun loadRequiresUserPresence(): Boolean = false
    override fun authorizeStoreUserPresence() = Unit

    override fun storeBlob(key: String, value: VaultKernSensitiveBytes) {
        values.put(key, value.copyBytes())?.fill(0)
        value.close()
        invalidated.remove(key)
        state = UnlockEnrollmentState.ENROLLED
    }

    override fun loadBlob(key: String): VaultKernSensitiveBytes? =
        values[key]?.copyOf()?.let(VaultKernSensitiveBytes::fromByteArray)

    override fun containsBlob(key: String): Boolean = values.containsKey(key)

    override fun deleteBlob(key: String) {
        values.remove(key)?.fill(0)
        invalidated.remove(key)
        state = UnlockEnrollmentState.NOT_ENROLLED
    }

    fun deleteAll() {
        values.values.forEach { it.fill(0) }
        values.clear()
        invalidated.clear()
        state = UnlockEnrollmentState.NOT_ENROLLED
    }

    fun enrollmentState(key: String): UnlockEnrollmentState = when {
        invalidated.contains(key) -> UnlockEnrollmentState.INVALIDATED
        values.containsKey(key) -> UnlockEnrollmentState.ENROLLED
        else -> UnlockEnrollmentState.NOT_ENROLLED
    }

    fun invalidateOnlyStoredBlob() {
        val key = values.keys.single()
        values.remove(key)?.fill(0)
        invalidated.add(key)
        state = UnlockEnrollmentState.INVALIDATED
    }
}

private class NoOneDriveTokenAdapter : OneDriveTokenAdapter {
    override fun loadRefreshToken(): VaultKernSensitiveString? = null
    override fun storeRefreshToken(token: VaultKernSensitiveString) {
        token.close()
        throw PlatformAdapterException.Failure("OneDrive is not configured")
    }
    override fun deleteRefreshToken() = Unit
}
