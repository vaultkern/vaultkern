package org.vaultkern.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import android.system.Os
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.vaultkern.android.vault.VaultKernResidentVaultPort
import org.vaultkern.android.vault.VaultSaveStatus
import org.vaultkern.core.OneDriveTokenAdapter
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.ResidentPlatform
import org.vaultkern.core.UnlockBlobAdapter
import org.vaultkern.core.VaultKernSensitiveBytes
import org.vaultkern.core.VaultKernSensitiveString
import org.vaultkern.core.VaultSession
import org.vaultkern.core.VaultSessionConfig

@RunWith(AndroidJUnit4::class)
class ResidentVaultFlowTest {
    @Test
    fun browseEditAndSaveRoundTripUsesTheResidentCore() {
        withOpenedFixture("m2-save") { root, vault, session ->
            val port = VaultKernResidentVaultPort(session)
            val first = port.listEntries().first()
            val draft = port.readEntry(first.id)
            val editedTitle = "${draft.title} (Android M2)"
            val originalMode = Os.stat(vault.absolutePath).st_mode

            val result = port.editAndSave(draft.copy(title = editedTitle))

            assertEquals(VaultSaveStatus.SAVED, result.status)
            assertTrue(vault.isFile)
            assertEquals(originalMode, Os.stat(vault.absolutePath).st_mode)
            val reloaded = newSession(root.resolve("reload"))
            try {
                val handle = reloaded.openVault(vault.absolutePath)
                unlock(reloaded, handle.vaultId)
                val reloadedPort = VaultKernResidentVaultPort(reloaded)
                val saved = reloadedPort.readEntry(first.id)
                assertEquals(editedTitle, saved.title)
                assertEquals(draft.username, saved.username)
                assertEquals(draft.password, saved.password)
                assertEquals(draft.url, saved.url)
                assertEquals(draft.notes, saved.notes)
                assertEquals(draft.totpUri, saved.totpUri)
                assertEquals(draft.customFields, saved.customFields)
            } finally {
                reloaded.close()
            }
        }
    }

    @Test
    fun preRenameFingerprintMismatchPreservesForeignFileAndCreatesConflictCopy() {
        withOpenedFixture("m2-conflict") { root, vault, session ->
            val port = VaultKernResidentVaultPort(session)
            val first = port.listEntries().first()
            val draft = port.readEntry(first.id).copy(title = "Android conflict edit")
            val foreignBytes = vault.readBytes() + "foreign-writer-marker".encodeToByteArray()
            vault.writeBytes(foreignBytes)

            val result = port.editAndSave(draft)

            assertEquals(VaultSaveStatus.CONFLICT_COPY, result.status)
            assertArrayEquals(foreignBytes, vault.readBytes())
            assertNotNull(result.conflictCopyPath)
            val conflictPath = result.conflictCopyPath!!
            assertTrue(File(conflictPath).isFile)
            val conflictSession = newSession(root.resolve("conflict-reload"))
            try {
                val handle = conflictSession.openVault(conflictPath)
                unlock(conflictSession, handle.vaultId)
                val conflictPort = VaultKernResidentVaultPort(conflictSession)
                assertEquals("Android conflict edit", conflictPort.readEntry(first.id).title)
            } finally {
                conflictSession.close()
            }
        }
    }

    private fun withOpenedFixture(
        label: String,
        body: (File, File, VaultSession) -> Unit,
    ) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val root = File(context.noBackupFilesDir, "$label-${System.nanoTime()}")
        val vault = File(root, "vault.kdbx")
        root.mkdirs()
        instrumentation.context.assets.open("keepassxc-2.7.6-kdbx4.1.kdbx").use { input ->
            vault.outputStream().use(input::copyTo)
        }
        val session = newSession(root.resolve("resident"))
        try {
            val handle = session.openVault(vault.absolutePath)
            unlock(session, handle.vaultId)
            body(root, vault, session)
        } finally {
            session.close()
            root.deleteRecursively()
        }
    }

    private fun newSession(root: File): VaultSession = VaultSession(
        VaultSessionConfig(
            ResidentPlatform.ANDROID,
            root.resolve("state").absolutePath,
            root.resolve("temporary").absolutePath,
        ),
        MemoryUnlockBlobAdapter(),
        NoOneDriveTokenAdapterM2(),
    )

    private fun unlock(session: VaultSession, vaultId: String) {
        VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
            session.unlock().use { unlock ->
                unlock.unlockVault(vaultId, password, null, false)
            }
        }
    }

    companion object {
        private const val FIXTURE_PASSWORD = "vaultkern-external-fixture"
    }
}

private class MemoryUnlockBlobAdapter : UnlockBlobAdapter {
    private val values = ConcurrentHashMap<String, ByteArray>()
    override fun supportsUnlockBlob(): Boolean = true
    override fun authorize(reason: String) = Unit
    override fun storeRequiresUserPresence(): Boolean = false
    override fun loadRequiresUserPresence(): Boolean = false
    override fun authorizeStoreUserPresence() = Unit
    override fun storeBlob(key: String, value: VaultKernSensitiveBytes) {
        values.put(key, value.copyBytes())?.fill(0)
        value.close()
    }
    override fun loadBlob(key: String): VaultKernSensitiveBytes? =
        values[key]?.copyOf()?.let(VaultKernSensitiveBytes::fromByteArray)
    override fun containsBlob(key: String): Boolean = values.containsKey(key)
    override fun deleteBlob(key: String) {
        values.remove(key)?.fill(0)
    }
}

private class NoOneDriveTokenAdapterM2 : OneDriveTokenAdapter {
    override fun loadRefreshToken(): VaultKernSensitiveString? = null
    override fun storeRefreshToken(token: VaultKernSensitiveString) {
        token.close()
        throw PlatformAdapterException.Failure("OneDrive is not configured")
    }
    override fun deleteRefreshToken() = Unit
}
