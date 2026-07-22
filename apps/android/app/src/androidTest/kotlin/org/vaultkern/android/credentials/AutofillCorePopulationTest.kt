package org.vaultkern.android.credentials

import android.view.View
import android.view.autofill.AutofillValue
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
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
class AutofillCorePopulationTest {
    @Test
    fun residentCorePopulatesPasswordAndCurrentTotpDataset() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val root = File(context.noBackupFilesDir, "m3-autofill-${System.nanoTime()}")
        val vault = File(root, "vault.kdbx")
        root.mkdirs()
        try {
            instrumentation.context.assets.open("keepassxc-2.7.6-kdbx4.1.kdbx").use { input ->
                vault.outputStream().use(input::copyTo)
            }
            newAutofillSession(root.resolve("resident")).use { session ->
                val handle = session.openVault(vault.absolutePath)
                VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
                    session.unlock().use { unlock ->
                        unlock.unlockVault(handle.vaultId, password, null, false)
                    }
                }
                val editor = VaultKernResidentVaultPort(session)
                val draft = editor.readEntry(editor.listEntries().first().id)
                assertEquals(
                    VaultSaveStatus.SAVED,
                    editor.editAndSave(draft.copy(totpUri = TEST_TOTP_URI)).status,
                )
                val port = AutofillVaultPort(session)
                val candidate = port.candidates(requireTotp = true).first()
                val credential = port.credential(candidate.entryId)
                val ids = AutofillFieldIds(
                    username = View(context).apply { id = View.generateViewId() }.autofillId,
                    password = View(context).apply { id = View.generateViewId() }.autofillId,
                    totp = View(context).apply { id = View.generateViewId() }.autofillId,
                )

                val populated = AutofillDatasetFactory.populated(context, ids, credential)

                assertNotNull(populated.dataset)
                assertEquals(AutofillValue.forText(credential.username), populated.values[ids.username])
                assertEquals(AutofillValue.forText(credential.password), populated.values[ids.password])
                assertEquals(AutofillValue.forText(credential.totp), populated.values[ids.totp])
                assertTrue(credential.totp?.matches(Regex("[0-9]{6,8}")) == true)
            }
        } finally {
            root.deleteRecursively()
        }
    }

    private fun newAutofillSession(root: File): VaultSession = VaultSession(
        VaultSessionConfig(
            ResidentPlatform.ANDROID,
            root.resolve("state").absolutePath,
            root.resolve("temporary").absolutePath,
        ),
        AutofillTestUnlockBlobAdapter(),
        AutofillTestOneDriveAdapter(),
    )

    companion object {
        private const val FIXTURE_PASSWORD = "vaultkern-external-fixture"
        private const val TEST_TOTP_URI =
            "otpauth://totp/VaultKern:alice?secret=JBSWY3DPEHPK3PXP&issuer=VaultKern"
    }
}

private class AutofillTestUnlockBlobAdapter : UnlockBlobAdapter {
    override fun supportsUnlockBlob(): Boolean = true
    override fun authorize(reason: String) = Unit
    override fun storeRequiresUserPresence(): Boolean = false
    override fun loadRequiresUserPresence(): Boolean = false
    override fun authorizeStoreUserPresence() = Unit
    override fun storeBlob(key: String, value: VaultKernSensitiveBytes) = value.close()
    override fun loadBlob(key: String): VaultKernSensitiveBytes? = null
    override fun containsBlob(key: String): Boolean = false
    override fun deleteBlob(key: String) = Unit
}

private class AutofillTestOneDriveAdapter : OneDriveTokenAdapter {
    override fun loadRefreshToken(): VaultKernSensitiveString? = null
    override fun storeRefreshToken(token: VaultKernSensitiveString) {
        token.close()
        throw PlatformAdapterException.Failure("OneDrive is not configured")
    }
    override fun deleteRefreshToken() = Unit
}
