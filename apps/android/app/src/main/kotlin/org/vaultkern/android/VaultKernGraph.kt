package org.vaultkern.android

import android.content.Context
import androidx.biometric.BiometricManager
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.Future
import org.vaultkern.android.security.AndroidKeystoreUnlockCipherBackend
import org.vaultkern.android.security.AndroidUnlockBlobAdapter
import org.vaultkern.android.security.AtomicUnlockBlobRecordStore
import org.vaultkern.android.security.ProcessBiometricGate
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.settings.AtomicDesiredSettingsStore
import org.vaultkern.android.settings.CurrentVaultQuickUnlockActualState
import org.vaultkern.android.settings.QuickUnlockReconciler
import org.vaultkern.android.settings.QuickUnlockSettingsController
import org.vaultkern.android.settings.ReconciliationScheduler
import org.vaultkern.android.unlock.CorePostUnlockReconciliation
import org.vaultkern.android.unlock.UnlockCoordinator
import org.vaultkern.android.vault.VaultEditorWorkflow
import org.vaultkern.android.vault.VaultKernResidentVaultPort
import org.vaultkern.core.OneDriveTokenAdapter
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.ResidentPlatform
import org.vaultkern.core.VaultKernSensitiveString
import org.vaultkern.core.VaultSession
import org.vaultkern.core.VaultSessionConfig

class VaultKernGraph(context: Context) {
    private val applicationContext = context.applicationContext
    private val reconciliationExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "vaultkern-settings-reconciliation")
    }
    private val records = AtomicUnlockBlobRecordStore(applicationContext)
    private val biometricGate = ProcessBiometricGate(applicationContext)

    val unlockBlobAdapter = AndroidUnlockBlobAdapter(
        records = records,
        cipherBackend = AndroidKeystoreUnlockCipherBackend(applicationContext),
        biometricGate = biometricGate,
        userVerificationGate = biometricGate,
        requireHardwareBacked = !BuildConfig.DEBUG,
        biometricAvailable = {
            BiometricManager.from(applicationContext).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG,
            ) == BiometricManager.BIOMETRIC_SUCCESS
        },
    )
    val desiredSettings = AtomicDesiredSettingsStore(applicationContext)
    val session = VaultSession(
        VaultSessionConfig(
            ResidentPlatform.ANDROID,
            File(applicationContext.noBackupFilesDir, "resident-state").absolutePath,
            File(applicationContext.noBackupFilesDir, "resident-temporary").absolutePath,
        ),
        unlockBlobAdapter,
        UnconfiguredOneDriveTokenAdapter(),
    )

    private val residentUnlockPort = VaultKernResidentUnlockPort(session)
    private val actualState = CurrentVaultQuickUnlockActualState(
        session = session,
        storedState = unlockBlobAdapter::enrollmentState,
        revokeAll = unlockBlobAdapter::deleteAll,
    )
    private val reconciler = QuickUnlockReconciler(desiredSettings, actualState)

    val unlockCoordinator = UnlockCoordinator(
        residentUnlockPort,
        CorePostUnlockReconciliation(reconciler, unlockBlobAdapter::reconcileStorage),
    )
    val settingsController = QuickUnlockSettingsController(
        desiredSettings,
        ReconciliationScheduler { scheduleReconciliation() },
    )
    val vaultWorkflow = VaultEditorWorkflow(VaultKernResidentVaultPort(session))

    @Volatile
    private var lastReconciliation: Future<*>? = null

    init {
        scheduleReconciliation()
    }

    fun awaitScheduledReconciliation() {
        lastReconciliation?.get()
    }

    fun currentEnrollmentState(): UnlockEnrollmentState = actualState.enrollmentState()

    fun currentKeySecurityLevel() =
        unlockBlobAdapter.securityLevel().takeIf {
            currentEnrollmentState() == UnlockEnrollmentState.ENROLLED
        }

    private fun scheduleReconciliation() {
        lastReconciliation = reconciliationExecutor.submit {
            CorePostUnlockReconciliation(
                reconciler,
                unlockBlobAdapter::reconcileStorage,
            ).reconcile(null)
        }
    }
}

private class UnconfiguredOneDriveTokenAdapter : OneDriveTokenAdapter {
    override fun loadRefreshToken(): VaultKernSensitiveString? = null

    override fun storeRefreshToken(token: VaultKernSensitiveString) {
        token.close()
        throw PlatformAdapterException.Failure("OneDrive account is not configured")
    }

    override fun deleteRefreshToken() = Unit
}
