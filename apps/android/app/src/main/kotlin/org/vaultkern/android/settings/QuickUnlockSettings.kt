package org.vaultkern.android.settings

import java.util.concurrent.atomic.AtomicReference
import org.vaultkern.android.security.UnlockEnrollmentState

data class AndroidDesiredSettings(
    val quickUnlockEnabled: Boolean = false,
)

interface DesiredSettingsStore {
    fun load(): AndroidDesiredSettings
    fun save(settings: AndroidDesiredSettings)
}

fun interface ReconciliationScheduler {
    fun schedule()
}

class QuickUnlockSettingsController(
    private val store: DesiredSettingsStore,
    private val scheduler: ReconciliationScheduler,
) {
    private val schedulingFailure = AtomicReference<String?>(null)

    fun setQuickUnlockEnabled(enabled: Boolean) {
        schedulingFailure.set(null)
        val current = store.load()
        store.save(current.copy(quickUnlockEnabled = enabled))
        try {
            scheduler.schedule()
        } catch (error: Exception) {
            schedulingFailure.set(error.javaClass.simpleName)
        }
    }

    fun lastSchedulingFailure(): String? = schedulingFailure.get()
}

enum class QuickUnlockSettingsApplyOutcome {
    CONVERGED,
    COMMITTED_RECONCILIATION_PENDING,
}

class QuickUnlockSettingsApplier(
    private val controller: QuickUnlockSettingsController,
    private val awaitReconciliation: () -> Unit,
) {
    fun apply(enabled: Boolean): QuickUnlockSettingsApplyOutcome {
        controller.setQuickUnlockEnabled(enabled)
        if (controller.lastSchedulingFailure() != null) {
            return QuickUnlockSettingsApplyOutcome.COMMITTED_RECONCILIATION_PENDING
        }
        return try {
            awaitReconciliation()
            QuickUnlockSettingsApplyOutcome.CONVERGED
        } catch (_: Exception) {
            QuickUnlockSettingsApplyOutcome.COMMITTED_RECONCILIATION_PENDING
        }
    }
}

interface QuickUnlockActualState {
    fun enrollmentState(): UnlockEnrollmentState
    fun vaultIsUnlocked(): Boolean
    fun revokeAll()
}

enum class QuickUnlockReconciliationOutcome {
    ALREADY_CONVERGED,
    ENROLLED,
    REVOKED,
    SKIPPED_LOCKED,
    WAITING_FOR_CREDENTIAL,
}

class QuickUnlockReconciler(
    private val desiredSettings: DesiredSettingsStore,
    private val actualState: QuickUnlockActualState,
) {
    @Synchronized
    fun reconcile(enrollCurrentVault: (() -> Unit)? = null): QuickUnlockReconciliationOutcome {
        val desired = desiredSettings.load()
        if (!desired.quickUnlockEnabled) {
            actualState.revokeAll()
            return QuickUnlockReconciliationOutcome.REVOKED
        }

        if (enrollCurrentVault != null) {
            if (!actualState.vaultIsUnlocked()) {
                return QuickUnlockReconciliationOutcome.SKIPPED_LOCKED
            }
            enrollCurrentVault()
            return QuickUnlockReconciliationOutcome.ENROLLED
        }
        if (actualState.enrollmentState() == UnlockEnrollmentState.ENROLLED) {
            return QuickUnlockReconciliationOutcome.ALREADY_CONVERGED
        }
        return if (actualState.vaultIsUnlocked()) {
            QuickUnlockReconciliationOutcome.WAITING_FOR_CREDENTIAL
        } else {
            QuickUnlockReconciliationOutcome.SKIPPED_LOCKED
        }
    }
}
