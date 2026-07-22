package org.vaultkern.android.unlock

import java.util.concurrent.atomic.AtomicReference
import org.vaultkern.android.settings.QuickUnlockReconciler

enum class UnlockAttemptOutcome {
    UNLOCKED,
    NOT_ENROLLED,
    CANCELLED,
    OPEN_APP_REQUIRED,
    CREDENTIAL_REQUIRED,
    UNSUPPORTED,
}

interface ResidentUnlockPort {
    fun interactiveUnlock(path: String, credential: CharArray)
    fun quickUnlock(): UnlockAttemptOutcome
    fun enrollQuickUnlock(credential: CharArray)
}

internal fun reconcilePlatformStores(vararg stores: () -> Unit) {
    var failure: Exception? = null
    stores.forEach { reconcile ->
        try {
            reconcile()
        } catch (error: Exception) {
            if (failure == null) failure = error else failure?.addSuppressed(error)
        }
    }
    failure?.let { throw it }
}

fun interface PostUnlockReconciliation {
    fun reconcile(enrollCurrentVault: (() -> Unit)?)
}

class CorePostUnlockReconciliation(
    private val delegate: QuickUnlockReconciler,
    private val reconcilePlatformStorage: () -> Unit = {},
) : PostUnlockReconciliation {
    override fun reconcile(enrollCurrentVault: (() -> Unit)?) {
        var failure = runCatching { reconcilePlatformStorage() }.exceptionOrNull()
        try {
            delegate.reconcile(enrollCurrentVault)
        } catch (error: Exception) {
            failure = combineFailures(failure, error)
        } finally {
            val cleanupFailure = runCatching { reconcilePlatformStorage() }.exceptionOrNull()
            failure = combineFailures(failure, cleanupFailure)
        }
        failure?.let { throw it }
    }

    private fun combineFailures(primary: Throwable?, additional: Throwable?): Throwable? {
        if (primary == null) return additional
        if (additional != null && additional !== primary) primary.addSuppressed(additional)
        return primary
    }
}

class UnlockCoordinator(
    private val port: ResidentUnlockPort,
    private val reconciliation: PostUnlockReconciliation,
    private val beforeQuickUnlock: () -> Unit = {},
) {
    private val reconciliationFailure = AtomicReference<String?>(null)

    fun interactiveUnlock(path: String, credential: CharArray): UnlockAttemptOutcome = try {
        reconciliationFailure.set(null)
        port.interactiveUnlock(path, credential)
        try {
            reconciliation.reconcile {
                port.enrollQuickUnlock(credential)
            }
        } catch (error: Exception) {
            reconciliationFailure.set(error.javaClass.simpleName)
        }
        UnlockAttemptOutcome.UNLOCKED
    } finally {
        credential.fill('\u0000')
    }

    fun quickUnlock(): UnlockAttemptOutcome {
        beforeQuickUnlock()
        val outcome = port.quickUnlock()
        if (outcome == UnlockAttemptOutcome.UNLOCKED) {
            reconciliationFailure.set(null)
            try {
                reconciliation.reconcile(null)
            } catch (error: Exception) {
                reconciliationFailure.set(error.javaClass.simpleName)
            }
        }
        return outcome
    }

    fun lastReconciliationFailure(): String? = reconciliationFailure.get()
}
