package org.vaultkern.android.unlock

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.settings.AndroidDesiredSettings
import org.vaultkern.android.settings.DesiredSettingsStore
import org.vaultkern.android.settings.QuickUnlockActualState
import org.vaultkern.android.settings.QuickUnlockReconciler

class UnlockCoordinatorTest {
    @Test
    fun sourceReconciliationCannotEnterWhileCoreUnlockIsUsingThePreparedMirror() {
        val sourceGate = ReentrantLock()
        val unlockEntered = CountDownLatch(1)
        val releaseUnlock = CountDownLatch(1)
        val reconciliationEntered = CountDownLatch(1)
        val port = object : ResidentUnlockPort {
            override fun interactiveUnlock(path: String, credential: CharArray) = Unit
            override fun interactiveUnlockCurrent(credential: CharArray) {
                unlockEntered.countDown()
                check(releaseUnlock.await(5, TimeUnit.SECONDS))
            }
            override fun quickUnlock() = UnlockAttemptOutcome.UNLOCKED
            override fun enrollQuickUnlock(credential: CharArray) = Unit
        }
        val coordinator = UnlockCoordinator(
            port,
            PostUnlockReconciliation {},
            sourceGate = sourceGate,
        )
        val unlockThread = Thread {
            coordinator.interactiveUnlockCurrent("secret".toCharArray())
        }
        val reconciliationThread = Thread {
            sourceGate.withLock { reconciliationEntered.countDown() }
        }

        try {
            unlockThread.start()
            assertTrue(unlockEntered.await(5, TimeUnit.SECONDS))
            reconciliationThread.start()
            assertFalse(reconciliationEntered.await(250, TimeUnit.MILLISECONDS))
        } finally {
            releaseUnlock.countDown()
            unlockThread.join(5_000)
            reconciliationThread.join(5_000)
        }
        assertTrue(reconciliationEntered.await(1, TimeUnit.SECONDS))
    }

    @Test
    fun interactiveUnlockRefreshesTheSelectedSourceBeforeOpeningIt() {
        val port = RecordingUnlockPort()
        val coordinator = UnlockCoordinator(
            port,
            PostUnlockReconciliation { port.events += "reconcile" },
            beforeUnlock = { port.events += "refresh-source" },
        )

        coordinator.interactiveUnlockCurrent("secret".toCharArray())

        assertEquals(
            listOf("refresh-source", "unlock-current", "reconcile"),
            port.events,
        )
    }

    @Test
    fun interactiveUnlockReconcilesEnrollmentThenClearsCredentialBuffer() {
        val port = RecordingUnlockPort()
        val coordinator = coordinator(port, quickUnlockEnabled = true)
        val credential = "test-master-password".toCharArray()

        val result = coordinator.interactiveUnlock("/vaults/demo.kdbx", credential)

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals(listOf("unlock", "enroll"), port.events)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun failedInteractiveUnlockDoesNotReconcileAndStillClearsCredentialBuffer() {
        val port = RecordingUnlockPort(failInteractiveUnlock = true)
        val coordinator = coordinator(port, quickUnlockEnabled = true)
        val credential = "wrong-password".toCharArray()

        val result = runCatching {
            coordinator.interactiveUnlock("/vaults/demo.kdbx", credential)
        }

        assertTrue(result.isFailure)
        assertEquals(listOf("unlock"), port.events)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun currentRemoteVaultUnlockUsesTheSameReconciliationAndSecretCleanup() {
        val port = RecordingUnlockPort()
        val coordinator = coordinator(port, quickUnlockEnabled = true)
        val credential = "remote-master-password".toCharArray()

        val result = coordinator.interactiveUnlockCurrent(credential)

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals(listOf("unlock-current", "enroll"), port.events)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun successfulBlobUnlockRunsTheSamePostUnlockReconciliationPoint() {
        val port = RecordingUnlockPort(
            initialEnrollment = UnlockEnrollmentState.ENROLLED,
        )
        val reconciliation = CountingReconciliation(
            QuickUnlockReconciler(FixedSettings(true), port),
        )
        val coordinator = UnlockCoordinator(port, reconciliation)

        val result = coordinator.quickUnlock()

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals(1, reconciliation.calls)
    }

    @Test
    fun quickUnlockRefreshesTheSelectedVaultBeforeConsultingTheCoreBlob() {
        val port = RecordingUnlockPort(initialEnrollment = UnlockEnrollmentState.ENROLLED)
        val coordinator = UnlockCoordinator(
            port,
            CountingReconciliation(QuickUnlockReconciler(FixedSettings(true), port)),
            beforeUnlock = { port.events += "refresh" },
        )

        val result = coordinator.quickUnlock()

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals(listOf("refresh", "quick"), port.events)
    }

    @Test
    fun reconciliationFailureDoesNotTurnASuccessfulUnlockIntoAnUnlockFailure() {
        val port = RecordingUnlockPort()
        val reconciliation = object : PostUnlockReconciliation {
            override fun reconcile(enrollCurrentVault: (() -> Unit)?) {
                throw IllegalStateException("injected reconciliation failure")
            }
        }
        val coordinator = UnlockCoordinator(port, reconciliation)
        val credential = "valid-password".toCharArray()

        val result = coordinator.interactiveUnlock("/vaults/demo.kdbx", credential)

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals("IllegalStateException", coordinator.lastReconciliationFailure())
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun platformCleanupFailureDoesNotSkipDesiredStateReconciliation() {
        val port = RecordingUnlockPort(initialEnrollment = UnlockEnrollmentState.ENROLLED)
        var cleanupCalls = 0
        val reconciliation = CorePostUnlockReconciliation(
            QuickUnlockReconciler(FixedSettings(false), port),
        ) {
            cleanupCalls += 1
            if (cleanupCalls == 1) error("injected cleanup failure")
        }

        val result = runCatching { reconciliation.reconcile(null) }

        assertTrue(result.isFailure)
        assertEquals(UnlockEnrollmentState.NOT_ENROLLED, port.enrollmentState())
        assertEquals(2, cleanupCalls)
    }

    @Test
    fun platformStoreReconciliationRunsEveryStoreAndCombinesFailures() {
        val events = mutableListOf<String>()

        val result = runCatching {
            reconcilePlatformStores(
                {
                    events += "unlock-blob"
                    error("blob failure")
                },
                {
                    events += "local-documents"
                    error("document failure")
                },
            )
        }

        assertTrue(result.isFailure)
        assertEquals(listOf("unlock-blob", "local-documents"), events)
        assertEquals(1, result.exceptionOrNull()?.suppressed?.size)
    }
}

private fun coordinator(
    port: RecordingUnlockPort,
    quickUnlockEnabled: Boolean,
): UnlockCoordinator = UnlockCoordinator(
    port,
    CountingReconciliation(
        QuickUnlockReconciler(FixedSettings(quickUnlockEnabled), port),
    ),
)

private class FixedSettings(enabled: Boolean) : DesiredSettingsStore {
    private val settings = AndroidDesiredSettings(enabled)
    override fun load(): AndroidDesiredSettings = settings
    override fun save(settings: AndroidDesiredSettings) = error("not used")
}

private class CountingReconciliation(
    private val delegate: QuickUnlockReconciler,
) : PostUnlockReconciliation {
    var calls = 0
    override fun reconcile(enrollCurrentVault: (() -> Unit)?) {
        calls += 1
        delegate.reconcile(enrollCurrentVault)
    }
}

private class RecordingUnlockPort(
    private val failInteractiveUnlock: Boolean = false,
    initialEnrollment: UnlockEnrollmentState = UnlockEnrollmentState.NOT_ENROLLED,
) : ResidentUnlockPort, QuickUnlockActualState {
    val events = mutableListOf<String>()
    private var unlocked = false
    private var enrollment = initialEnrollment

    override fun interactiveUnlock(path: String, credential: CharArray) {
        events += "unlock"
        check(path == "/vaults/demo.kdbx")
        check(credential.isNotEmpty())
        if (failInteractiveUnlock) error("credential rejected")
        unlocked = true
    }

    override fun interactiveUnlockCurrent(credential: CharArray) {
        events += "unlock-current"
        check(credential.isNotEmpty())
        if (failInteractiveUnlock) error("credential rejected")
        unlocked = true
    }

    override fun quickUnlock(): UnlockAttemptOutcome {
        events += "quick"
        unlocked = true
        return UnlockAttemptOutcome.UNLOCKED
    }

    override fun enrollQuickUnlock(credential: CharArray) {
        events += "enroll"
        check(unlocked)
        check(credential.isNotEmpty())
        enrollment = UnlockEnrollmentState.ENROLLED
    }

    override fun enrollmentState(): UnlockEnrollmentState = enrollment
    override fun vaultIsUnlocked(): Boolean = unlocked
    override fun revokeAll() {
        enrollment = UnlockEnrollmentState.NOT_ENROLLED
    }
}
