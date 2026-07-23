package org.vaultkern.android.settings

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.android.security.UnlockEnrollmentState

class QuickUnlockReconcilerTest {
    @Test
    fun disabledDesiredStateRevokesEvenWhileVaultIsLocked() {
        val actual = FakeUnlockActualState(
            state = UnlockEnrollmentState.ENROLLED,
            unlocked = false,
        )
        val reconciler = QuickUnlockReconciler(
            desiredSettings = FixedDesiredSettings(false),
            actualState = actual,
        )

        val outcome = reconciler.reconcile()

        assertEquals(QuickUnlockReconciliationOutcome.REVOKED, outcome)
        assertTrue(actual.revoked)
        assertEquals(UnlockEnrollmentState.NOT_ENROLLED, actual.enrollmentState())
    }

    @Test
    fun disabledDesiredStateStillRunsIdempotentRevokeWhenNoBlobIsReported() {
        val actual = FakeUnlockActualState(
            state = UnlockEnrollmentState.NOT_ENROLLED,
            unlocked = false,
        )
        val reconciler = QuickUnlockReconciler(
            desiredSettings = FixedDesiredSettings(false),
            actualState = actual,
        )

        val outcome = reconciler.reconcile()

        assertEquals(QuickUnlockReconciliationOutcome.REVOKED, outcome)
        assertTrue(actual.revoked)
    }

    @Test
    fun enabledDesiredStateSkipsVaultDependentEnrollmentWhileLocked() {
        val actual = FakeUnlockActualState(
            state = UnlockEnrollmentState.NOT_ENROLLED,
            unlocked = false,
        )
        var enrollmentRan = false
        val reconciler = QuickUnlockReconciler(
            desiredSettings = FixedDesiredSettings(true),
            actualState = actual,
        )

        val outcome = reconciler.reconcile { enrollmentRan = true }

        assertEquals(QuickUnlockReconciliationOutcome.SKIPPED_LOCKED, outcome)
        assertFalse(enrollmentRan)
    }

    @Test
    fun nextUnlockedReconciliationEnrollsAfterAnInvalidation() {
        val actual = FakeUnlockActualState(
            state = UnlockEnrollmentState.INVALIDATED,
            unlocked = true,
        )
        val reconciler = QuickUnlockReconciler(
            desiredSettings = FixedDesiredSettings(true),
            actualState = actual,
        )

        val outcome = reconciler.reconcile { actual.markEnrolled() }

        assertEquals(QuickUnlockReconciliationOutcome.ENROLLED, outcome)
        assertEquals(UnlockEnrollmentState.ENROLLED, actual.enrollmentState())
    }

    @Test
    fun freshInteractiveCredentialRefreshesAnExistingEnrollment() {
        val actual = FakeUnlockActualState(
            state = UnlockEnrollmentState.ENROLLED,
            unlocked = true,
        )
        var refreshes = 0
        val reconciler = QuickUnlockReconciler(
            desiredSettings = FixedDesiredSettings(true),
            actualState = actual,
        )

        val outcome = reconciler.reconcile {
            refreshes += 1
            actual.markEnrolled()
        }

        assertEquals(QuickUnlockReconciliationOutcome.ENROLLED, outcome)
        assertEquals(1, refreshes)
    }

    @Test
    fun concurrentDisableCannotBeOverwrittenByAnOlderEnrollmentPass() {
        val desired = MutableDesiredSettings(true)
        val actual = BlockingEnrollmentActualState()
        val reconciler = QuickUnlockReconciler(desired, actual)
        val executor = Executors.newFixedThreadPool(2)

        try {
            val enrollment = executor.submit<QuickUnlockReconciliationOutcome> {
                reconciler.reconcile {
                    actual.enrollmentStarted.countDown()
                    check(actual.finishEnrollment.await(5, TimeUnit.SECONDS))
                    actual.markEnrolled()
                }
            }
            assertTrue(actual.enrollmentStarted.await(5, TimeUnit.SECONDS))

            desired.save(AndroidDesiredSettings(quickUnlockEnabled = false))
            val revoke = executor.submit<QuickUnlockReconciliationOutcome> {
                reconciler.reconcile()
            }

            // An unsynchronised reconciler revokes here, then the older pass
            // resumes and silently restores the now-disabled blob.
            actual.revokeObserved.await(250, TimeUnit.MILLISECONDS)
            actual.finishEnrollment.countDown()

            assertEquals(QuickUnlockReconciliationOutcome.ENROLLED, enrollment.get(5, TimeUnit.SECONDS))
            assertEquals(QuickUnlockReconciliationOutcome.REVOKED, revoke.get(5, TimeUnit.SECONDS))
            assertEquals(UnlockEnrollmentState.NOT_ENROLLED, actual.enrollmentState())
        } finally {
            actual.finishEnrollment.countDown()
            executor.shutdownNow()
        }
    }
}

private class FixedDesiredSettings(
    quickUnlockEnabled: Boolean,
) : DesiredSettingsStore {
    private val value = AndroidDesiredSettings(quickUnlockEnabled)
    override fun load(): AndroidDesiredSettings = value
    override fun save(settings: AndroidDesiredSettings) = error("not used")
}

private class MutableDesiredSettings(
    quickUnlockEnabled: Boolean,
) : DesiredSettingsStore {
    private val value = AtomicReference(AndroidDesiredSettings(quickUnlockEnabled))

    override fun load(): AndroidDesiredSettings = value.get()
    override fun save(settings: AndroidDesiredSettings) {
        value.set(settings)
    }
}

private class BlockingEnrollmentActualState : QuickUnlockActualState {
    private val state = AtomicReference(UnlockEnrollmentState.NOT_ENROLLED)
    val enrollmentStarted = CountDownLatch(1)
    val finishEnrollment = CountDownLatch(1)
    val revokeObserved = CountDownLatch(1)

    override fun enrollmentState(): UnlockEnrollmentState = state.get()
    override fun vaultIsUnlocked(): Boolean = true

    override fun revokeAll() {
        state.set(UnlockEnrollmentState.NOT_ENROLLED)
        revokeObserved.countDown()
    }

    fun markEnrolled() {
        state.set(UnlockEnrollmentState.ENROLLED)
    }
}

private class FakeUnlockActualState(
    private var state: UnlockEnrollmentState,
    private val unlocked: Boolean,
) : QuickUnlockActualState {
    var revoked = false

    override fun enrollmentState(): UnlockEnrollmentState = state
    override fun vaultIsUnlocked(): Boolean = unlocked

    override fun revokeAll() {
        revoked = true
        state = UnlockEnrollmentState.NOT_ENROLLED
    }

    fun markEnrolled() {
        state = UnlockEnrollmentState.ENROLLED
    }
}
