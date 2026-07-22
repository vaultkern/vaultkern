package org.vaultkern.android.settings

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
}

private class FixedDesiredSettings(
    quickUnlockEnabled: Boolean,
) : DesiredSettingsStore {
    private val value = AndroidDesiredSettings(quickUnlockEnabled)
    override fun load(): AndroidDesiredSettings = value
    override fun save(settings: AndroidDesiredSettings) = error("not used")
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
