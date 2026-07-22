package org.vaultkern.android.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QuickUnlockSettingsControllerTest {
    @Test
    fun successfulCommitPersistsDesiredStateBeforeSchedulingReconciliation() {
        val events = mutableListOf<String>()
        val store = FakeDesiredSettingsStore(events = events)
        val scheduler = ReconciliationScheduler { events += "reconcile" }
        val controller = QuickUnlockSettingsController(store, scheduler)

        controller.setQuickUnlockEnabled(true)

        assertTrue(store.load().quickUnlockEnabled)
        assertEquals(listOf("persist:true", "reconcile"), events)
    }

    @Test
    fun failedCommitPreservesPreviousStateAndDoesNotReconcile() {
        val store = FakeDesiredSettingsStore(
            initial = AndroidDesiredSettings(quickUnlockEnabled = false),
            failSave = true,
        )
        var reconciliationRequested = false
        val controller = QuickUnlockSettingsController(store) {
            reconciliationRequested = true
        }

        val result = runCatching { controller.setQuickUnlockEnabled(true) }

        assertTrue(result.isFailure)
        assertFalse(store.load().quickUnlockEnabled)
        assertFalse(reconciliationRequested)
    }

    @Test
    fun schedulerFailureDoesNotTurnACommittedSettingIntoASaveFailure() {
        val store = FakeDesiredSettingsStore()
        val controller = QuickUnlockSettingsController(store) {
            error("injected scheduler failure")
        }

        val result = runCatching { controller.setQuickUnlockEnabled(true) }

        assertTrue(result.isSuccess)
        assertTrue(store.load().quickUnlockEnabled)
        assertEquals("IllegalStateException", controller.lastSchedulingFailure())
    }

    @Test
    fun reconciliationFailureIsReportedAsCommittedAndPending() {
        val store = FakeDesiredSettingsStore()
        val controller = QuickUnlockSettingsController(store) { }
        val applier = QuickUnlockSettingsApplier(controller) {
            error("injected reconciliation failure")
        }

        val outcome = applier.apply(true)

        assertEquals(QuickUnlockSettingsApplyOutcome.COMMITTED_RECONCILIATION_PENDING, outcome)
        assertTrue(store.load().quickUnlockEnabled)
    }
}

private class FakeDesiredSettingsStore(
    initial: AndroidDesiredSettings = AndroidDesiredSettings(),
    private val failSave: Boolean = false,
    private val events: MutableList<String> = mutableListOf(),
) : DesiredSettingsStore {
    private var value = initial

    override fun load(): AndroidDesiredSettings = value

    override fun save(settings: AndroidDesiredSettings) {
        if (failSave) error("injected settings failure")
        events += "persist:${settings.quickUnlockEnabled}"
        value = settings
    }
}
