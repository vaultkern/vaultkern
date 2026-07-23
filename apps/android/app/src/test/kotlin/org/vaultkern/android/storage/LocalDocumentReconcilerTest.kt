package org.vaultkern.android.storage

import org.junit.Assert.assertEquals
import org.junit.Test

class LocalDocumentReconcilerTest {
    @Test
    fun unlockedReconciliationPublishesPendingWritesWithoutReplacingTheActiveMirror() {
        var pendingRuns = 0
        var authorityRefreshes = 0
        val reconciler = LocalDocumentReconciler(
            reconcilePending = { pendingRuns += 1 },
            refreshAuthorities = { authorityRefreshes += 1 },
        )

        reconciler.reconcile(vaultUnlocked = true)

        assertEquals(1, pendingRuns)
        assertEquals(0, authorityRefreshes)
    }

    @Test
    fun lockedReconciliationRefreshesAuthorityAfterPendingRecovery() {
        val events = mutableListOf<String>()
        val reconciler = LocalDocumentReconciler(
            reconcilePending = { events += "pending" },
            refreshAuthorities = { events += "refresh" },
        )

        reconciler.reconcile(vaultUnlocked = false)

        assertEquals(listOf("pending", "refresh"), events)
    }

    @Test
    fun remoteCurrentSourcePreparationDoesNotConsultUnrelatedLocalState() {
        var pendingRuns = 0
        var authorityRefreshes = 0
        val reconciler = LocalDocumentReconciler(
            reconcilePending = { pendingRuns += 1 },
            refreshAuthorities = { authorityRefreshes += 1 },
        )

        reconciler.prepareForUnlock(
            vaultUnlocked = false,
            currentSourceIsLocal = false,
        )

        assertEquals(0, pendingRuns)
        assertEquals(0, authorityRefreshes)
    }

    @Test
    fun currentLocalSourcePreparationPublishesThenRefreshesBeforeUnlock() {
        val events = mutableListOf<String>()
        val reconciler = LocalDocumentReconciler(
            reconcilePending = { events += "pending" },
            refreshAuthorities = { events += "refresh" },
        )

        reconciler.prepareForUnlock(
            vaultUnlocked = false,
            currentSourceIsLocal = true,
        )

        assertEquals(listOf("pending", "refresh"), events)
    }
}
