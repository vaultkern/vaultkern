package org.vaultkern.android

import java.util.concurrent.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class StartupReconciliationTest {
    @Test
    fun reconciliationFailureDoesNotSuppressPersistedStartupState() {
        var stateLoaded = false

        val result = loadAfterBestEffortReconciliation(
            reconcile = { error("injected reconciliation failure") },
            load = {
                stateLoaded = true
                "persisted-current-vault"
            },
        )

        assertTrue(stateLoaded)
        assertEquals("persisted-current-vault", result.value)
        assertEquals("IllegalStateException", result.reconciliationFailure)
    }

    @Test
    fun cancellationIsNotDowngradedToAReconciliationWarning() {
        assertThrows(CancellationException::class.java) {
            runCatchingUnlessCancelled {
                loadAfterBestEffortReconciliation(
                    reconcile = { throw CancellationException("cancelled") },
                    load = { "must-not-load" },
                )
            }
        }
    }
}
