package org.vaultkern.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.android.sync.AndroidSyncStatus

class SyncProjectionTest {
    @Test
    fun projectionFailureDoesNotRewriteASuccessfulSyncAsFailure() {
        val expected = AndroidSyncStatus(
            sourceKind = "onedrive",
            remoteState = "online",
            lastSyncAt = 123,
            cachedAt = 123,
            lastError = null,
        )

        val result = syncThenRefreshProjection(
            sync = { expected },
            refresh = { error("injected browse failure") },
        )

        assertEquals(expected, result.status)
        assertTrue(result.projection.isFailure)
    }
}
