package org.vaultkern.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.android.sync.OneDriveAccount

class OneDriveLoginProjectionTest {
    @Test
    fun listingFailureDoesNotRewriteACommittedAuthorizationAsFailure() {
        val result = completeOneDriveLoginAndLoadItems(
            complete = { OneDriveAccount("alice@example.test") },
            loadItems = { error("injected listing failure") },
        )

        assertEquals("alice@example.test", result.account.accountLabel)
        assertTrue(result.items.isFailure)
    }
}
