package org.vaultkern.android.credentials

import java.util.concurrent.CancellationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialActivityOwnershipTest {
    @Test
    fun assertionThatWasNotHandedToTheActivityIsClosed() {
        val resource = CountingCloseable()

        closeUnclaimedCredentialOperation(resource, claimed = false)

        assertEquals(1, resource.closeCount)
    }

    @Test
    fun assertionOwnedByTheActivityIsNotClosedByTheProducer() {
        val resource = CountingCloseable()

        closeUnclaimedCredentialOperation(resource, claimed = true)

        assertEquals(0, resource.closeCount)
    }

    @Test
    fun transientCloseFailureGetsOneRetry() {
        val resource = CountingCloseable(failFirstClose = true)

        closeUnclaimedCredentialOperation(resource, claimed = false)

        assertEquals(2, resource.closeCount)
    }

    @Test
    fun selectedCredentialIdDecoderRejectsMalformedPendingIntentData() {
        assertArrayEquals(byteArrayOf(1, 2, 3), decodeSelectedCredentialId("AQID"))
        assertThrows(IllegalArgumentException::class.java) {
            decodeSelectedCredentialId("not+base64url")
        }
    }

    @Test
    fun operationCanBeClosedAgainAfterItsCompletionBodyHasExited() {
        val state = CredentialCompletionState()

        assertTrue(state.beginCompletion())
        assertFalse(state.canClose())

        state.endCompletion()

        assertTrue(state.canClose())
    }

    @Test
    fun coroutineCancellationIsNeverConvertedToAProviderFailure() {
        assertThrows(CancellationException::class.java) {
            credentialResult<Unit> { throw CancellationException("activity destroyed") }
        }
        assertTrue(
            credentialResult<Unit> { throw IllegalArgumentException("bad request") }.isFailure,
        )
    }
}

private class CountingCloseable(
    private val failFirstClose: Boolean = false,
) : AutoCloseable {
    var closeCount = 0
        private set

    override fun close() {
        closeCount += 1
        if (failFirstClose && closeCount == 1) {
            throw IllegalStateException("injected close failure")
        }
    }
}
