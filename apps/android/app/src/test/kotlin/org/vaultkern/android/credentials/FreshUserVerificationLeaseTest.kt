package org.vaultkern.android.credentials

import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class FreshUserVerificationLeaseTest {
    @Test
    fun refreshesOnlyAfterFreshnessWindowExpires() {
        var now = 100L
        val verifies = AtomicInteger()
        val lease = FreshUserVerificationLease(
            verifier = FreshUserVerification { verifies.incrementAndGet() },
            clock = MonotonicClock { now },
            acquiredAtNanos = now,
        )

        now += FreshUserVerificationLease.MAX_FRESH_UV_NANOS
        lease.refreshIfStale("assert")
        assertEquals(0, verifies.get())

        now += 1
        lease.refreshIfStale("assert")
        assertEquals(1, verifies.get())
    }

    @Test
    fun failedRefreshDoesNotAdvanceTheLease() {
        var now = FreshUserVerificationLease.MAX_FRESH_UV_NANOS + 1
        val verifies = AtomicInteger()
        val lease = FreshUserVerificationLease(
            verifier = FreshUserVerification {
                verifies.incrementAndGet()
                throw IllegalStateException("cancelled")
            },
            clock = MonotonicClock { now },
            acquiredAtNanos = 0,
        )

        assertThrows(IllegalStateException::class.java) { lease.refreshIfStale("assert") }
        now += 1
        assertThrows(IllegalStateException::class.java) { lease.refreshIfStale("assert") }
        assertEquals(2, verifies.get())
    }
}
