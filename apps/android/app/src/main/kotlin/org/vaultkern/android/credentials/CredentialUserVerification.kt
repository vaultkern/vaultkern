package org.vaultkern.android.credentials

import org.vaultkern.android.unlock.UnlockAttemptOutcome
import org.vaultkern.android.unlock.UnlockCoordinator
import org.vaultkern.core.VaultSession

fun interface MonotonicClock {
    fun nowNanos(): Long
}

class CredentialReleaseCoordinator(
    private val session: VaultSession,
    private val unlockCoordinator: UnlockCoordinator,
    private val verifier: FreshUserVerification,
    private val clock: MonotonicClock = MonotonicClock(System::nanoTime),
) {
    fun ensureUnlockedWithFreshUserVerification(reason: String): FreshUserVerificationLease {
        if (session.sessionState().unlocked) {
            verifier.verify(reason)
        } else {
            require(unlockCoordinator.quickUnlock() == UnlockAttemptOutcome.UNLOCKED) {
                "vault could not be quick-unlocked for credential release"
            }
        }
        return FreshUserVerificationLease(verifier, clock, clock.nowNanos())
    }
}

class FreshUserVerificationLease internal constructor(
    private val verifier: FreshUserVerification,
    private val clock: MonotonicClock,
    acquiredAtNanos: Long,
) {
    private var acquiredAt = acquiredAtNanos

    @Synchronized
    fun refreshIfStale(reason: String) {
        val now = clock.nowNanos()
        if (now - acquiredAt <= MAX_FRESH_UV_NANOS) return
        verifier.verify(reason)
        acquiredAt = clock.nowNanos()
    }

    companion object {
        internal const val MAX_FRESH_UV_NANOS = 30_000_000_000L
    }
}
