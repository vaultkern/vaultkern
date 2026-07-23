package org.vaultkern.android

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.security.UnlockKeySecurityLevel
import org.vaultkern.android.ui.UnlockUiState

class UnlockActionGateTest {
    @Test
    fun concurrentActionsCannotBothOwnTheBusyState() {
        val state = MutableStateFlow(UnlockUiState(currentVaultSelected = true))
        val gate = UnlockActionGate(state)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)

        try {
            val attempts = List(2) { index ->
                executor.submit<Boolean> {
                    start.await(5, TimeUnit.SECONDS)
                    gate.tryBegin("action-$index", requireCurrentVault = true)
                }
            }
            start.countDown()

            assertEquals(1, attempts.count { it.get(5, TimeUnit.SECONDS) })
            assertTrue(state.value.busy)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun cancelledScopeClearsAnOwnedCredentialWithoutRunningTheOperation() = runBlocking {
        val parent = Job().apply { cancel() }
        val scope = CoroutineScope(parent + Dispatchers.Unconfined)
        val credential = "never-dispatched".toCharArray()
        var invoked = false

        val job = scope.launchOwnedCredential(credential, Dispatchers.Unconfined) {
            invoked = true
        }
        job.join()

        assertFalse(invoked)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun completedOperationClearsItsOwnedCredential() = runBlocking {
        val credential = "dispatched".toCharArray()
        var sawCredential = false

        val job = launchOwnedCredential(credential, Dispatchers.Unconfined) { owned ->
            sawCredential = owned.contentEquals("dispatched".toCharArray())
        }
        job.join()

        assertTrue(sawCredential)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun synchronousHandoffFailureReturnsAndClearsCredentialOwnership() {
        val credential = "not-accepted".toCharArray()

        val result = runCatching {
            handOffCredential(credential) {
                error("receiver rejected ownership")
            }
        }

        assertTrue(result.isFailure)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun successfulStartupRetryRestoresTheWholePresentationAtomically() {
        val current = UnlockUiState(status = "Startup state needs retry (injected)")
        val refreshed = StartupUnlockSnapshot(
            selectedVaultName = "selected.kdbx",
            currentVaultSelected = true,
            quickUnlockDesired = true,
            enrollmentState = UnlockEnrollmentState.ENROLLED,
            keySecurityLevel = UnlockKeySecurityLevel.TRUSTED_ENVIRONMENT,
        )

        val result = applyStartupRefresh(current, refreshed)

        assertEquals("selected.kdbx", result.selectedVaultName)
        assertTrue(result.currentVaultSelected)
        assertTrue(result.quickUnlockDesired)
        assertEquals(UnlockEnrollmentState.ENROLLED, result.enrollmentState)
        assertEquals(UnlockKeySecurityLevel.TRUSTED_ENVIRONMENT, result.keySecurityLevel)
        assertEquals("Select a vault and unlock it", result.status)
    }

    @Test
    fun failedInvalidationRefreshStillProducesATerminalStatus() {
        val status = quickUnlockNotEnrolledStatus(
            Result.failure(IllegalStateException("injected")),
        )

        assertTrue(status.contains("not enrolled"))
        assertTrue(status.contains("retry"))
    }

    @Test
    fun failedSettingsCommitKeepsTheUsersDraftMarkedAsUnsaved() {
        val draft = UnlockUiState(
            quickUnlockDesired = true,
            quickUnlockDraftDirty = true,
        )

        val result = applyQuickUnlockSaveCompletion(draft, committed = false)

        assertTrue(result.quickUnlockDesired)
        assertTrue(result.quickUnlockDraftDirty)
    }

    @Test
    fun committedSettingsClearTheDraftMarker() {
        val draft = UnlockUiState(
            quickUnlockDesired = true,
            quickUnlockDraftDirty = true,
        )

        val result = applyQuickUnlockSaveCompletion(draft, committed = true)

        assertTrue(result.quickUnlockDesired)
        assertFalse(result.quickUnlockDraftDirty)
    }

    @Test
    fun backgroundRefreshCannotOverwriteAnUnsavedQuickUnlockDraft() {
        val current = UnlockUiState(
            quickUnlockDesired = true,
            quickUnlockDraftDirty = true,
            status = "Settings save failed",
        )
        val persisted = StartupUnlockSnapshot(
            selectedVaultName = null,
            currentVaultSelected = false,
            quickUnlockDesired = false,
            enrollmentState = UnlockEnrollmentState.NOT_ENROLLED,
            keySecurityLevel = null,
        )

        val result = applyStartupRefresh(current, persisted)

        assertTrue(result.quickUnlockDesired)
        assertTrue(result.quickUnlockDraftDirty)
    }
}
