package org.vaultkern.android.unlock

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.settings.AndroidDesiredSettings
import org.vaultkern.android.settings.DesiredSettingsStore
import org.vaultkern.android.settings.QuickUnlockActualState
import org.vaultkern.android.settings.QuickUnlockReconciler
import org.vaultkern.android.storage.SelectedKeyFile
import org.vaultkern.core.VaultKernSensitiveBytes

class UnlockCoordinatorTest {
    @Test
    fun interactiveUnlockReconcilesEnrollmentThenClearsCredentialBuffer() {
        val port = RecordingUnlockPort()
        val coordinator = coordinator(port, quickUnlockEnabled = true)
        val credential = "test-master-password".toCharArray()

        val result = coordinator.interactiveUnlockCurrent(credential)

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals(listOf("unlock-current", "enroll"), port.events)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun keyFileCapabilityFlowsThroughUnlockAndFreshEnrollment() {
        val port = RecordingUnlockPort()
        val coordinator = coordinator(port, quickUnlockEnabled = true)
        val credential = "test-master-password".toCharArray()
        val keyFile = RecordingSelectedKeyFile(byteArrayOf(1, 3, 3, 7))

        val result = coordinator.interactiveUnlockCurrent(credential, keyFile)

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals(
            listOf(
                "unlock-current:01030307",
                "enroll:01030307",
            ),
            port.keyFileEvents,
        )
        assertEquals(2, keyFile.openCount)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun restoredCurrentVaultUnlockUsesTheSameFreshEnrollmentFlow() {
        val port = RecordingUnlockPort()
        val coordinator = coordinator(port, quickUnlockEnabled = true)
        val credential = "restored-master-password".toCharArray()

        val result = coordinator.interactiveUnlockCurrent(credential)

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals(listOf("unlock-current", "enroll"), port.events)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun failedInteractiveUnlockDoesNotReconcileAndStillClearsCredentialBuffer() {
        val port = RecordingUnlockPort(failInteractiveUnlock = true)
        val coordinator = coordinator(port, quickUnlockEnabled = true)
        val credential = "wrong-password".toCharArray()

        val result = runCatching {
            coordinator.interactiveUnlockCurrent(credential)
        }

        assertTrue(result.isFailure)
        assertEquals(listOf("unlock-current"), port.events)
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun successfulBlobUnlockRunsTheSamePostUnlockReconciliationPoint() {
        val port = RecordingUnlockPort(
            initialEnrollment = UnlockEnrollmentState.ENROLLED,
        )
        val reconciliation = CountingReconciliation(
            QuickUnlockReconciler(FixedSettings(true), port),
        )
        val coordinator = UnlockCoordinator(port, reconciliation)

        val result = coordinator.quickUnlock()

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals(1, reconciliation.calls)
    }

    @Test
    fun localDocumentAuthorityRefreshRunsBeforeBlobUnlockReadsTheVault() {
        val port = RecordingUnlockPort(
            initialEnrollment = UnlockEnrollmentState.ENROLLED,
        )
        val events = mutableListOf<String>()
        port.beforeQuickUnlock = { events += "unlock" }
        val coordinator = UnlockCoordinator(
            port,
            CountingReconciliation(
                QuickUnlockReconciler(FixedSettings(true), port),
            ),
            beforeVaultRead = { events += "refresh" },
        )

        coordinator.quickUnlock()

        assertEquals(listOf("refresh", "unlock"), events)
    }

    @Test
    fun reconciliationFailureDoesNotTurnASuccessfulUnlockIntoAnUnlockFailure() {
        val port = RecordingUnlockPort()
        val reconciliation = object : PostUnlockReconciliation {
            override fun reconcile(enrollCurrentVault: (() -> Unit)?) {
                throw IllegalStateException("injected reconciliation failure")
            }
        }
        val coordinator = UnlockCoordinator(port, reconciliation)
        val credential = "valid-password".toCharArray()

        val result = coordinator.interactiveUnlockCurrent(credential)

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals("IllegalStateException", coordinator.lastReconciliationFailure())
        assertTrue(credential.all { it == '\u0000' })
    }

    @Test
    fun failedFreshEnrollmentAlwaysFinishesPreparedPlatformState() {
        val port = RecordingUnlockPort(failEnrollment = true)
        var finishCalls = 0
        val coordinator = UnlockCoordinator(
            port,
            CountingReconciliation(
                QuickUnlockReconciler(FixedSettings(true), port),
            ),
            finishEnrollmentAttempt = { finishCalls += 1 },
        )
        val credential = "valid-password".toCharArray()

        val result = coordinator.interactiveUnlockCurrent(credential)

        assertEquals(UnlockAttemptOutcome.UNLOCKED, result)
        assertEquals(1, finishCalls)
        assertEquals("IllegalStateException", coordinator.lastReconciliationFailure())
    }

    @Test
    fun credentialIsClearedAsSoonAsFreshEnrollmentStopsUsingIt() {
        val port = RecordingUnlockPort()
        val credential = "valid-password".toCharArray()
        var clearedBeforeReconciliationReturned = false
        val reconciliation = PostUnlockReconciliation { enroll ->
            requireNotNull(enroll).invoke()
            clearedBeforeReconciliationReturned = credential.all { it == '\u0000' }
        }
        val coordinator = UnlockCoordinator(port, reconciliation)

        coordinator.interactiveUnlockCurrent(credential)

        assertTrue(clearedBeforeReconciliationReturned)
    }

    @Test
    fun platformCleanupFailureDoesNotSkipDesiredStateReconciliation() {
        val port = RecordingUnlockPort(initialEnrollment = UnlockEnrollmentState.ENROLLED)
        var cleanupCalls = 0
        val reconciliation = CorePostUnlockReconciliation(
            QuickUnlockReconciler(FixedSettings(false), port),
        ) {
            cleanupCalls += 1
            if (cleanupCalls == 1) error("injected cleanup failure")
        }

        val result = runCatching { reconciliation.reconcile(null) }

        assertTrue(result.isFailure)
        assertEquals(UnlockEnrollmentState.NOT_ENROLLED, port.enrollmentState())
        assertEquals(2, cleanupCalls)
    }
}

private class RecordingSelectedKeyFile(
    private val content: ByteArray,
) : SelectedKeyFile {
    override val displayName = "test.key"
    var openCount = 0

    override fun <T> withSensitiveBytes(block: (VaultKernSensitiveBytes) -> T): T {
        openCount += 1
        val sensitive = VaultKernSensitiveBytes.fromByteArray(content.copyOf())
        return try {
            block(sensitive)
        } finally {
            sensitive.close()
        }
    }
}

private fun coordinator(
    port: RecordingUnlockPort,
    quickUnlockEnabled: Boolean,
): UnlockCoordinator = UnlockCoordinator(
    port,
    CountingReconciliation(
        QuickUnlockReconciler(FixedSettings(quickUnlockEnabled), port),
    ),
)

private class FixedSettings(enabled: Boolean) : DesiredSettingsStore {
    private val settings = AndroidDesiredSettings(enabled)
    override fun load(): AndroidDesiredSettings = settings
    override fun save(settings: AndroidDesiredSettings) = error("not used")
}

private class CountingReconciliation(
    private val delegate: QuickUnlockReconciler,
) : PostUnlockReconciliation {
    var calls = 0
    override fun reconcile(enrollCurrentVault: (() -> Unit)?) {
        calls += 1
        delegate.reconcile(enrollCurrentVault)
    }
}

private class RecordingUnlockPort(
    private val failInteractiveUnlock: Boolean = false,
    private val failEnrollment: Boolean = false,
    initialEnrollment: UnlockEnrollmentState = UnlockEnrollmentState.NOT_ENROLLED,
) : ResidentUnlockPort, QuickUnlockActualState {
    val events = mutableListOf<String>()
    val keyFileEvents = mutableListOf<String>()
    var beforeQuickUnlock: () -> Unit = {}
    private var unlocked = false
    private var enrollment = initialEnrollment

    override fun interactiveUnlockCurrent(
        credential: CharArray,
        keyFile: VaultKernSensitiveBytes?,
    ) {
        events += "unlock-current"
        keyFileEvents += "unlock-current:${keyFile.marker()}"
        check(credential.isNotEmpty())
        if (failInteractiveUnlock) error("credential rejected")
        unlocked = true
    }

    override fun quickUnlock(): UnlockAttemptOutcome {
        beforeQuickUnlock()
        unlocked = true
        return UnlockAttemptOutcome.UNLOCKED
    }

    override fun enrollQuickUnlock(
        credential: CharArray,
        keyFile: VaultKernSensitiveBytes?,
    ) {
        events += "enroll"
        keyFileEvents += "enroll:${keyFile.marker()}"
        check(unlocked)
        check(credential.isNotEmpty())
        if (failEnrollment) error("injected enrollment failure")
        enrollment = UnlockEnrollmentState.ENROLLED
    }

    override fun enrollmentState(): UnlockEnrollmentState = enrollment
    override fun vaultIsUnlocked(): Boolean = unlocked
    override fun revokeAll() {
        enrollment = UnlockEnrollmentState.NOT_ENROLLED
    }
}

private fun VaultKernSensitiveBytes?.marker(): String {
    if (this == null) return "none"
    val bytes = copyBytes()
    return try {
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    } finally {
        bytes.fill(0)
    }
}
