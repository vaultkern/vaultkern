package org.vaultkern.android

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.settings.QuickUnlockSettingsApplier
import org.vaultkern.android.settings.QuickUnlockSettingsApplyOutcome
import org.vaultkern.android.storage.SelectedKeyFile
import org.vaultkern.android.ui.UnlockUiState
import org.vaultkern.android.unlock.UnlockAttemptOutcome

class UnlockViewModel(
    private val graph: VaultKernGraph,
) : ViewModel() {
    private val selectedKeyFile = AtomicReference<SelectedKeyFile?>(null)
    private val initialVaultSelection = runCatching { graph.vaultSelection.current() }
    private val initialPresentation = runCatching {
        RefreshedUnlockPresentation(
            quickUnlockDesired = graph.desiredSettings.load().quickUnlockEnabled,
            enrollmentState = graph.currentEnrollmentState(),
            keySecurityLevel = graph.currentKeySecurityLevel(),
        )
    }
    private val mutableState = MutableStateFlow(
        UnlockUiState(
            selectedVaultName = initialVaultSelection.getOrNull()?.displayName,
            currentVaultSelected = initialVaultSelection.getOrNull() != null,
            quickUnlockDesired = initialPresentation.getOrNull()?.quickUnlockDesired ?: false,
            enrollmentState = initialPresentation.getOrNull()?.enrollmentState
                ?: UnlockEnrollmentState.NOT_ENROLLED,
            keySecurityLevel = initialPresentation.getOrNull()?.keySecurityLevel,
            status = initialFailureStatus(),
        ),
    )
    private val actionGate = UnlockActionGate(mutableState)
    val state: StateFlow<UnlockUiState> = mutableState.asStateFlow()

    init {
        viewModelScope.launch(Dispatchers.IO) {
            val refreshed = runCatching {
                graph.awaitScheduledReconciliation()
                val selection = graph.vaultSelection.current()
                StartupUnlockSnapshot(
                    selectedVaultName = selection?.displayName,
                    currentVaultSelected = selection != null,
                    quickUnlockDesired = graph.desiredSettings.load().quickUnlockEnabled,
                    enrollmentState = graph.currentEnrollmentState(),
                    keySecurityLevel = graph.currentKeySecurityLevel(),
                )
            }
            mutableState.update { current ->
                if (current.busy) {
                    current
                } else {
                    refreshed.fold(
                        onSuccess = { applyStartupRefresh(current, it) },
                        onFailure = {
                            if (current.status == INITIAL_STATUS ||
                                current.status.startsWith(STARTUP_RETRY_PREFIX)
                            ) {
                                current.copy(
                                    status = "Quick-unlock reconciliation needs retry " +
                                        "(${it.javaClass.simpleName})",
                                )
                            } else {
                                current
                            }
                        },
                    )
                }
            }
        }
    }

    fun selectKeyFile(uri: String) {
        if (uri.isBlank() || !actionGate.tryBegin("Selecting key file")) return
        viewModelScope.launch(Dispatchers.IO) {
            val selected = runCatching { graph.selectKeyFile(uri) }
            selected.getOrNull()?.let(selectedKeyFile::set)
            mutableState.update { current ->
                selected.fold(
                    onSuccess = { keyFile ->
                        current.copy(
                            selectedKeyFileName = keyFile.displayName,
                            busy = false,
                            status = "Key file selected",
                        )
                    },
                    onFailure = {
                        current.copy(
                            busy = false,
                            status = "Key-file selection failed: ${it.javaClass.simpleName}",
                        )
                    },
                )
            }
        }
    }

    fun selectLocalDocument(uri: String) {
        if (uri.isBlank() ||
            !actionGate.tryBegin("Opening selected local vault")
        ) {
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            val selected = runCatching { graph.selectLocalDocument(uri) }
            selected.fold(
                onSuccess = {
                    selectedKeyFile.set(null)
                    publishStatus("Local vault selected") { current ->
                        current.copy(
                            selectedVaultName = it.displayName,
                            currentVaultSelected = true,
                            selectedKeyFileName = null,
                        )
                    }
                },
                onFailure = {
                    publishStatus("Vault selection failed: ${it.javaClass.simpleName}")
                },
            )
        }
    }

    fun interactiveUnlock(credential: CharArray) {
        if (!actionGate.tryBegin(
                status = "Unlocking vault",
                requireCurrentVault = true,
            )
        ) {
            credential.fill('\u0000')
            return
        }
        val keyFile = selectedKeyFile.get()
        try {
            viewModelScope.launchOwnedCredential(credential, Dispatchers.IO) { owned ->
                val result = runCatching {
                    graph.unlockCoordinator.interactiveUnlockCurrent(owned, keyFile)
                }
                if (result.isSuccess) {
                    selectedKeyFile.compareAndSet(keyFile, null)
                    publishStatus(unlockedStatus()) { state ->
                        state.copy(selectedKeyFileName = null)
                    }
                } else {
                    publishStatus(
                        "Unlock failed: ${result.exceptionOrNull()?.javaClass?.simpleName}",
                    )
                }
            }
        } catch (error: Throwable) {
            publishStatus("Unlock failed: ${error.javaClass.simpleName}")
        }
    }

    fun quickUnlock() {
        if (!actionGate.tryBegin(
                status = "Waiting for biometrics",
                requireCurrentVault = true,
            )
        ) {
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching { graph.unlockCoordinator.quickUnlock() }
            val status = result.fold(
                onSuccess = ::quickUnlockStatus,
                onFailure = { "Quick unlock failed: ${it.javaClass.simpleName}" },
            )
            publishStatus(status)
        }
    }

    fun setQuickUnlockDesired(enabled: Boolean) {
        if (!actionGate.tryBegin("Saving quick-unlock setting") {
                it.copy(
                    quickUnlockDesired = enabled,
                    quickUnlockDraftDirty = true,
                )
            }
        ) {
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching {
                QuickUnlockSettingsApplier(
                    graph.settingsController,
                    graph::awaitScheduledReconciliation,
                ).apply(enabled)
            }
            val status = result.fold(
                onSuccess = { outcome ->
                    when (outcome) {
                        QuickUnlockSettingsApplyOutcome.CONVERGED ->
                            if (enabled) {
                                "Quick unlock will enroll after an interactive unlock"
                            } else {
                                "Quick unlock disabled"
                            }
                        QuickUnlockSettingsApplyOutcome.COMMITTED_RECONCILIATION_PENDING ->
                            "Setting saved; quick-unlock reconciliation needs retry"
                    }
                },
                onFailure = {
                    "Settings save failed; unsaved change retained " +
                        "(${it.javaClass.simpleName})"
                },
            )
            mutableState.update { state ->
                applyQuickUnlockSaveCompletion(
                    state,
                    committed = result.isSuccess,
                )
            }
            publishStatus(status)
        }
    }

    private fun publishStatus(
        status: String,
        update: (UnlockUiState) -> UnlockUiState = { it },
    ) {
        val refreshed = runCatching {
            RefreshedUnlockPresentation(
                quickUnlockDesired = graph.desiredSettings.load().quickUnlockEnabled,
                enrollmentState = graph.currentEnrollmentState(),
                keySecurityLevel = graph.currentKeySecurityLevel(),
            )
        }
        mutableState.update {
            val current = update(it)
            refreshed.fold(
                onSuccess = { presentation ->
                    current.copy(
                        busy = false,
                        status = status,
                        quickUnlockDesired = if (current.quickUnlockDraftDirty) {
                            current.quickUnlockDesired
                        } else {
                            presentation.quickUnlockDesired
                        },
                        enrollmentState = presentation.enrollmentState,
                        keySecurityLevel = presentation.keySecurityLevel,
                    )
                },
                onFailure = { error ->
                    current.copy(
                        busy = false,
                        status = "$status; state refresh needs retry " +
                            "(${error.javaClass.simpleName})",
                    )
                },
            )
        }
    }

    private fun unlockedStatus(): String =
        graph.unlockCoordinator.lastReconciliationFailure()?.let {
            "Vault unlocked; quick-unlock reconciliation needs retry ($it)"
        } ?: "Vault unlocked"

    private fun quickUnlockStatus(outcome: UnlockAttemptOutcome): String = when (outcome) {
        UnlockAttemptOutcome.UNLOCKED -> unlockedStatus()
        UnlockAttemptOutcome.NOT_ENROLLED -> quickUnlockNotEnrolledStatus(
            runCatching { graph.currentEnrollmentState() },
        )
        UnlockAttemptOutcome.CANCELLED -> "Biometric authentication cancelled"
        UnlockAttemptOutcome.OPEN_APP_REQUIRED -> "Open the app once to refresh quick unlock"
        UnlockAttemptOutcome.CREDENTIAL_REQUIRED ->
            "Master credential changed; unlock interactively to re-enroll"
        UnlockAttemptOutcome.UNSUPPORTED -> "Biometric quick unlock is unavailable"
    }

    private fun initialFailureStatus(): String {
        val failure = initialVaultSelection.exceptionOrNull()
            ?: initialPresentation.exceptionOrNull()
            ?: return INITIAL_STATUS
        return "$STARTUP_RETRY_PREFIX (${failure.javaClass.simpleName})"
    }
}

private data class RefreshedUnlockPresentation(
    val quickUnlockDesired: Boolean,
    val enrollmentState: UnlockEnrollmentState,
    val keySecurityLevel: org.vaultkern.android.security.UnlockKeySecurityLevel?,
)

internal data class StartupUnlockSnapshot(
    val selectedVaultName: String?,
    val currentVaultSelected: Boolean,
    val quickUnlockDesired: Boolean,
    val enrollmentState: UnlockEnrollmentState,
    val keySecurityLevel: org.vaultkern.android.security.UnlockKeySecurityLevel?,
)

internal fun applyStartupRefresh(
    current: UnlockUiState,
    refreshed: StartupUnlockSnapshot,
): UnlockUiState {
    val quickUnlockRefreshed = current.copy(
        quickUnlockDesired = if (current.quickUnlockDraftDirty) {
            current.quickUnlockDesired
        } else {
            refreshed.quickUnlockDesired
        },
        enrollmentState = refreshed.enrollmentState,
        keySecurityLevel = refreshed.keySecurityLevel,
    )
    return if (current.status == INITIAL_STATUS ||
        current.status.startsWith(STARTUP_RETRY_PREFIX)
    ) {
        quickUnlockRefreshed.copy(
            selectedVaultName = refreshed.selectedVaultName,
            currentVaultSelected = refreshed.currentVaultSelected,
            status = INITIAL_STATUS,
        )
    } else {
        quickUnlockRefreshed
    }
}

internal fun applyQuickUnlockSaveCompletion(
    current: UnlockUiState,
    committed: Boolean,
): UnlockUiState = current.copy(
    quickUnlockDraftDirty = !committed && current.quickUnlockDraftDirty,
)

private const val INITIAL_STATUS = "Select a vault and unlock it"
private const val STARTUP_RETRY_PREFIX = "Startup state needs retry"

internal fun quickUnlockNotEnrolledStatus(
    enrollment: Result<UnlockEnrollmentState>,
): String = enrollment.fold(
    onSuccess = {
        if (it == UnlockEnrollmentState.INVALIDATED) {
            "Quick unlock invalidated; unlock interactively to re-enroll"
        } else {
            "Quick unlock is not enrolled"
        }
    },
    onFailure = {
        "Quick unlock is not enrolled; state refresh needs retry " +
            "(${it.javaClass.simpleName})"
    },
)
