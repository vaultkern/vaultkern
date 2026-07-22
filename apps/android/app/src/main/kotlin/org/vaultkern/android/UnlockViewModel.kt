package org.vaultkern.android

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.settings.QuickUnlockSettingsApplier
import org.vaultkern.android.settings.QuickUnlockSettingsApplyOutcome
import org.vaultkern.android.ui.UnlockUiState
import org.vaultkern.android.unlock.UnlockAttemptOutcome

class UnlockViewModel(
    private val graph: VaultKernGraph,
) : ViewModel() {
    private val mutableState = MutableStateFlow(
        UnlockUiState(
            quickUnlockDesired = graph.desiredSettings.load().quickUnlockEnabled,
            enrollmentState = graph.currentEnrollmentState(),
            keySecurityLevel = graph.currentKeySecurityLevel(),
        ),
    )
    val state: StateFlow<UnlockUiState> = mutableState.asStateFlow()

    init {
        viewModelScope.launch(Dispatchers.IO) {
            val refreshed = runCatching {
                graph.awaitScheduledReconciliation()
                graph.currentEnrollmentState() to graph.currentKeySecurityLevel()
            }
            mutableState.update { current ->
                if (current.busy || current.status != INITIAL_STATUS) {
                    current
                } else {
                    refreshed.fold(
                        onSuccess = { (enrollment, security) ->
                            current.copy(
                                enrollmentState = enrollment,
                                keySecurityLevel = security,
                            )
                        },
                        onFailure = {
                            current.copy(
                                status = "Quick-unlock reconciliation needs retry " +
                                    "(${it.javaClass.simpleName})",
                            )
                        },
                    )
                }
            }
        }
    }

    fun onPathChanged(value: String) {
        mutableState.update { it.copy(vaultPath = value) }
    }

    fun onPasswordChanged(value: String) {
        mutableState.update { it.copy(password = value) }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    fun interactiveUnlock() {
        val snapshot = mutableState.value
        if (snapshot.vaultPath.isBlank()) return
        val path = snapshot.vaultPath
        val credential = snapshot.password.toCharArray()
        mutableState.update {
            it.copy(password = "", busy = true, status = "Unlocking vault")
        }
        viewModelScope.launch(Dispatchers.IO, start = CoroutineStart.ATOMIC) {
            val result = try {
                runCatching {
                    graph.unlockCoordinator.interactiveUnlock(path, credential)
                }
            } finally {
                credential.fill('\u0000')
            }
            if (result.isSuccess) {
                publishStatus(unlockedStatus())
            } else {
                publishStatus("Unlock failed: ${result.exceptionOrNull()?.javaClass?.simpleName}")
            }
        }
    }

    fun quickUnlock() {
        mutableState.update { it.copy(busy = true, status = "Waiting for biometrics") }
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
        mutableState.update { it.copy(quickUnlockDesired = enabled, busy = true) }
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
                    "Settings save failed: ${it.javaClass.simpleName}"
                },
            )
            if (result.isFailure) {
                mutableState.update { state ->
                    state.copy(
                        quickUnlockDesired = graph.desiredSettings.load().quickUnlockEnabled,
                    )
                }
            }
            publishStatus(status)
        }
    }

    private fun publishStatus(status: String) {
        mutableState.update {
            it.copy(
                busy = false,
                status = status,
                quickUnlockDesired = graph.desiredSettings.load().quickUnlockEnabled,
                enrollmentState = graph.currentEnrollmentState(),
                keySecurityLevel = graph.currentKeySecurityLevel(),
            )
        }
    }

    private fun unlockedStatus(): String =
        graph.unlockCoordinator.lastReconciliationFailure()?.let {
            "Vault unlocked; quick-unlock reconciliation needs retry ($it)"
        } ?: "Vault unlocked"

    private fun quickUnlockStatus(outcome: UnlockAttemptOutcome): String = when (outcome) {
        UnlockAttemptOutcome.UNLOCKED -> unlockedStatus()
        UnlockAttemptOutcome.NOT_ENROLLED ->
            if (graph.currentEnrollmentState() == UnlockEnrollmentState.INVALIDATED) {
                "Quick unlock invalidated; unlock interactively to re-enroll"
            } else {
                "Quick unlock is not enrolled"
            }
        UnlockAttemptOutcome.CANCELLED -> "Biometric authentication cancelled"
        UnlockAttemptOutcome.OPEN_APP_REQUIRED -> "Open the app once to refresh quick unlock"
        UnlockAttemptOutcome.CREDENTIAL_REQUIRED ->
            "Master credential changed; unlock interactively to re-enroll"
        UnlockAttemptOutcome.UNSUPPORTED -> "Biometric quick unlock is unavailable"
    }

    companion object {
        private const val INITIAL_STATUS = "Select a vault and unlock it"
    }
}
