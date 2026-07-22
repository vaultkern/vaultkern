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
import org.vaultkern.android.vault.VaultEntryDraft
import org.vaultkern.android.vault.VaultEntryListItem
import org.vaultkern.android.vault.VaultSaveResult
import org.vaultkern.android.vault.VaultSaveStatus

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
                val unlocked = graph.session.sessionState().unlocked
                StartupSnapshot(
                    enrollment = graph.currentEnrollmentState(),
                    security = graph.currentKeySecurityLevel(),
                    unlocked = unlocked,
                    entries = if (unlocked) graph.vaultWorkflow.browse() else emptyList(),
                )
            }
            mutableState.update { current ->
                if (current.busy || current.status != INITIAL_STATUS) {
                    current
                } else {
                    refreshed.fold(
                        onSuccess = { snapshot ->
                            current.copy(
                                enrollmentState = snapshot.enrollment,
                                keySecurityLevel = snapshot.security,
                                vaultUnlocked = snapshot.unlocked,
                                entries = snapshot.entries,
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
        if (snapshot.busy || snapshot.vaultPath.isBlank()) return
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
                publishUnlockedVault(unlockedStatus())
            } else {
                publishStatus("Unlock failed: ${result.exceptionOrNull()?.javaClass?.simpleName}")
            }
        }
    }

    fun quickUnlock() {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(busy = true, status = "Waiting for biometrics") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching { graph.unlockCoordinator.quickUnlock() }
            val status = result.fold(
                onSuccess = ::quickUnlockStatus,
                onFailure = { "Quick unlock failed: ${it.javaClass.simpleName}" },
            )
            if (result.getOrNull() == UnlockAttemptOutcome.UNLOCKED) {
                publishUnlockedVault(status)
            } else {
                publishStatus(status)
            }
        }
    }

    fun selectEntry(entryId: String) {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(busy = true, status = "Opening entry") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching { graph.vaultWorkflow.open(entryId) }
            mutableState.update { current ->
                result.fold(
                    onSuccess = { draft ->
                        current.copy(busy = false, status = "Editing entry", editor = draft)
                    },
                    onFailure = {
                        current.copy(
                            busy = false,
                            status = "Entry open failed: ${it.javaClass.simpleName}",
                        )
                    },
                )
            }
        }
    }

    fun updateDraft(draft: VaultEntryDraft) {
        mutableState.update { current ->
            if (current.editor?.id == draft.id && !current.busy) current.copy(editor = draft)
            else current
        }
    }

    fun closeEditor() {
        mutableState.update { current ->
            if (current.busy) current
            else current.copy(editor = null, status = "Vault unlocked")
        }
    }

    fun saveEditor() {
        val snapshot = mutableState.value
        if (snapshot.busy) return
        val draft = snapshot.editor ?: return
        mutableState.update { it.copy(busy = true, status = "Saving vault") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching { graph.vaultWorkflow.save(draft) }
            val refreshed = result.mapCatching { graph.vaultWorkflow.browse() }
            mutableState.update { current ->
                result.fold(
                    onSuccess = { save ->
                        current.copy(
                            busy = false,
                            status = saveStatus(save),
                            entries = refreshed.getOrDefault(current.entries),
                            editor = null,
                            conflictCopyPath = save.conflictCopyPath,
                        )
                    },
                    onFailure = {
                        current.copy(
                            busy = false,
                            status = "Save failed: ${it.javaClass.simpleName}",
                        )
                    },
                )
            }
        }
    }

    fun lockVault() {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(busy = true, status = "Locking vault") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching { graph.vaultWorkflow.lock() }
            mutableState.update { current ->
                if (result.isSuccess) {
                    current.copy(
                        busy = false,
                        status = INITIAL_STATUS,
                        vaultUnlocked = false,
                        entries = emptyList(),
                        editor = null,
                        conflictCopyPath = null,
                    )
                } else {
                    current.copy(
                        busy = false,
                        status = "Lock failed: ${result.exceptionOrNull()?.javaClass?.simpleName}",
                    )
                }
            }
        }
    }

    fun setQuickUnlockDesired(enabled: Boolean) {
        if (mutableState.value.busy) return
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

    private fun publishUnlockedVault(status: String) {
        val entries = runCatching { graph.vaultWorkflow.browse() }
        mutableState.update { current ->
            current.copy(
                busy = false,
                status = entries.fold(
                    onSuccess = { status },
                    onFailure = { "$status; browse failed (${it.javaClass.simpleName})" },
                ),
                quickUnlockDesired = graph.desiredSettings.load().quickUnlockEnabled,
                enrollmentState = graph.currentEnrollmentState(),
                keySecurityLevel = graph.currentKeySecurityLevel(),
                vaultUnlocked = true,
                entries = entries.getOrDefault(emptyList()),
                editor = null,
            )
        }
    }

    private fun saveStatus(result: VaultSaveResult): String = when (result.status) {
        VaultSaveStatus.SAVED -> "Vault saved durably"
        VaultSaveStatus.MERGED -> "Vault saved after core field patch"
        VaultSaveStatus.SAVED_TO_CACHE -> "Vault saved to local working copy"
        VaultSaveStatus.CONFLICT_COPY -> "Foreign change detected; conflict copy created"
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

private data class StartupSnapshot(
    val enrollment: UnlockEnrollmentState,
    val security: org.vaultkern.android.security.UnlockKeySecurityLevel?,
    val unlocked: Boolean,
    val entries: List<VaultEntryListItem>,
)
