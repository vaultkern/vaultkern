package org.vaultkern.android

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import java.util.concurrent.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.security.UnlockKeySecurityLevel
import org.vaultkern.android.settings.QuickUnlockSettingsApplier
import org.vaultkern.android.settings.QuickUnlockSettingsApplyOutcome
import org.vaultkern.android.sync.AndroidSyncStatus
import org.vaultkern.android.sync.OneDriveAccount
import org.vaultkern.android.sync.OneDriveBrowserItem
import org.vaultkern.android.sync.OneDriveVaultPreloadException
import org.vaultkern.android.ui.UnlockUiState
import org.vaultkern.android.unlock.UnlockAttemptOutcome
import org.vaultkern.android.vault.CurrentVaultSelection
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
            val refreshed = runCatchingUnlessCancelled {
                loadAfterBestEffortReconciliation(
                    reconcile = graph::awaitScheduledReconciliation,
                    load = {
                        val unlocked = graph.session.sessionState().unlocked
                        StartupSnapshot(
                            enrollment = graph.currentEnrollmentState(),
                            security = graph.currentKeySecurityLevel(),
                            unlocked = unlocked,
                            entries = if (unlocked) graph.vaultWorkflow.browse() else emptyList(),
                            syncStatus = graph.oneDriveWorkflow.status(),
                            currentSelection = graph.vaultSelection.current(),
                            oneDriveConnected = graph.oneDriveTokenAdapter.hasStoredToken(),
                        )
                    },
                )
            }
            mutableState.update { current ->
                if (current.busy || current.status != INITIAL_STATUS) {
                    current
                } else {
                    refreshed.fold(
                        onSuccess = { refreshedState ->
                            val snapshot = refreshedState.value
                            current.withRestoredVaultSelection(
                                snapshot.currentSelection,
                                snapshot.syncStatus,
                            ).copy(
                                enrollmentState = snapshot.enrollment,
                                keySecurityLevel = snapshot.security,
                                vaultUnlocked = snapshot.unlocked,
                                entries = snapshot.entries,
                                oneDriveConnected = snapshot.oneDriveConnected,
                                status = refreshedState.reconciliationFailure?.let { failure ->
                                    "Platform reconciliation needs retry ($failure)"
                                } ?: current.status,
                            )
                        },
                        onFailure = {
                            current.copy(
                                status = "Startup state restore failed " +
                                    "(${it.javaClass.simpleName})",
                            )
                        },
                    )
                }
            }
        }
    }

    fun onPasswordChanged(value: String) {
        mutableState.update { it.copy(password = value) }
    }

    fun selectLocalDocument(uri: String) {
        if (uri.isBlank() || mutableState.value.busy) return
        mutableState.update { it.copy(busy = true, status = "Opening selected local vault") }
        viewModelScope.launch(Dispatchers.IO) {
            val selected = runCatchingUnlessCancelled { graph.selectLocalDocument(uri) }
            mutableState.update { current ->
                selected.fold(
                    onSuccess = {
                        current.withSelectedLocalVault(it.displayName)
                            .withCurrentVaultUnlockState(
                                graph.currentEnrollmentState(),
                                graph.currentKeySecurityLevel(),
                            ).copy(
                                busy = false,
                                status = "Local vault selected",
                            )
                    },
                    onFailure = {
                        current.copy(
                            busy = false,
                            status = "Vault selection failed: ${it.javaClass.simpleName}",
                        )
                    },
                )
            }
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    fun interactiveUnlock() {
        val snapshot = mutableState.value
        if (snapshot.busy ||
            (snapshot.vaultPath.isBlank() && !snapshot.currentVaultSelected)
        ) return
        val path = snapshot.vaultPath
        val unlockCurrent = path.isBlank() && snapshot.currentVaultSelected
        val credential = snapshot.password.toCharArray()
        mutableState.update {
            it.copy(password = "", busy = true, status = "Unlocking vault")
        }
        viewModelScope.launch(Dispatchers.IO, start = CoroutineStart.ATOMIC) {
            val result = try {
                runCatching {
                    if (unlockCurrent) graph.unlockCoordinator.interactiveUnlockCurrent(credential)
                    else graph.unlockCoordinator.interactiveUnlock(path, credential)
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
            val syncStatus = runCatching { graph.oneDriveWorkflow.status() }.getOrNull()
            mutableState.update { current ->
                result.fold(
                    onSuccess = { save ->
                        current.copy(
                            busy = false,
                            status = saveStatus(save),
                            entries = refreshed.getOrDefault(current.entries),
                            editor = null,
                            conflictCopyPath = save.conflictCopyPath,
                            syncStatus = syncStatus,
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
                        syncStatus = runCatching { graph.oneDriveWorkflow.status() }.getOrNull(),
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

    fun beginOneDriveLogin() {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(busy = true, status = "Opening OneDrive sign-in") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatchingUnlessCancelled { graph.oneDriveWorkflow.beginLogin() }
            val connected = graph.oneDriveTokenAdapter.hasStoredToken()
            mutableState.update { current ->
                result.fold(
                    onSuccess = {
                        current.copy(
                            busy = false,
                            oneDriveAuthPending = true,
                            status = "Finish OneDrive sign-in in the browser",
                        )
                    },
                    onFailure = {
                        current.copy(
                            busy = false,
                            oneDriveAuthPending = false,
                            status = "OneDrive sign-in unavailable: ${it.javaClass.simpleName}",
                        ).reconcileOneDriveTokenPresence(connected)
                    },
                )
            }
        }
    }

    fun completeOneDriveLogin() {
        val snapshot = mutableState.value
        if (snapshot.busy || !snapshot.oneDriveAuthPending) return
        mutableState.update { it.copy(busy = true, status = "Completing OneDrive sign-in") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatchingUnlessCancelled {
                completeOneDriveLoginAndLoadItems(
                    complete = graph.oneDriveWorkflow::completeLogin,
                    loadItems = { graph.oneDriveWorkflow.browse(null) },
                )
            }
            val connected = graph.oneDriveTokenAdapter.hasStoredToken()
            mutableState.update { current ->
                result.fold(
                    onSuccess = { completed ->
                        current.copy(
                            busy = false,
                            oneDriveAuthPending = false,
                            oneDriveAccountLabel = completed.account.accountLabel,
                            oneDriveItems = completed.items.getOrDefault(emptyList()),
                            oneDriveFolderId = null,
                            status = completed.items.fold(
                                onSuccess = { "OneDrive connected; choose a KDBX vault" },
                                onFailure = {
                                    "OneDrive connected; file listing needs retry " +
                                        "(${it.javaClass.simpleName})"
                                },
                            ),
                        ).reconcileOneDriveTokenPresence(true)
                    },
                    onFailure = {
                        current.copy(
                            busy = false,
                            oneDriveAuthPending = false,
                            status = "OneDrive sign-in failed: ${it.javaClass.simpleName}",
                        ).reconcileOneDriveTokenPresence(connected)
                    },
                )
            }
        }
    }

    fun browseOneDriveRoot() = browseOneDrive(null)

    fun selectOneDriveItem(item: OneDriveBrowserItem) {
        if (mutableState.value.busy) return
        if (item.folder) {
            browseOneDrive(item.itemId)
            return
        }
        mutableState.update { it.copy(busy = true, status = "Selecting OneDrive vault") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatchingUnlessCancelled { graph.oneDriveWorkflow.select(item) }
            val syncStatus = runCatching { graph.oneDriveWorkflow.status() }.getOrNull()
            val connected = graph.oneDriveTokenAdapter.hasStoredToken()
            mutableState.update { current ->
                result.fold(
                    onSuccess = { selected ->
                        current.withSelectedOneDriveVault(
                            selected.displayName,
                            syncStatus,
                        ).withCurrentVaultUnlockState(
                            graph.currentEnrollmentState(),
                            graph.currentKeySecurityLevel(),
                        ).copy(
                            busy = false,
                            status = "OneDrive vault selected; enter its master password",
                        ).reconcileOneDriveTokenPresence(connected)
                    },
                    onFailure = { error ->
                        val failed = if (error is OneDriveVaultPreloadException) {
                            current.withSelectedOneDriveVault(
                                error.selected.displayName,
                                syncStatus,
                            ).withCurrentVaultUnlockState(
                                graph.currentEnrollmentState(),
                                graph.currentKeySecurityLevel(),
                            ).copy(
                                busy = false,
                                status = "OneDrive vault selected; private download failed, retry unlock",
                            )
                        } else {
                            current.copy(
                                busy = false,
                                status = "OneDrive selection failed: ${error.javaClass.simpleName}",
                            )
                        }
                        failed.reconcileOneDriveTokenPresence(connected)
                    },
                )
            }
        }
    }

    fun syncOneDrive() {
        val snapshot = mutableState.value
        if (snapshot.busy || !snapshot.vaultUnlocked || snapshot.editor != null) return
        mutableState.update { it.copy(busy = true, status = "Synchronizing OneDrive") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatchingUnlessCancelled {
                syncThenRefreshProjection(
                    sync = graph.oneDriveWorkflow::sync,
                    refresh = graph.vaultWorkflow::browse,
                )
            }
            val connected = graph.oneDriveTokenAdapter.hasStoredToken()
            mutableState.update { current ->
                result.fold(
                    onSuccess = { synced ->
                        val status = synced.status
                        current.copy(
                            busy = false,
                            status = synced.projection.fold(
                                onSuccess = { syncStatusLabel(status) },
                                onFailure = {
                                    "${syncStatusLabel(status)}; browse failed " +
                                        "(${it.javaClass.simpleName})"
                                },
                            ),
                            syncStatus = status,
                            entries = synced.projection.getOrDefault(current.entries),
                            conflictCopyPath = null,
                        ).reconcileOneDriveTokenPresence(connected)
                    },
                    onFailure = {
                        current.copy(
                            busy = false,
                            status = "OneDrive sync failed: ${it.javaClass.simpleName}",
                            syncStatus = runCatching {
                                graph.oneDriveWorkflow.status()
                            }.getOrNull() ?: current.syncStatus,
                        ).reconcileOneDriveTokenPresence(connected)
                    },
                )
            }
        }
    }

    private fun browseOneDrive(parentItemId: String?) {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(busy = true, status = "Loading OneDrive files") }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatchingUnlessCancelled {
                graph.oneDriveWorkflow.browse(parentItemId)
            }
            val connected = graph.oneDriveTokenAdapter.hasStoredToken()
            mutableState.update { current ->
                result.fold(
                    onSuccess = { items ->
                        current.copy(
                            busy = false,
                            status = "Choose a OneDrive KDBX vault",
                            oneDriveItems = items,
                            oneDriveFolderId = parentItemId,
                        ).reconcileOneDriveTokenPresence(connected)
                    },
                    onFailure = {
                        current.copy(
                            busy = false,
                            status = "OneDrive listing failed: ${it.javaClass.simpleName}",
                        ).reconcileOneDriveTokenPresence(connected)
                    },
                )
            }
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
                syncStatus = runCatching { graph.oneDriveWorkflow.status() }.getOrNull(),
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
            "Vault unlocked; platform reconciliation needs retry ($it)"
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

    private fun syncStatusLabel(status: AndroidSyncStatus): String = when {
        status.conflictCopyCreated -> "OneDrive sync completed with a recoverable conflict copy"
        status.remoteState == "online" -> "OneDrive sync complete"
        else -> "OneDrive sync pending; the durable local cache is retained"
    }

    companion object {
        private const val INITIAL_STATUS = "Select a vault and unlock it"
    }
}

internal fun UnlockUiState.reconcileOneDriveTokenPresence(connected: Boolean): UnlockUiState =
    if (connected) {
        copy(oneDriveConnected = true)
    } else {
        copy(
            oneDriveConnected = false,
            oneDriveAccountLabel = null,
            oneDriveItems = emptyList(),
            oneDriveFolderId = null,
        )
    }

internal fun UnlockUiState.withSelectedLocalVault(
    displayName: String,
): UnlockUiState = copy(
    vaultPath = "",
    selectedVaultName = displayName,
    currentVaultSelected = true,
    oneDriveVaultSelected = false,
    oneDriveSelectedName = null,
    syncStatus = null,
)

internal fun UnlockUiState.withSelectedOneDriveVault(
    displayName: String,
    status: AndroidSyncStatus?,
): UnlockUiState = copy(
    vaultPath = "",
    selectedVaultName = null,
    currentVaultSelected = true,
    oneDriveVaultSelected = true,
    oneDriveSelectedName = displayName,
    syncStatus = status,
)

internal fun UnlockUiState.withCurrentVaultUnlockState(
    enrollment: UnlockEnrollmentState,
    securityLevel: UnlockKeySecurityLevel?,
): UnlockUiState = copy(
    enrollmentState = enrollment,
    keySecurityLevel = securityLevel,
)

internal fun UnlockUiState.withRestoredVaultSelection(
    selection: CurrentVaultSelection?,
    status: AndroidSyncStatus?,
): UnlockUiState = when {
    selection == null -> copy(
        vaultPath = "",
        selectedVaultName = null,
        currentVaultSelected = false,
        oneDriveVaultSelected = false,
        oneDriveSelectedName = null,
        syncStatus = null,
    )
    selection.sourceKind == "onedrive" -> copy(
        vaultPath = "",
        selectedVaultName = null,
        currentVaultSelected = true,
        oneDriveVaultSelected = true,
        oneDriveSelectedName = selection.displayName,
        syncStatus = status,
    )
    else -> copy(
        vaultPath = "",
        selectedVaultName = selection.displayName,
        currentVaultSelected = true,
        oneDriveVaultSelected = false,
        oneDriveSelectedName = null,
        syncStatus = null,
    )
}

private data class StartupSnapshot(
    val enrollment: UnlockEnrollmentState,
    val security: UnlockKeySecurityLevel?,
    val unlocked: Boolean,
    val entries: List<VaultEntryListItem>,
    val syncStatus: AndroidSyncStatus?,
    val currentSelection: CurrentVaultSelection?,
    val oneDriveConnected: Boolean,
)

internal data class BestEffortReconciliationResult<T>(
    val value: T,
    val reconciliationFailure: String?,
)

internal inline fun <T> loadAfterBestEffortReconciliation(
    reconcile: () -> Unit,
    load: () -> T,
): BestEffortReconciliationResult<T> {
    val reconciliationFailure = try {
        reconcile()
        null
    } catch (error: CancellationException) {
        throw error
    } catch (error: Exception) {
        error.javaClass.simpleName
    }
    return BestEffortReconciliationResult(load(), reconciliationFailure)
}

internal inline fun <T> runCatchingUnlessCancelled(block: () -> T): Result<T> = try {
    Result.success(block())
} catch (error: CancellationException) {
    throw error
} catch (error: Exception) {
    Result.failure(error)
}

internal data class SyncProjectionResult<T>(
    val status: AndroidSyncStatus,
    val projection: Result<T>,
)

internal inline fun <T> syncThenRefreshProjection(
    sync: () -> AndroidSyncStatus,
    refresh: () -> T,
): SyncProjectionResult<T> {
    val status = sync()
    val projection = try {
        Result.success(refresh())
    } catch (error: CancellationException) {
        throw error
    } catch (error: Exception) {
        Result.failure(error)
    }
    return SyncProjectionResult(status, projection)
}

internal data class OneDriveLoginProjection(
    val account: OneDriveAccount,
    val items: Result<List<OneDriveBrowserItem>>,
)

internal inline fun completeOneDriveLoginAndLoadItems(
    complete: () -> OneDriveAccount,
    loadItems: () -> List<OneDriveBrowserItem>,
): OneDriveLoginProjection {
    val account = complete()
    return OneDriveLoginProjection(
        account = account,
        items = runCatchingUnlessCancelled(loadItems),
    )
}
