package org.vaultkern.android.vault

import java.util.concurrent.atomic.AtomicBoolean
import org.vaultkern.android.storage.LocalDocumentPublishStatus
import org.vaultkern.android.storage.LocalDocumentWorkspace

class SelectedLocalDocumentSaveCoordinator(
    private val workspace: LocalDocumentWorkspace,
) {
    fun prepare(vaultPath: String): SelectedLocalDocumentSaveTransaction? {
        val binding = workspace.bindingFor(vaultPath) ?: return null
        if (binding.sourceUri == null) return null
        workspace.prepareSave(vaultPath)
        return SelectedLocalDocumentSaveTransaction(workspace, vaultPath)
    }
}

class SelectedLocalDocumentSaveTransaction internal constructor(
    private val workspace: LocalDocumentWorkspace,
    private val vaultPath: String,
) {
    private val completed = AtomicBoolean(false)

    fun complete(coreResult: VaultSaveResult): VaultSaveResult {
        check(completed.compareAndSet(false, true)) {
            "selected local document save transaction already completed"
        }
        val publication = workspace.publishAfterSave(vaultPath)
        return when (publication.status) {
            LocalDocumentPublishStatus.PUBLISHED,
            LocalDocumentPublishStatus.NO_CHANGE,
            -> coreResult
            LocalDocumentPublishStatus.PENDING -> VaultSaveResult(VaultSaveStatus.SAVED_TO_CACHE)
            LocalDocumentPublishStatus.CONFLICT_COPY -> VaultSaveResult(
                status = VaultSaveStatus.CONFLICT_COPY,
                conflictCopyPath = publication.conflictLocation,
            )
        }
    }
}
