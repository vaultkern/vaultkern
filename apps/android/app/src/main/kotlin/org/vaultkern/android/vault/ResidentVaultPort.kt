package org.vaultkern.android.vault

import org.vaultkern.core.EntryCustomFieldDto
import org.vaultkern.core.EntryDetailDto
import org.vaultkern.core.EntryFieldsDto
import org.vaultkern.core.SaveVaultStatusDto
import org.vaultkern.core.VaultKernSensitiveString
import org.vaultkern.core.VaultSession

data class VaultEntryListItem(
    val id: String,
    val title: String,
    val username: String,
    val hasTotp: Boolean,
) {
    override fun toString(): String =
        "VaultEntryListItem(id=$id, title=[REDACTED], username=[REDACTED], hasTotp=$hasTotp)"
}

data class VaultCustomField(
    val key: String,
    val value: String,
    val protected: Boolean,
) {
    override fun toString(): String =
        "VaultCustomField(key=[REDACTED], value=[REDACTED], protected=$protected)"
}

data class VaultEntryDraft(
    val id: String,
    val title: String,
    val username: String,
    val password: String,
    val url: String,
    val notes: String,
    val totpUri: String?,
    val customFields: List<VaultCustomField>,
) {
    override fun toString(): String =
        "VaultEntryDraft(" +
            "id=$id, title=[REDACTED], username=[REDACTED], password=[REDACTED], " +
            "url=[REDACTED], notes=[REDACTED], totpUri=[REDACTED], " +
            "customFields=[REDACTED])"
}

enum class VaultSaveStatus {
    SAVED,
    MERGED,
    SAVED_TO_CACHE,
    CONFLICT_COPY,
}

data class VaultSaveResult(
    val status: VaultSaveStatus,
    val conflictCopyPath: String? = null,
)

interface ResidentVaultPort {
    fun listEntries(): List<VaultEntryListItem>
    fun readEntry(entryId: String): VaultEntryDraft
    fun editAndSave(draft: VaultEntryDraft): VaultSaveResult
    fun lock()
}

class VaultEditorWorkflow(
    private val port: ResidentVaultPort,
) {
    fun browse(): List<VaultEntryListItem> = port.listEntries()
    fun open(entryId: String): VaultEntryDraft = port.readEntry(entryId)
    fun save(draft: VaultEntryDraft): VaultSaveResult = port.editAndSave(draft)
    fun lock() = port.lock()
}

class VaultKernResidentVaultPort(
    private val session: VaultSession,
    private val selectedLocalDocuments: SelectedLocalDocumentSaveCoordinator? = null,
) : ResidentVaultPort {
    override fun listEntries(): List<VaultEntryListItem> =
        session.listEntries(activeVaultId()).map { entry ->
            VaultEntryListItem(
                id = entry.id,
                title = entry.title,
                username = entry.username,
                hasTotp = entry.hasTotp,
            )
        }

    override fun readEntry(entryId: String): VaultEntryDraft {
        val detail = session.readEntry(activeVaultId(), entryId)
        return try {
            VaultEntryDraft(
                id = detail.id.reveal(),
                title = detail.title.reveal(),
                username = detail.username.reveal(),
                password = detail.password.reveal(),
                url = detail.url.reveal(),
                notes = detail.notes.reveal(),
                totpUri = detail.totpUri?.reveal(),
                customFields = detail.customFields.map { field ->
                    VaultCustomField(
                        key = field.key.reveal(),
                        value = field.value.reveal(),
                        protected = field.protected,
                    )
                },
            )
        } finally {
            detail.closeSecrets()
        }
    }

    override fun editAndSave(draft: VaultEntryDraft): VaultSaveResult {
        val owners = mutableListOf<VaultKernSensitiveString>()
        fun sensitive(value: String): VaultKernSensitiveString =
            VaultKernSensitiveString.fromString(value).also(owners::add)

        var edited: EntryDetailDto? = null
        var localSave: SelectedLocalDocumentSaveTransaction? = null
        return try {
            val fields = EntryFieldsDto(
                title = sensitive(draft.title),
                username = sensitive(draft.username),
                password = sensitive(draft.password),
                url = sensitive(draft.url),
                notes = sensitive(draft.notes),
                totpUri = draft.totpUri?.let(::sensitive),
                customFields = draft.customFields.map { field ->
                    EntryCustomFieldDto(
                        key = sensitive(field.key),
                        value = sensitive(field.value),
                        protected = field.protected,
                    )
                },
            )
            val vaultId = activeVaultId()
            edited = session.editEntry(vaultId, draft.id, fields)
            edited.closeSecrets()
            edited = null
            localSave = selectedLocalDocuments?.prepare(vaultId)
            val result = session.save(vaultId)
            val coreResult = VaultSaveResult(
                status = when (result.status) {
                    SaveVaultStatusDto.SAVED -> VaultSaveStatus.SAVED
                    SaveVaultStatusDto.MERGED -> VaultSaveStatus.MERGED
                    SaveVaultStatusDto.SAVED_TO_CACHE -> VaultSaveStatus.SAVED_TO_CACHE
                    SaveVaultStatusDto.CONFLICT_COPY -> VaultSaveStatus.CONFLICT_COPY
                },
                conflictCopyPath = result.conflictCopyPath,
            )
            localSave?.complete(coreResult) ?: coreResult
        } finally {
            var cleanupFailure: Throwable? = null
            try {
                localSave?.abandon()
            } catch (error: Throwable) {
                cleanupFailure = error
            }
            try {
                edited?.closeSecrets()
            } catch (error: Throwable) {
                cleanupFailure?.addSuppressed(error) ?: run { cleanupFailure = error }
            }
            try {
                owners.closeAllSecrets()
            } catch (error: Throwable) {
                cleanupFailure?.addSuppressed(error) ?: run { cleanupFailure = error }
            }
            cleanupFailure?.let { throw it }
        }
    }

    override fun lock() {
        session.lockSession()
    }

    private fun activeVaultId(): String =
        session.sessionState().activeVaultId
            ?: error("no unlocked vault is active")
}

private fun EntryDetailDto.closeSecrets() {
    buildList {
        add(id)
        add(title)
        add(username)
        add(password)
        add(url)
        add(notes)
        totp?.let(::add)
        totpUri?.let(::add)
        customFields.forEach { field ->
            add(field.key)
            add(field.value)
        }
        attachments.forEach { add(it.name) }
        passkey?.let { value ->
            add(value.username)
            add(value.credentialId)
            value.generatedUserId?.let(::add)
            add(value.relyingParty)
            value.userHandle?.let(::add)
        }
    }.closeAllSecrets()
}

private fun Iterable<VaultKernSensitiveString>.closeAllSecrets() {
    var firstFailure: Throwable? = null
    forEach { owner ->
        try {
            owner.close()
        } catch (error: Throwable) {
            if (firstFailure == null) firstFailure = error
        }
    }
    firstFailure?.let { throw it }
}
