package org.vaultkern.android.sync

import java.util.Locale
import org.vaultkern.core.OneDriveAuthSessionDto
import org.vaultkern.core.OneDriveAuthStatusDto
import org.vaultkern.core.OneDriveItemDto
import org.vaultkern.core.VaultReferenceDto
import org.vaultkern.core.VaultSession
import org.vaultkern.core.VaultSourceStatusDto

fun interface OneDriveAuthPresenter {
    fun open(authUrl: String)
}

class PendingOneDriveLogin(
    val redirectUri: String,
    val expiresInSeconds: UInt,
) {
    override fun toString(): String =
        "PendingOneDriveLogin(redirectUri=[REDACTED], expiresInSeconds=$expiresInSeconds)"
}

class OneDriveAccount(val accountLabel: String?) {
    override fun toString(): String = "OneDriveAccount(accountLabel=[REDACTED])"
}

class OneDriveVaultPreloadException(
    val selected: SelectedOneDriveVault,
    cause: Exception,
) : Exception("the selected OneDrive vault could not be cached privately", cause)

data class OneDriveBrowserItem(
    val driveId: String,
    val itemId: String,
    val name: String,
    val folder: Boolean,
    val size: ULong?,
) {
    override fun toString(): String =
        "OneDriveBrowserItem(driveId=[REDACTED], itemId=[REDACTED], " +
            "name=[REDACTED], folder=$folder, size=$size)"
}

data class SelectedOneDriveVault(
    val vaultRefId: String,
    val displayName: String,
) {
    override fun toString(): String =
        "SelectedOneDriveVault(vaultRefId=[REDACTED], displayName=[REDACTED])"
}

data class AndroidSyncStatus(
    val sourceKind: String,
    val remoteState: String,
    val lastSyncAt: Long?,
    val cachedAt: Long?,
    val lastError: String?,
) {
    val conflictCopyCreated: Boolean
        get() {
            if (remoteState == "conflict_copy") return true
            if (remoteState != "online") return false
            val diagnostic = lastError?.lowercase(Locale.ROOT) ?: return false
            return diagnostic.contains("local changes were saved to onedrive:") ||
                diagnostic.contains("conflict-copy publication completed at onedrive:")
        }

    val retryRecommended: Boolean
        get() = remoteState == "pending_sync" || remoteState == "cache"

    override fun toString(): String =
        "AndroidSyncStatus(sourceKind=$sourceKind, remoteState=$remoteState, " +
            "lastSyncAt=$lastSyncAt, cachedAt=$cachedAt, " +
            "lastError=${if (lastError == null) "none" else "[REDACTED]"})"
}

internal interface OneDriveCoreGateway {
    fun beginLogin(): OneDriveAuthSessionDto
    fun completeLogin(): OneDriveAuthStatusDto
    fun listChildren(parentItemId: String?): List<OneDriveItemDto>
    fun addVault(driveId: String, itemId: String): VaultReferenceDto
    fun preloadCurrent()
    fun activeVaultId(): String?
    fun sync(vaultId: String): VaultSourceStatusDto
    fun status(): VaultSourceStatusDto?
}

class OneDriveWorkflow internal constructor(
    private val core: OneDriveCoreGateway,
    private val presenter: OneDriveAuthPresenter,
) {
    constructor(session: VaultSession, presenter: OneDriveAuthPresenter) :
        this(UniFfiOneDriveCoreGateway(session), presenter)

    fun beginLogin(): PendingOneDriveLogin {
        val pending = core.beginLogin()
        presenter.open(pending.authUrl)
        return PendingOneDriveLogin(pending.redirectUri, pending.expiresInSeconds)
    }

    fun completeLogin(): OneDriveAccount {
        val status = core.completeLogin()
        require(status.status == "authorized") { "OneDrive authorization did not complete" }
        return OneDriveAccount(status.accountLabel)
    }

    fun browse(parentItemId: String?): List<OneDriveBrowserItem> =
        core.listChildren(parentItemId)
            .map { item ->
                OneDriveBrowserItem(
                    item.driveId,
                    item.itemId,
                    item.name,
                    item.folder,
                    item.size,
                )
            }
            .sortedWith(compareByDescending<OneDriveBrowserItem> { it.folder }.thenBy { it.name })

    fun select(item: OneDriveBrowserItem): SelectedOneDriveVault {
        require(!item.folder) { "a OneDrive folder cannot be opened as a vault" }
        require(item.name.lowercase(Locale.ROOT).endsWith(".kdbx")) {
            "the selected OneDrive item is not a KDBX file"
        }
        val reference = core.addVault(item.driveId, item.itemId)
        val selected = SelectedOneDriveVault(reference.vaultRefId, reference.displayName)
        try {
            core.preloadCurrent()
        } catch (error: Exception) {
            throw OneDriveVaultPreloadException(selected, error)
        }
        return selected
    }

    fun status(): AndroidSyncStatus? = core.status()?.toAndroidStatus()

    fun sync(): AndroidSyncStatus {
        val vaultId = core.activeVaultId() ?: error("no active vault is available for sync")
        return core.sync(vaultId).toAndroidStatus()
    }

    private fun VaultSourceStatusDto.toAndroidStatus(): AndroidSyncStatus = AndroidSyncStatus(
        sourceKind,
        remoteState,
        lastSyncAt,
        cachedAt,
        lastError,
    )
}

private class UniFfiOneDriveCoreGateway(
    private val session: VaultSession,
) : OneDriveCoreGateway {
    override fun beginLogin(): OneDriveAuthSessionDto =
        session.sources().use { it.beginOneDriveLogin() }

    override fun completeLogin(): OneDriveAuthStatusDto =
        session.sources().use { it.completePendingOneDriveLogin() }

    override fun listChildren(parentItemId: String?): List<OneDriveItemDto> =
        session.sources().use { it.listOneDriveChildren(parentItemId).items }

    override fun addVault(driveId: String, itemId: String): VaultReferenceDto =
        session.sources().use { it.addOneDriveVault(driveId, itemId) }

    override fun preloadCurrent() {
        session.sources().use { it.preloadCurrentVault() }
    }

    override fun activeVaultId(): String? = session.sessionState().activeVaultId

    override fun sync(vaultId: String): VaultSourceStatusDto =
        session.sync().use { it.trigger(vaultId) }

    override fun status(): VaultSourceStatusDto? = session.sync().use { it.status() }
}
