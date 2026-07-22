package org.vaultkern.android.vault

import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.vaultkern.android.storage.LocalDocumentAccess
import org.vaultkern.android.storage.LocalDocumentPublishStatus
import org.vaultkern.android.storage.LocalDocumentSnapshot
import org.vaultkern.android.storage.LocalDocumentWorkspace

class SelectedLocalDocumentSaveCoordinatorTest {
    @get:Rule
    val temporary = TemporaryFolder()

    @Test
    fun completedCoreSaveIsPublishedToTheSelectedLocalDocument() {
        val uri = "content://documents/local/vault.kdbx"
        val candidate = ByteArray(72) { 51 }
        val access = CoordinatorDocumentAccess(uri, ByteArray(48) { 50 })
        val workspace = LocalDocumentWorkspace(temporary.newFolder("published"), access)
        val selected = workspace.select(uri, "vault.kdbx")
        val transaction = assertNotNullTransaction(
            SelectedLocalDocumentSaveCoordinator(workspace).prepare(selected.privatePath),
        )

        File(selected.privatePath).writeBytes(candidate)
        val result = transaction.complete(VaultSaveResult(VaultSaveStatus.SAVED))

        assertEquals(VaultSaveStatus.SAVED, result.status)
        assertArrayEquals(candidate, access.bytes)
    }

    @Test
    fun providerFailureReportsARecoverablePrivateSaveInsteadOfDurablePublication() {
        val uri = "content://documents/local/vault.kdbx"
        val original = ByteArray(56) { 52 }
        val candidate = ByteArray(84) { 53 }
        val access = CoordinatorDocumentAccess(uri, original).apply { failReplace = true }
        val root = temporary.newFolder("pending")
        val workspace = LocalDocumentWorkspace(root, access)
        val selected = workspace.select(uri, "vault.kdbx")
        val transaction = assertNotNullTransaction(
            SelectedLocalDocumentSaveCoordinator(workspace).prepare(selected.privatePath),
        )

        File(selected.privatePath).writeBytes(candidate)
        val result = transaction.complete(VaultSaveResult(VaultSaveStatus.SAVED))

        assertEquals(VaultSaveStatus.SAVED_TO_CACHE, result.status)
        assertArrayEquals(original, access.bytes)
        access.failReplace = false
        assertEquals(1, LocalDocumentWorkspace(root, access).reconcilePending().size)
        assertArrayEquals(candidate, access.bytes)
    }

    @Test
    fun abandonedCoreSaveReleasesTheInProcessGuardButKeepsItsReceiptRecoverable() {
        val uri = "content://documents/local/vault.kdbx"
        val access = CoordinatorDocumentAccess(uri, ByteArray(48) { 54 })
        val workspace = LocalDocumentWorkspace(temporary.newFolder("abandoned"), access)
        val selected = workspace.select(uri, "vault.kdbx")
        val transaction = assertNotNullTransaction(
            SelectedLocalDocumentSaveCoordinator(workspace).prepare(selected.privatePath),
        )

        transaction.abandon()

        assertEquals(LocalDocumentPublishStatus.NO_CHANGE, workspace.reconcilePending().single().status)
        val retried = assertNotNullTransaction(
            SelectedLocalDocumentSaveCoordinator(workspace).prepare(selected.privatePath),
        )
        retried.abandon()
    }

    @Test
    fun providerPreflightReadFailureKeepsARecoverablePrivateSave() {
        val uri = "content://documents/local/vault.kdbx"
        val original = ByteArray(60) { 54 }
        val candidate = ByteArray(92) { 55 }
        val access = CoordinatorDocumentAccess(uri, original)
        val root = temporary.newFolder("pending-preflight")
        val workspace = LocalDocumentWorkspace(root, access)
        val selected = workspace.select(uri, "vault.kdbx")
        val transaction = assertNotNullTransaction(
            SelectedLocalDocumentSaveCoordinator(workspace).prepare(selected.privatePath),
        )
        File(selected.privatePath).writeBytes(candidate)
        access.failRead = true

        val result = transaction.complete(VaultSaveResult(VaultSaveStatus.SAVED))

        assertEquals(VaultSaveStatus.SAVED_TO_CACHE, result.status)
        assertArrayEquals(original, access.bytes)
        access.failRead = false
        assertEquals(1, LocalDocumentWorkspace(root, access).reconcilePending().size)
        assertArrayEquals(candidate, access.bytes)
    }

    private fun assertNotNullTransaction(
        value: SelectedLocalDocumentSaveTransaction?,
    ): SelectedLocalDocumentSaveTransaction {
        assertNotNull(value)
        return requireNotNull(value)
    }
}

private class CoordinatorDocumentAccess(
    private val expectedUri: String,
    initial: ByteArray,
) : LocalDocumentAccess {
    var bytes: ByteArray = initial.copyOf()
        private set
    var failReplace = false
    var failRead = false
    private var modifiedAt = 1L

    override fun read(uri: String): LocalDocumentSnapshot {
        require(uri == expectedUri)
        if (failRead) throw IllegalStateException("injected provider read failure")
        return LocalDocumentSnapshot(bytes.copyOf(), modifiedAt)
    }

    override fun replace(uri: String, bytes: ByteArray) {
        require(uri == expectedUri)
        if (failReplace) throw IllegalStateException("injected provider failure")
        this.bytes = bytes.copyOf()
        modifiedAt += 1
    }

    override fun createConflictCopy(
        sourceUri: String,
        displayName: String,
        bytes: ByteArray,
    ): String? = null
}
