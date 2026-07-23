package org.vaultkern.android.storage

import java.io.File
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class LocalDocumentWorkspaceTest {
    @get:Rule
    val temporary = TemporaryFolder()

    @Test
    fun selectionMaterializesTheChosenDocumentAndPersistsItsAuthority() {
        val uri = "content://documents/local/vault.kdbx"
        val sourceBytes = ByteArray(64) { it.toByte() }
        val documents = MemoryLocalDocuments().apply {
            put(uri, sourceBytes, modifiedAt = 41L)
        }
        val root = temporary.newFolder("local-documents")

        val selected = LocalDocumentWorkspace(root, documents).select(uri, "vault.kdbx")

        assertTrue(File(selected.privatePath).canonicalPath.startsWith(root.canonicalPath))
        assertArrayEquals(sourceBytes, File(selected.privatePath).readBytes())
        val restored = LocalDocumentWorkspace(root, documents).bindingFor(selected.privatePath)
        assertEquals(uri, restored?.sourceUri)
        assertEquals("vault.kdbx", restored?.displayName)
    }

    @Test
    fun committedPrivateSavePublishesBackToTheSameChosenDocument() {
        val uri = "content://documents/local/vault.kdbx"
        val original = ByteArray(48) { 1 }
        val candidate = ByteArray(72) { 2 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, original, modifiedAt = 7L)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("publish"), documents)
        val selected = workspace.select(uri, "vault.kdbx")

        workspace.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        val result = workspace.publishAfterSave(selected.privatePath)

        assertEquals(LocalDocumentPublishStatus.PUBLISHED, result.status)
        assertEquals(listOf(uri), documents.replacedUris)
        assertArrayEquals(candidate, documents.bytes(uri))
        assertEquals(
            LocalDocumentWorkspace.fingerprint(documents.read(uri)),
            workspace.bindingFor(selected.privatePath)?.baseline,
        )
    }

    @Test
    fun foreignChangeForksTheCandidateWithoutOverwritingTheChosenDocument() {
        val uri = "content://documents/local/vault.kdbx"
        val conflictUri = "content://documents/local/vault-vaultkern-conflict.kdbx"
        val original = ByteArray(32) { 3 }
        val foreign = ByteArray(32) { 4 }
        val candidate = ByteArray(40) { 5 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, original, modifiedAt = 10L)
            nextConflictUri = conflictUri
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("conflict"), documents)
        val selected = workspace.select(uri, "vault.kdbx")

        workspace.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        documents.put(uri, foreign, modifiedAt = 11L)
        val result = workspace.publishAfterSave(selected.privatePath)

        assertEquals(LocalDocumentPublishStatus.CONFLICT_COPY, result.status)
        assertEquals(conflictUri, result.conflictLocation)
        assertArrayEquals(foreign, documents.bytes(uri))
        assertArrayEquals(candidate, documents.bytes(conflictUri))
        assertTrue(documents.replacedUris.isEmpty())
        assertEquals(conflictUri, workspace.bindingFor(selected.privatePath)?.sourceUri)
    }

    @Test
    fun providerWithoutSiblingCreationKeepsARecoverablePrivateConflictCopy() {
        val uri = "content://documents/local/vault.kdbx"
        val foreign = ByteArray(28) { 8 }
        val candidate = ByteArray(36) { 9 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(28) { 7 }, modifiedAt = 20L)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("private-conflict"), documents)
        val selected = workspace.select(uri, "vault.kdbx")

        workspace.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        documents.put(uri, foreign, modifiedAt = 21L)
        val result = workspace.publishAfterSave(selected.privatePath)

        assertEquals(LocalDocumentPublishStatus.CONFLICT_COPY, result.status)
        val conflict = File(requireNotNull(result.conflictLocation))
        assertTrue(conflict.isFile)
        assertArrayEquals(candidate, conflict.readBytes())
        assertArrayEquals(foreign, documents.bytes(uri))
        assertEquals(null, workspace.bindingFor(selected.privatePath)?.sourceUri)
    }

    @Test
    fun processRestartPublishesACommittedMirrorFromItsPendingReceipt() {
        val uri = "content://documents/local/vault.kdbx"
        val candidate = ByteArray(80) { 12 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(64) { 11 }, modifiedAt = 30L)
        }
        val root = temporary.newFolder("restart")
        val firstProcess = LocalDocumentWorkspace(root, documents)
        val selected = firstProcess.select(uri, "vault.kdbx")

        firstProcess.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        val recovered = LocalDocumentWorkspace(root, documents).reconcilePending()

        assertEquals(LocalDocumentPublishStatus.PUBLISHED, recovered.single().status)
        assertArrayEquals(candidate, documents.bytes(uri))
        assertTrue(LocalDocumentWorkspace(root, documents).reconcilePending().isEmpty())
    }

    @Test
    fun transientProviderWriteFailureKeepsTheSavePendingForRestartRecovery() {
        val uri = "content://documents/local/vault.kdbx"
        val original = ByteArray(48) { 13 }
        val candidate = ByteArray(96) { 14 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, original, modifiedAt = 40L)
            failNextReplace = true
        }
        val root = temporary.newFolder("transient-write-failure")
        val firstProcess = LocalDocumentWorkspace(root, documents)
        val selected = firstProcess.select(uri, "vault.kdbx")

        firstProcess.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        val failedAttempt = firstProcess.publishAfterSave(selected.privatePath)

        assertEquals(LocalDocumentPublishStatus.PENDING, failedAttempt.status)
        assertArrayEquals(original, documents.bytes(uri))

        val recovered = LocalDocumentWorkspace(root, documents).reconcilePending()
        assertEquals(LocalDocumentPublishStatus.PUBLISHED, recovered.single().status)
        assertArrayEquals(candidate, documents.bytes(uri))
    }

    @Test
    fun restartRecognizesAProviderWriteThatCompletedBeforeTheCallFailed() {
        val uri = "content://documents/local/vault.kdbx"
        val candidate = ByteArray(88) { 16 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(44) { 15 }, modifiedAt = 50L)
            throwAfterNextReplace = true
        }
        val root = temporary.newFolder("ambiguous-write")
        val firstProcess = LocalDocumentWorkspace(root, documents)
        val selected = firstProcess.select(uri, "vault.kdbx")

        firstProcess.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        val ambiguousAttempt = firstProcess.publishAfterSave(selected.privatePath)
        assertEquals(LocalDocumentPublishStatus.PENDING, ambiguousAttempt.status)
        assertArrayEquals(candidate, documents.bytes(uri))

        val restarted = LocalDocumentWorkspace(root, documents)
        val recovered = restarted.reconcilePending()

        assertEquals(LocalDocumentPublishStatus.PUBLISHED, recovered.single().status)
        assertTrue(restarted.reconcilePending().isEmpty())
        assertEquals(uri, restarted.bindingFor(selected.privatePath)?.sourceUri)
        assertTrue(documents.createdConflictUris.isEmpty())
    }

    @Test
    fun ambiguousWriteFollowedByAForeignChangeForksInsteadOfOverwriting() {
        val uri = "content://documents/local/vault.kdbx"
        val conflictUri = "content://documents/local/vault-vaultkern-conflict.kdbx"
        val original = ByteArray(44) { 31 }
        val candidate = ByteArray(88) { 32 }
        val foreign = ByteArray(66) { 33 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, original, modifiedAt = 55L)
            throwAfterNextReplace = true
            nextConflictUri = conflictUri
        }
        val root = temporary.newFolder("ambiguous-then-foreign")
        val firstProcess = LocalDocumentWorkspace(root, documents)
        val selected = firstProcess.select(uri, "vault.kdbx")

        firstProcess.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        assertEquals(
            LocalDocumentPublishStatus.PENDING,
            firstProcess.publishAfterSave(selected.privatePath).status,
        )
        documents.put(uri, foreign, modifiedAt = 57L)

        val recovered = LocalDocumentWorkspace(root, documents).reconcilePending().single()

        assertEquals(LocalDocumentPublishStatus.CONFLICT_COPY, recovered.status)
        assertEquals(conflictUri, recovered.conflictLocation)
        assertArrayEquals(foreign, documents.bytes(uri))
        assertArrayEquals(candidate, documents.bytes(conflictUri))
    }

    @Test
    fun readbackMismatchForksTheCandidateInsteadOfOverwritingAmbiguousContent() {
        val uri = "content://documents/local/vault.kdbx"
        val candidate = ByteArray(104) { 18 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(52) { 17 }, modifiedAt = 60L)
            corruptNextReplace = true
        }
        val root = temporary.newFolder("readback-mismatch")
        val firstProcess = LocalDocumentWorkspace(root, documents)
        val selected = firstProcess.select(uri, "vault.kdbx")

        firstProcess.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        val mismatched = firstProcess.publishAfterSave(selected.privatePath)

        assertEquals(LocalDocumentPublishStatus.PENDING, mismatched.status)
        val ambiguousContent = documents.bytes(uri)
        assertTrue(!ambiguousContent.contentEquals(candidate))

        val recovered = LocalDocumentWorkspace(root, documents).reconcilePending()
        assertEquals(LocalDocumentPublishStatus.CONFLICT_COPY, recovered.single().status)
        assertArrayEquals(ambiguousContent, documents.bytes(uri))
        assertArrayEquals(candidate, File(requireNotNull(recovered.single().conflictLocation)).readBytes())
        assertTrue(documents.createdConflictUris.isEmpty())
    }

    @Test
    fun authorityRefreshUpdatesThePrivateMirrorBeforeAQuickUnlock() {
        val uri = "content://documents/local/vault.kdbx"
        val foreign = ByteArray(120) { 20 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(60) { 19 }, modifiedAt = 70L)
        }
        val root = temporary.newFolder("authority-refresh")
        val workspace = LocalDocumentWorkspace(root, documents)
        val selected = workspace.select(uri, "vault.kdbx")
        documents.put(uri, foreign, modifiedAt = 71L)

        val refreshed = workspace.refreshFromAuthorities()

        assertEquals(listOf(selected.privatePath), refreshed)
        assertArrayEquals(foreign, File(selected.privatePath).readBytes())
        assertEquals(
            LocalDocumentWorkspace.fingerprint(documents.read(uri)),
            workspace.bindingFor(selected.privatePath)?.baseline,
        )
    }

    @Test
    fun authorityRefreshNeverOverwritesAPendingPrivateSave() {
        val uri = "content://documents/local/vault.kdbx"
        val candidate = ByteArray(128) { 22 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(64) { 21 }, modifiedAt = 80L)
        }
        val root = temporary.newFolder("pending-refresh")
        val workspace = LocalDocumentWorkspace(root, documents)
        val selected = workspace.select(uri, "vault.kdbx")
        workspace.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        documents.put(uri, ByteArray(64) { 23 }, modifiedAt = 81L)

        val refreshed = workspace.refreshFromAuthorities()

        assertTrue(refreshed.isEmpty())
        assertArrayEquals(candidate, File(selected.privatePath).readBytes())
    }

    @Test
    fun metadataOnlyProviderChangeDoesNotForkAnUnchangedSource() {
        val uri = "content://documents/local/vault.kdbx"
        val original = ByteArray(68) { 24 }
        val candidate = ByteArray(136) { 25 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, original, modifiedAt = 90L)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("metadata-only"), documents)
        val selected = workspace.select(uri, "vault.kdbx")
        workspace.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        documents.put(uri, original, modifiedAt = 91L)

        val result = workspace.publishAfterSave(selected.privatePath)

        assertEquals(LocalDocumentPublishStatus.PUBLISHED, result.status)
        assertArrayEquals(candidate, documents.bytes(uri))
        assertTrue(documents.createdConflictUris.isEmpty())
    }

    @Test
    fun reselectingTheSameUriCannotOverwriteAnUnpublishedCandidate() {
        val uri = "content://documents/local/vault.kdbx"
        val candidate = ByteArray(144) { 27 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(72) { 26 }, modifiedAt = 100L)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("pending-reselection"), documents)
        val selected = workspace.select(uri, "vault.kdbx")
        workspace.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(candidate)
        documents.failNextReplace = true
        assertEquals(
            LocalDocumentPublishStatus.PENDING,
            workspace.publishAfterSave(selected.privatePath).status,
        )
        documents.failNextReplace = true

        val reselected = runCatching { workspace.select(uri, "vault.kdbx") }

        assertTrue(reselected.isFailure)
        assertArrayEquals(candidate, File(selected.privatePath).readBytes())
        assertEquals(LocalDocumentPublishStatus.PUBLISHED, workspace.reconcilePending().single().status)
        assertArrayEquals(candidate, documents.bytes(uri))
    }

    @Test
    fun backgroundRecoverySkipsAReceiptWhileItsCoreSaveIsActive() {
        val uri = "content://documents/local/vault.kdbx"
        val candidate = ByteArray(96) { 35 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(48) { 34 }, modifiedAt = 110L)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("active-save"), documents)
        val selected = workspace.select(uri, "vault.kdbx")

        workspace.prepareSave(selected.privatePath)

        assertTrue(workspace.reconcilePending().isEmpty())
        File(selected.privatePath).writeBytes(candidate)
        assertEquals(
            LocalDocumentPublishStatus.PUBLISHED,
            workspace.publishAfterSave(selected.privatePath).status,
        )
        assertArrayEquals(candidate, documents.bytes(uri))
    }

    @Test
    fun privateConflictCopiesNeverOverwriteAnEarlierConflict() {
        val uri = "content://documents/local/vault.kdbx"
        val firstCandidate = ByteArray(80) { 37 }
        val secondCandidate = ByteArray(84) { 39 }
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(40) { 36 }, modifiedAt = 120L)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("unique-private-conflicts"), documents)
        val selected = workspace.select(uri, "vault.kdbx")

        workspace.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(firstCandidate)
        documents.put(uri, ByteArray(40) { 38 }, modifiedAt = 121L)
        val firstConflict = File(
            requireNotNull(workspace.publishAfterSave(selected.privatePath).conflictLocation),
        )

        workspace.select(uri, "vault.kdbx")
        workspace.prepareSave(selected.privatePath)
        File(selected.privatePath).writeBytes(secondCandidate)
        documents.put(uri, ByteArray(40) { 40 }, modifiedAt = 122L)
        val secondConflict = File(
            requireNotNull(workspace.publishAfterSave(selected.privatePath).conflictLocation),
        )

        assertTrue(firstConflict.canonicalPath != secondConflict.canonicalPath)
        assertArrayEquals(firstCandidate, firstConflict.readBytes())
        assertArrayEquals(secondCandidate, secondConflict.readBytes())
    }

    @Test
    fun atomicMetadataCommitPropagatesDirectorySyncFailure() {
        val uri = "content://documents/local/vault.kdbx"
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(32) { 41 }, modifiedAt = 130L)
        }
        val workspace = LocalDocumentWorkspace(
            root = temporary.newFolder("directory-sync-failure"),
            documents = documents,
            directorySync = { throw IOException("injected directory sync failure") },
        )

        val selected = runCatching { workspace.select(uri, "vault.kdbx") }

        assertTrue(selected.isFailure)
        assertEquals("injected directory sync failure", selected.exceptionOrNull()?.message)
    }

    @Test
    fun atomicMetadataCommitNeverFallsBackToANonAtomicMove() {
        val uri = "content://documents/local/vault.kdbx"
        val documents = MemoryLocalDocuments().apply {
            put(uri, ByteArray(32) { 42 }, modifiedAt = 140L)
        }
        val workspace = LocalDocumentWorkspace(
            root = temporary.newFolder("atomic-move-failure"),
            documents = documents,
            atomicMove = { _, _ -> throw IOException("injected atomic move failure") },
        )

        val selected = runCatching { workspace.select(uri, "vault.kdbx") }

        assertTrue(selected.isFailure)
        assertEquals("injected atomic move failure", selected.exceptionOrNull()?.message)
    }
}

private class MemoryLocalDocuments : LocalDocumentAccess {
    private data class StoredDocument(
        var bytes: ByteArray,
        var modifiedAt: Long?,
    )

    private val documents = linkedMapOf<String, StoredDocument>()
    val replacedUris = mutableListOf<String>()
    val createdConflictUris = mutableListOf<String>()
    var nextConflictUri: String? = null
    var failNextReplace: Boolean = false
    var throwAfterNextReplace: Boolean = false
    var corruptNextReplace: Boolean = false

    fun put(uri: String, bytes: ByteArray, modifiedAt: Long?) {
        documents[uri] = StoredDocument(bytes.copyOf(), modifiedAt)
    }

    override fun read(uri: String): LocalDocumentSnapshot {
        val stored = requireNotNull(documents[uri])
        return LocalDocumentSnapshot(stored.bytes.copyOf(), stored.modifiedAt)
    }

    override fun replace(uri: String, bytes: ByteArray) {
        if (failNextReplace) {
            failNextReplace = false
            throw IllegalStateException("injected provider write failure")
        }
        val stored = requireNotNull(documents[uri])
        replacedUris += uri
        stored.bytes = if (corruptNextReplace) {
            corruptNextReplace = false
            bytes.copyOf(bytes.size / 2)
        } else {
            bytes.copyOf()
        }
        stored.modifiedAt = (stored.modifiedAt ?: 0L) + 1L
        if (throwAfterNextReplace) {
            throwAfterNextReplace = false
            throw IllegalStateException("injected failure after provider write")
        }
    }

    fun bytes(uri: String): ByteArray = requireNotNull(documents[uri]).bytes.copyOf()

    override fun createConflictCopy(
        sourceUri: String,
        displayName: String,
        bytes: ByteArray,
    ): String? {
        val uri = nextConflictUri ?: return null
        put(uri, bytes, modifiedAt = 1L)
        createdConflictUris += uri
        nextConflictUri = null
        return uri
    }
}
