package org.vaultkern.android.storage

import java.io.File
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
    fun selectedUriRemainsTheAuthorityAcrossWorkingCopyRefreshes() {
        val uri = "content://vault-provider/document/current"
        val documents = MemoryLocalDocuments().apply {
            put(uri, byteArrayOf(1, 2, 3), modifiedAt = 10)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("documents"), documents)

        val selected = workspace.select(uri, "current.kdbx")

        assertArrayEquals(byteArrayOf(1, 2, 3), File(selected.privatePath).readBytes())
        assertEquals(uri, workspace.bindingFor(selected.privatePath)?.sourceUri)

        documents.put(uri, byteArrayOf(4, 5, 6), modifiedAt = 11)
        assertEquals(listOf(selected.privatePath), workspace.refreshFromAuthorities())
        assertArrayEquals(byteArrayOf(4, 5, 6), File(selected.privatePath).readBytes())
    }

    @Test
    fun selectionRetainsTheUriGrantBeforeReadingTheAuthority() {
        val events = mutableListOf<String>()
        val access = object : PersistableLocalDocumentAccess {
            override fun retainReadWrite(uri: String) {
                events += "retain:$uri"
            }

            override fun displayName(uri: String): String = "picked.kdbx"

            override fun read(uri: String): LocalDocumentSnapshot {
                events += "read:$uri"
                return LocalDocumentSnapshot(byteArrayOf(7, 8, 9), modifiedAt = null)
            }
        }
        val selection = LocalDocumentSelectionService(
            access,
            LocalDocumentWorkspace(temporary.newFolder("selection"), access),
        )

        val selected = selection.select("content://vault-provider/document/picked")

        assertEquals(
            listOf(
                "retain:content://vault-provider/document/picked",
                "read:content://vault-provider/document/picked",
            ),
            events,
        )
        assertEquals("picked.kdbx", selected.displayName)
        assertTrue(File(selected.privatePath).isFile)
    }

    @Test
    fun missingWorkingCopyIsRebuiltFromThePersistedAuthority() {
        val uri = "content://vault-provider/document/recoverable"
        val documents = MemoryLocalDocuments().apply {
            put(uri, byteArrayOf(1, 2, 3), modifiedAt = 10)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("recovery"), documents)
        val selected = workspace.select(uri, "recoverable.kdbx")
        assertTrue(File(selected.privatePath).delete())
        documents.put(uri, byteArrayOf(9, 8, 7), modifiedAt = 11)

        assertEquals(listOf(selected.privatePath), workspace.refreshFromAuthorities())
        assertArrayEquals(byteArrayOf(9, 8, 7), File(selected.privatePath).readBytes())
    }

    @Test
    fun divergentWorkingCopyIsRebuiltEvenWhenTheAuthorityBaselineDidNotChange() {
        val uri = "content://vault-provider/document/diverged"
        val documents = MemoryLocalDocuments().apply {
            put(uri, byteArrayOf(1, 2, 3), modifiedAt = 10)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("diverged"), documents)
        val selected = workspace.select(uri, "diverged.kdbx")
        File(selected.privatePath).writeBytes(byteArrayOf(9, 9, 9))

        assertTrue(workspace.refresh(selected.privatePath))
        assertArrayEquals(byteArrayOf(1, 2, 3), File(selected.privatePath).readBytes())
    }

    @Test
    fun refreshingTheCurrentDocumentDoesNotTouchAnUnrelatedRevokedAuthority() {
        val revokedUri = "content://vault-provider/document/revoked"
        val currentUri = "content://vault-provider/document/current"
        val documents = MemoryLocalDocuments().apply {
            put(revokedUri, byteArrayOf(1), modifiedAt = 10)
            put(currentUri, byteArrayOf(2), modifiedAt = 10)
        }
        val workspace = LocalDocumentWorkspace(temporary.newFolder("current-only"), documents)
        workspace.select(revokedUri, "revoked.kdbx")
        val current = workspace.select(currentUri, "current.kdbx")
        documents.remove(revokedUri)
        documents.put(currentUri, byteArrayOf(3), modifiedAt = 11)

        assertTrue(workspace.refresh(current.privatePath))
        assertArrayEquals(byteArrayOf(3), File(current.privatePath).readBytes())
    }
}

private class MemoryLocalDocuments : LocalDocumentAccess {
    private data class Stored(val bytes: ByteArray, val modifiedAt: Long?)
    private val values = mutableMapOf<String, Stored>()

    fun put(uri: String, bytes: ByteArray, modifiedAt: Long?) {
        values.put(uri, Stored(bytes.copyOf(), modifiedAt))?.bytes?.fill(0)
    }

    fun remove(uri: String) {
        values.remove(uri)?.bytes?.fill(0)
    }

    override fun read(uri: String): LocalDocumentSnapshot {
        val stored = requireNotNull(values[uri])
        return LocalDocumentSnapshot(stored.bytes.copyOf(), stored.modifiedAt)
    }
}
