package org.vaultkern.android.storage

import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class LocalDocumentSelectionServiceTest {
    @get:Rule
    val temporary = TemporaryFolder()

    @Test
    fun selectionRetainsReadWriteAuthorityBeforeMaterializingTheExactDocument() {
        val uri = "content://documents/local/chosen.kdbx"
        val bytes = ByteArray(32) { 31 }
        val access = RecordingPersistableAccess(uri, bytes)
        val workspace = LocalDocumentWorkspace(temporary.newFolder("selection"), access)
        val opened = mutableListOf<String>()

        val selected = LocalDocumentSelectionService(access, workspace) { opened += it }.select(uri)

        assertEquals(listOf("retain:$uri", "name:$uri", "read:$uri"), access.events)
        assertEquals(listOf(selected.privatePath), opened)
        assertEquals("chosen.kdbx", selected.displayName)
        assertArrayEquals(bytes, File(selected.privatePath).readBytes())
        assertEquals(uri, workspace.bindingFor(selected.privatePath)?.sourceUri)
    }
}

private class RecordingPersistableAccess(
    private val expectedUri: String,
    private val bytes: ByteArray,
) : PersistableLocalDocumentAccess {
    val events = mutableListOf<String>()

    override fun retainReadWrite(uri: String) {
        require(uri == expectedUri)
        events += "retain:$uri"
    }

    override fun displayName(uri: String): String {
        require(uri == expectedUri)
        events += "name:$uri"
        return "chosen.kdbx"
    }

    override fun read(uri: String): LocalDocumentSnapshot {
        require(uri == expectedUri)
        events += "read:$uri"
        return LocalDocumentSnapshot(bytes.copyOf(), 1L)
    }

    override fun replace(uri: String, bytes: ByteArray) = error("not used")

    override fun createConflictCopy(
        sourceUri: String,
        displayName: String,
        bytes: ByteArray,
    ): String? = error("not used")
}
