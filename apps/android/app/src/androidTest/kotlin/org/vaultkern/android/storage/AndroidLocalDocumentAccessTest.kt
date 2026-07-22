package org.vaultkern.android.storage

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.FileOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidLocalDocumentAccessTest {
    @Test
    fun contentResolverReadsAndReplacesTheChosenUri() {
        val resolver = InstrumentationRegistry.getInstrumentation().context.contentResolver
        val uri = Uri.parse("content://org.vaultkern.android.test.documents/chosen.kdbx")
        val original = ByteArray(64) { 41 }
        val replacement = ByteArray(96) { 42 }
        resolver.openFileDescriptor(uri, "rwt").use { descriptor ->
            FileOutputStream(requireNotNull(descriptor).fileDescriptor).use { output ->
                output.write(original)
                output.flush()
                output.fd.sync()
            }
        }
        val access = AndroidLocalDocumentAccess(resolver)

        val opened = access.read(uri.toString())
        try {
            assertArrayEquals(original, opened.bytes)
            assertEquals("chosen.kdbx", access.displayName(uri.toString()))
        } finally {
            opened.bytes.fill(0)
        }

        access.replace(uri.toString(), replacement)
        val replaced = access.read(uri.toString())
        try {
            assertArrayEquals(replacement, replaced.bytes)
        } finally {
            replaced.bytes.fill(0)
            resolver.delete(uri, null, null)
        }
    }
}
