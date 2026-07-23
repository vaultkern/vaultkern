package org.vaultkern.android.storage

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.OpenableColumns

class AndroidLocalDocumentAccess(
    private val resolver: ContentResolver,
) : PersistableLocalDocumentAccess {
    override fun retainReadWrite(uri: String) {
        resolver.takePersistableUriPermission(
            contentUri(uri),
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
        )
    }

    override fun displayName(uri: String): String {
        val parsed = contentUri(uri)
        return resolver.query(
            parsed,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )?.use { cursor ->
            if (!cursor.moveToFirst() || cursor.isNull(0)) null else cursor.getString(0)
        }?.takeIf(String::isNotBlank)
            ?: parsed.lastPathSegment?.substringAfterLast('/')?.takeIf(String::isNotBlank)
            ?: "vault.kdbx"
    }

    override fun read(uri: String): LocalDocumentSnapshot {
        val parsed = contentUri(uri)
        val descriptor = requireNotNull(resolver.openFileDescriptor(parsed, "r")) {
            "selected local document could not be opened"
        }
        val bytes = ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
            input.readBytes()
        }
        return localDocumentSnapshot(bytes) { queryModifiedAt(parsed) }
    }

    private fun queryModifiedAt(uri: Uri): Long? = resolver.query(
        uri,
        arrayOf(DocumentsContract.Document.COLUMN_LAST_MODIFIED),
        null,
        null,
        null,
    )?.use { cursor ->
        if (!cursor.moveToFirst() || cursor.isNull(0)) null else cursor.getLong(0)
    }

    private fun contentUri(value: String): Uri = Uri.parse(value).also { uri ->
        require(uri.scheme == ContentResolver.SCHEME_CONTENT) {
            "selected local document must use a content URI"
        }
    }

    companion object {
        const val KEEPASS_MIME_TYPE = "application/x-keepass2"
    }
}
