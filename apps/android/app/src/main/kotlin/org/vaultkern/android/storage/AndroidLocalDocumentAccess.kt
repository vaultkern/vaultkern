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
        val queried = resolver.query(
            parsed,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )?.use { cursor ->
            if (!cursor.moveToFirst() || cursor.isNull(0)) null else cursor.getString(0)
        }
        return queried?.takeIf(String::isNotBlank)
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

    override fun replace(uri: String, bytes: ByteArray) {
        val descriptor = requireNotNull(resolver.openFileDescriptor(contentUri(uri), "rwt")) {
            "selected local document could not be opened for replacement"
        }
        ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use { output ->
            output.write(bytes)
            output.flush()
            output.fd.sync()
        }
    }

    override fun createConflictCopy(
        sourceUri: String,
        displayName: String,
        bytes: ByteArray,
    ): String? = runCatching {
        val source = contentUri(sourceUri)
        val documentPath = DocumentsContract.findDocumentPath(resolver, source)
            ?: return@runCatching null
        val path = documentPath.path
        if (path.size < 2) return@runCatching null
        val parentId = path[path.lastIndex - 1]
        val authority = source.authority ?: return@runCatching null
        val parent = if (DocumentsContract.isTreeUri(source)) {
            DocumentsContract.buildDocumentUriUsingTree(source, parentId)
        } else {
            DocumentsContract.buildDocumentUri(authority, parentId)
        }
        val created = DocumentsContract.createDocument(
            resolver,
            parent,
            KEEPASS_MIME_TYPE,
            displayName,
        ) ?: return@runCatching null
        try {
            replace(created.toString(), bytes)
            created.toString()
        } catch (error: Exception) {
            runCatching { DocumentsContract.deleteDocument(resolver, created) }
            throw error
        }
    }.getOrNull()

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
