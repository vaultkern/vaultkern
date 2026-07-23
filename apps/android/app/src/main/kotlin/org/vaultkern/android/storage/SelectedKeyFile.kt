package org.vaultkern.android.storage

import android.content.ContentResolver
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import org.vaultkern.core.VaultKernSensitiveBytes

interface SelectedKeyFile {
    val displayName: String
    fun <T> withSensitiveBytes(block: (VaultKernSensitiveBytes) -> T): T
}

internal class ParcelFileDescriptorKeyFile(
    override val displayName: String,
    private val open: () -> ParcelFileDescriptor,
) : SelectedKeyFile {
    override fun <T> withSensitiveBytes(
        block: (VaultKernSensitiveBytes) -> T,
    ): T {
        val plaintext = ParcelFileDescriptor.AutoCloseInputStream(open()).use { input ->
            input.readBytes()
        }
        val sensitive = try {
            VaultKernSensitiveBytes.fromByteArray(plaintext)
        } finally {
            plaintext.fill(0)
        }
        return try {
            block(sensitive)
        } finally {
            sensitive.close()
        }
    }

    override fun toString(): String = "SelectedKeyFile([REDACTED])"
}

class AndroidKeyFileSelection(
    private val resolver: ContentResolver,
) {
    fun select(value: String): SelectedKeyFile {
        val uri = Uri.parse(value).also {
            require(it.scheme == ContentResolver.SCHEME_CONTENT) {
                "selected key file must use a content URI"
            }
        }
        val name = resolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )?.use { cursor ->
            if (!cursor.moveToFirst() || cursor.isNull(0)) null else cursor.getString(0)
        }?.takeIf(String::isNotBlank) ?: "selected key file"
        return ParcelFileDescriptorKeyFile(name) {
            requireNotNull(resolver.openFileDescriptor(uri, "r")) {
                "selected key file could not be opened"
            }
        }
    }
}
