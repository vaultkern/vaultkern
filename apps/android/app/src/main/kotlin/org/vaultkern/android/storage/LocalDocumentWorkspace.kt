package org.vaultkern.android.storage

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

data class LocalDocumentSnapshot(
    val bytes: ByteArray,
    val modifiedAt: Long?,
)

internal fun localDocumentSnapshot(
    bytes: ByteArray,
    modifiedAt: () -> Long?,
): LocalDocumentSnapshot = try {
    LocalDocumentSnapshot(bytes, modifiedAt())
} catch (error: Throwable) {
    bytes.fill(0)
    throw error
}

interface LocalDocumentAccess {
    fun read(uri: String): LocalDocumentSnapshot
}

data class LocalDocumentFingerprint(
    val contentSha256: String,
    val sizeBytes: Long,
    val modifiedAt: Long?,
)

data class LocalDocumentBinding(
    val privatePath: String,
    val sourceUri: String,
    val displayName: String,
    val baseline: LocalDocumentFingerprint,
) {
    override fun toString(): String = "LocalDocumentBinding([REDACTED])"
}

class SelectedLocalDocument(
    val privatePath: String,
    val displayName: String,
) {
    override fun toString(): String = "SelectedLocalDocument([REDACTED])"
}

class LocalDocumentWorkspace(
    root: File,
    private val documents: LocalDocumentAccess,
    private val atomicMove: (File, File) -> Unit = ::moveAtomically,
    private val directorySync: (File) -> Unit = ::forceDirectory,
) {
    private val root = root.canonicalFile

    @Synchronized
    fun select(uri: String, displayName: String): SelectedLocalDocument {
        require(uri.isNotBlank()) { "document URI is empty" }
        require(displayName.isNotBlank()) { "document display name is empty" }
        val directory = File(root, stableId(uri)).canonicalFile
        require(directory.path.startsWith(root.path + File.separator)) {
            "document workspace escaped its private root"
        }
        val privateFile = File(directory, PRIVATE_FILE_NAME)
        val snapshot = documents.read(uri)
        try {
            writeAtomic(privateFile, snapshot.bytes)
            writeBinding(
                directory,
                LocalDocumentBinding(
                    privatePath = privateFile.canonicalPath,
                    sourceUri = uri,
                    displayName = displayName,
                    baseline = fingerprint(snapshot),
                ),
            )
        } finally {
            snapshot.bytes.fill(0)
        }
        return SelectedLocalDocument(privateFile.canonicalPath, displayName)
    }

    @Synchronized
    fun bindingFor(privatePath: String): LocalDocumentBinding? {
        val privateFile = File(privatePath).canonicalFile
        if (privateFile.name != PRIVATE_FILE_NAME) return null
        val directory = privateFile.parentFile?.canonicalFile ?: return null
        if (!directory.path.startsWith(root.path + File.separator)) return null
        val bindingFile = File(directory, BINDING_FILE_NAME)
        if (!bindingFile.isFile) return null
        return decodeBinding(bindingFile.readBytes(), privateFile.canonicalPath)
    }

    @Synchronized
    fun refresh(privatePath: String): Boolean {
        val binding = requireNotNull(bindingFor(privatePath)) {
            "current local vault has no persisted document authority"
        }
        return refreshBinding(binding)
    }

    @Synchronized
    fun refreshFromAuthorities(): List<String> =
        root.listFiles()
            .orEmpty()
            .asSequence()
            .filter(File::isDirectory)
            .mapNotNull { directory ->
                val privateFile = File(directory, PRIVATE_FILE_NAME)
                val binding = bindingFor(privateFile.canonicalPath) ?: return@mapNotNull null
                privateFile.canonicalPath.takeIf { refreshBinding(binding) }
            }
            .toList()

    private fun refreshBinding(binding: LocalDocumentBinding): Boolean {
        val privateFile = File(binding.privatePath)
        val directory = requireNotNull(privateFile.parentFile)
        val current = documents.read(binding.sourceUri)
        try {
            val currentFingerprint = fingerprint(current)
            if (privateFile.isFile &&
                fingerprint(privateFile).sameContentAs(currentFingerprint)
            ) {
                if (currentFingerprint != binding.baseline) {
                    writeBinding(directory, binding.copy(baseline = currentFingerprint))
                }
                return false
            }
            writeAtomic(privateFile, current.bytes)
            writeBinding(directory, binding.copy(baseline = currentFingerprint))
            return true
        } finally {
            current.bytes.fill(0)
        }
    }

    private fun writeBinding(directory: File, binding: LocalDocumentBinding) {
        val encoded = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeInt(BINDING_MAGIC)
                output.writeInt(BINDING_VERSION)
                output.writeBoolean(true)
                output.writeUTF(binding.sourceUri)
                output.writeUTF(binding.displayName)
                output.writeUTF(binding.baseline.contentSha256)
                output.writeLong(binding.baseline.sizeBytes)
                output.writeBoolean(binding.baseline.modifiedAt != null)
                binding.baseline.modifiedAt?.let(output::writeLong)
            }
            bytes.toByteArray()
        }
        try {
            writeAtomic(File(directory, BINDING_FILE_NAME), encoded)
        } finally {
            encoded.fill(0)
        }
    }

    private fun decodeBinding(bytes: ByteArray, privatePath: String): LocalDocumentBinding =
        try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                require(input.readInt() == BINDING_MAGIC) { "invalid local document binding" }
                require(input.readInt() == BINDING_VERSION) {
                    "unsupported local document binding"
                }
                require(input.readBoolean()) { "local document authority is missing" }
                val sourceUri = input.readUTF()
                val displayName = input.readUTF()
                val contentSha256 = input.readUTF()
                val sizeBytes = input.readLong()
                val modifiedAt = if (input.readBoolean()) input.readLong() else null
                require(input.available() == 0) { "trailing local document binding data" }
                LocalDocumentBinding(
                    privatePath = privatePath,
                    sourceUri = sourceUri,
                    displayName = displayName,
                    baseline = LocalDocumentFingerprint(contentSha256, sizeBytes, modifiedAt),
                )
            }
        } finally {
            bytes.fill(0)
        }

    private fun stableId(uri: String): String = sha256Hex(uri.toByteArray(Charsets.UTF_8))

    private fun writeAtomic(target: File, bytes: ByteArray) {
        val parent = requireNotNull(target.parentFile)
        check(parent.mkdirs() || parent.isDirectory) {
            "failed to create local document workspace"
        }
        val temporary = File(parent, target.name + NEW_SUFFIX)
        FileOutputStream(temporary).use { output ->
            output.write(bytes)
            output.flush()
            output.fd.sync()
        }
        atomicMove(temporary, target)
        directorySync(parent)
    }

    companion object {
        private const val BINDING_MAGIC = 0x564b4c44
        private const val BINDING_VERSION = 2
        private const val PRIVATE_FILE_NAME = "vault.kdbx"
        private const val BINDING_FILE_NAME = "binding.bin"
        private const val NEW_SUFFIX = ".new"

        internal fun fingerprint(snapshot: LocalDocumentSnapshot): LocalDocumentFingerprint =
            LocalDocumentFingerprint(
                contentSha256 = sha256Hex(snapshot.bytes),
                sizeBytes = snapshot.bytes.size.toLong(),
                modifiedAt = snapshot.modifiedAt,
            )

        private fun fingerprint(file: File): LocalDocumentFingerprint {
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            var size = 0L
            try {
                file.inputStream().buffered().use { input ->
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        digest.update(buffer, 0, count)
                        size += count
                    }
                }
            } finally {
                buffer.fill(0)
            }
            return LocalDocumentFingerprint(
                contentSha256 = digest.digest().toHex(),
                sizeBytes = size,
                modifiedAt = file.lastModified().takeIf { it > 0 },
            )
        }

        private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .toHex()
    }
}

private fun moveAtomically(source: File, target: File) {
    Files.move(
        source.toPath(),
        target.toPath(),
        StandardCopyOption.ATOMIC_MOVE,
        StandardCopyOption.REPLACE_EXISTING,
    )
}

private fun forceDirectory(directory: File) {
    FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { it.force(true) }
}

private fun LocalDocumentFingerprint.sameContentAs(other: LocalDocumentFingerprint): Boolean =
    contentSha256 == other.contentSha256 && sizeBytes == other.sizeBytes

private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte) }
