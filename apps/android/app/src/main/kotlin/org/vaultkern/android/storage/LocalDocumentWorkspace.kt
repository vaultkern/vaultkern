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
    fun replace(uri: String, bytes: ByteArray)
    fun createConflictCopy(sourceUri: String, displayName: String, bytes: ByteArray): String?
}

data class LocalDocumentFingerprint(
    val contentSha256: String,
    val sizeBytes: Long,
    val modifiedAt: Long?,
)

data class LocalDocumentBinding(
    val privatePath: String,
    val sourceUri: String?,
    val displayName: String,
    val baseline: LocalDocumentFingerprint,
)

data class SelectedLocalDocument(
    val privatePath: String,
    val displayName: String,
)

enum class LocalDocumentPublishStatus {
    PUBLISHED,
    NO_CHANGE,
    PENDING,
    CONFLICT_COPY,
}

data class LocalDocumentPublishResult(
    val status: LocalDocumentPublishStatus,
    val conflictLocation: String? = null,
)

private data class PendingLocalDocumentSave(
    val mirrorBefore: LocalDocumentFingerprint,
    val writeStarted: Boolean,
)

class LocalDocumentWorkspace(
    root: File,
    private val documents: LocalDocumentAccess,
    private val atomicMove: (File, File) -> Unit = ::moveAtomically,
    private val directorySync: (File) -> Unit = ::forceDirectory,
) {
    private val root = root.canonicalFile
    private val activeSaves = mutableSetOf<String>()

    @Synchronized
    fun select(uri: String, displayName: String): SelectedLocalDocument {
        require(uri.isNotBlank()) { "document URI is empty" }
        require(displayName.isNotBlank()) { "document display name is empty" }
        val directory = File(root, stableId(uri)).canonicalFile
        require(directory.path.startsWith(root.path + File.separator)) {
            "document workspace escaped its private root"
        }
        val privateFile = File(directory, PRIVATE_FILE_NAME)
        if (File(directory, PENDING_FILE_NAME).isFile) {
            check(!activeSaves.contains(privateFile.canonicalPath)) {
                "selected local document save is still active"
            }
            val publication = publishAfterSave(privateFile.canonicalPath)
            check(publication.status != LocalDocumentPublishStatus.PENDING) {
                "selected local document still has an unpublished private save"
            }
        }
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
    fun reconcilePending(): List<LocalDocumentPublishResult> =
        root.listFiles()
            .orEmpty()
            .asSequence()
            .filter(File::isDirectory)
            .filter { File(it, BINDING_FILE_NAME).isFile }
            .filter { File(it, PENDING_FILE_NAME).isFile }
            .filter { File(it, PRIVATE_FILE_NAME).isFile }
            .filterNot {
                activeSaves.contains(File(it, PRIVATE_FILE_NAME).canonicalPath)
            }
            .map { directory ->
                publishAfterSave(File(directory, PRIVATE_FILE_NAME).canonicalPath)
            }
            .toList()

    @Synchronized
    fun refreshFromAuthorities(): List<String> =
        root.listFiles()
            .orEmpty()
            .asSequence()
            .filter(File::isDirectory)
            .filterNot { File(it, PENDING_FILE_NAME).isFile }
            .mapNotNull { directory ->
                val privateFile = File(directory, PRIVATE_FILE_NAME)
                if (!privateFile.isFile) return@mapNotNull null
                val binding = bindingFor(privateFile.canonicalPath) ?: return@mapNotNull null
                val sourceUri = binding.sourceUri ?: return@mapNotNull null
                val current = documents.read(sourceUri)
                try {
                    val currentFingerprint = fingerprint(current)
                    if (currentFingerprint.sameContentAs(binding.baseline)) {
                        if (currentFingerprint != binding.baseline) {
                            writeBinding(directory, binding.copy(baseline = currentFingerprint))
                        }
                        null
                    } else {
                        writeAtomic(privateFile, current.bytes)
                        writeBinding(directory, binding.copy(baseline = currentFingerprint))
                        privateFile.canonicalPath
                    }
                } finally {
                    current.bytes.fill(0)
                }
            }
            .toList()

    @Synchronized
    fun prepareSave(privatePath: String) {
        val binding = requireNotNull(bindingFor(privatePath)) {
            "vault is not backed by a selected local document"
        }
        val privateFile = File(binding.privatePath)
        require(privateFile.isFile) { "local document working copy is missing" }
        val directory = requireNotNull(privateFile.parentFile)
        check(!File(directory, PENDING_FILE_NAME).isFile) {
            "a previous local document save still needs reconciliation"
        }
        check(activeSaves.add(privateFile.canonicalPath)) {
            "local document save is already active"
        }
        try {
            writePending(
                directory,
                PendingLocalDocumentSave(
                    mirrorBefore = fingerprint(privateFile),
                    writeStarted = false,
                ),
            )
        } catch (error: Throwable) {
            activeSaves.remove(privateFile.canonicalPath)
            throw error
        }
    }

    @Synchronized
    fun publishAfterSave(privatePath: String): LocalDocumentPublishResult {
        val canonicalPath = File(privatePath).canonicalPath
        return try {
            publishAfterSaveInternal(canonicalPath)
        } finally {
            activeSaves.remove(canonicalPath)
        }
    }

    @Synchronized
    fun abandonSave(privatePath: String) {
        activeSaves.remove(File(privatePath).canonicalPath)
    }

    private fun publishAfterSaveInternal(privatePath: String): LocalDocumentPublishResult {
        val binding = requireNotNull(bindingFor(privatePath)) {
            "vault is not backed by a selected local document"
        }
        val privateFile = File(binding.privatePath)
        val directory = requireNotNull(privateFile.parentFile)
        val pending = requireNotNull(readPending(directory)) {
            "local document save was not prepared"
        }
        val candidate = fingerprint(privateFile)
        if (candidate.sameContentAs(pending.mirrorBefore)) {
            clearPending(directory)
            return LocalDocumentPublishResult(LocalDocumentPublishStatus.NO_CHANGE)
        }

        val sourceUri = requireNotNull(binding.sourceUri) {
            "local document working copy is detached after a conflict"
        }
        val current = documents.read(sourceUri)
        val currentFingerprint = try {
            fingerprint(current)
        } finally {
            current.bytes.fill(0)
        }
        if (currentFingerprint.sameContentAs(candidate)) {
            writeBinding(
                directory,
                binding.copy(baseline = currentFingerprint),
            )
            clearPending(directory)
            return LocalDocumentPublishResult(LocalDocumentPublishStatus.PUBLISHED)
        }
        if (!currentFingerprint.sameContentAs(binding.baseline)) {
            return publishConflictCopy(binding, privateFile, directory, candidate)
        }

        if (!pending.writeStarted) {
            writePending(directory, pending.copy(writeStarted = true))
        }
        val candidateBytes = privateFile.readBytes()
        val publishedSuccessfully = try {
            documents.replace(sourceUri, candidateBytes)
            val published = documents.read(sourceUri)
            try {
                val publishedFingerprint = fingerprint(published)
                if (!publishedFingerprint.sameContentAs(candidate)) {
                    false
                } else {
                    writeBinding(
                        directory,
                        binding.copy(baseline = publishedFingerprint),
                    )
                    true
                }
            } finally {
                published.bytes.fill(0)
            }
        } catch (_: Exception) {
            false
        } finally {
            candidateBytes.fill(0)
        }
        if (!publishedSuccessfully) {
            return LocalDocumentPublishResult(LocalDocumentPublishStatus.PENDING)
        }
        clearPending(directory)
        return LocalDocumentPublishResult(LocalDocumentPublishStatus.PUBLISHED)
    }

    private fun publishConflictCopy(
        binding: LocalDocumentBinding,
        privateFile: File,
        directory: File,
        candidate: LocalDocumentFingerprint,
    ): LocalDocumentPublishResult {
        val candidateBytes = privateFile.readBytes()
        try {
            val conflictName = conflictDisplayName(binding.displayName)
            val sourceUri = requireNotNull(binding.sourceUri)
            val conflictUri = documents.createConflictCopy(sourceUri, conflictName, candidateBytes)
                ?: return publishPrivateConflictCopy(
                    binding,
                    directory,
                    conflictName,
                    candidateBytes,
                    candidate,
                )
            val conflict = documents.read(conflictUri)
            try {
                val conflictFingerprint = fingerprint(conflict)
                check(conflictFingerprint.sameContentAs(candidate)) {
                    "selected local document conflict-copy readback did not match"
                }
                writeBinding(
                    directory,
                    binding.copy(
                        sourceUri = conflictUri,
                        displayName = conflictName,
                        baseline = conflictFingerprint,
                    ),
                )
            } finally {
                conflict.bytes.fill(0)
            }
            clearPending(directory)
            return LocalDocumentPublishResult(
                LocalDocumentPublishStatus.CONFLICT_COPY,
                conflictUri,
            )
        } finally {
            candidateBytes.fill(0)
        }
    }

    private fun publishPrivateConflictCopy(
        binding: LocalDocumentBinding,
        directory: File,
        conflictName: String,
        candidateBytes: ByteArray,
        candidate: LocalDocumentFingerprint,
    ): LocalDocumentPublishResult {
        val conflictFile = File(
            directory,
            "$PRIVATE_CONFLICT_FILE_PREFIX${candidate.contentSha256}.kdbx",
        )
        writeAtomic(conflictFile, candidateBytes)
        writeBinding(
            directory,
            binding.copy(
                sourceUri = null,
                displayName = conflictName,
                baseline = fingerprint(conflictFile),
            ),
        )
        clearPending(directory)
        return LocalDocumentPublishResult(
            LocalDocumentPublishStatus.CONFLICT_COPY,
            conflictFile.canonicalPath,
        )
    }

    private fun conflictDisplayName(displayName: String): String {
        val stem = displayName.removeSuffix(".kdbx")
        return "$stem (VaultKern conflict).kdbx"
    }

    private fun writeBinding(directory: File, binding: LocalDocumentBinding) {
        val encoded = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeInt(BINDING_MAGIC)
                output.writeInt(BINDING_VERSION)
                output.writeBoolean(binding.sourceUri != null)
                binding.sourceUri?.let(output::writeUTF)
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
                val sourceUri = if (input.readBoolean()) input.readUTF() else null
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

    private fun writePending(directory: File, pending: PendingLocalDocumentSave) {
        val encoded = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeInt(PENDING_MAGIC)
                output.writeInt(PENDING_VERSION)
                output.writeUTF(pending.mirrorBefore.contentSha256)
                output.writeLong(pending.mirrorBefore.sizeBytes)
                output.writeBoolean(pending.mirrorBefore.modifiedAt != null)
                pending.mirrorBefore.modifiedAt?.let(output::writeLong)
                output.writeBoolean(pending.writeStarted)
            }
            bytes.toByteArray()
        }
        try {
            writeAtomic(File(directory, PENDING_FILE_NAME), encoded)
        } finally {
            encoded.fill(0)
        }
    }

    private fun readPending(directory: File): PendingLocalDocumentSave? {
        val file = File(directory, PENDING_FILE_NAME)
        if (!file.isFile) return null
        val bytes = file.readBytes()
        return try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                require(input.readInt() == PENDING_MAGIC) { "invalid local document pending save" }
                require(input.readInt() == PENDING_VERSION) {
                    "unsupported local document pending save"
                }
                val contentSha256 = input.readUTF()
                val sizeBytes = input.readLong()
                val modifiedAt = if (input.readBoolean()) input.readLong() else null
                val writeStarted = input.readBoolean()
                require(input.available() == 0) { "trailing local document pending save data" }
                PendingLocalDocumentSave(
                    mirrorBefore = LocalDocumentFingerprint(contentSha256, sizeBytes, modifiedAt),
                    writeStarted = writeStarted,
                )
            }
        } finally {
            bytes.fill(0)
        }
    }

    private fun clearPending(directory: File) {
        Files.deleteIfExists(File(directory, PENDING_FILE_NAME).toPath())
        directorySync(directory)
    }

    private fun stableId(uri: String): String = sha256Hex(uri.toByteArray(Charsets.UTF_8))

    private fun writeAtomic(target: File, bytes: ByteArray) {
        val parent = requireNotNull(target.parentFile)
        check(parent.mkdirs() || parent.isDirectory) { "failed to create local document workspace" }
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
        private const val PENDING_MAGIC = 0x564b4c50
        private const val PENDING_VERSION = 2
        private const val PRIVATE_FILE_NAME = "vault.kdbx"
        private const val PRIVATE_CONFLICT_FILE_PREFIX = "vault-vaultkern-conflict-"
        private const val BINDING_FILE_NAME = "binding.bin"
        private const val PENDING_FILE_NAME = "pending.bin"
        private const val NEW_SUFFIX = ".new"

        internal fun fingerprint(snapshot: LocalDocumentSnapshot): LocalDocumentFingerprint =
            LocalDocumentFingerprint(
                contentSha256 = sha256Hex(snapshot.bytes),
                sizeBytes = snapshot.bytes.size.toLong(),
                modifiedAt = snapshot.modifiedAt,
            )

        private fun fingerprint(file: File): LocalDocumentFingerprint {
            val bytes = file.readBytes()
            return try {
                LocalDocumentFingerprint(
                    contentSha256 = sha256Hex(bytes),
                    sizeBytes = bytes.size.toLong(),
                    modifiedAt = file.lastModified(),
                )
            } finally {
                bytes.fill(0)
            }
        }

        private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { byte -> "%02x".format(byte) }
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
