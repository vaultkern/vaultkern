package org.vaultkern.android.security

import android.content.Context
import android.util.AtomicFile
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileNotFoundException

class AtomicUnlockBlobRecordStore(
    context: Context,
    directoryName: String = "unlock-blobs",
) {
    private val directory = File(context.noBackupFilesDir, directoryName)
    private val gate = Any()

    fun write(key: String, record: UnlockBlobRecord) = synchronized(gate) {
        validateKey(key)
        require(record.keyAlias.length in 1..MAX_ALIAS_BYTES)
        require(record.iv.size in 1..MAX_IV_BYTES)
        require(record.ciphertext.size in 1..MAX_CIPHERTEXT_BYTES)
        check(directory.mkdirs() || directory.isDirectory) {
            "unlock blob directory is unavailable"
        }
        val atomic = atomicFile(key)
        val output = atomic.startWrite()
        try {
            DataOutputStream(output.buffered()).use { data ->
                data.writeInt(MAGIC)
                data.writeByte(VERSION)
                data.writeUTF(record.keyAlias)
                data.writeByte(record.securityLevel.ordinal)
                data.writeInt(record.iv.size)
                data.write(record.iv)
                data.writeInt(record.ciphertext.size)
                data.write(record.ciphertext)
                data.flush()
                atomic.finishWrite(output)
            }
        } catch (error: Throwable) {
            atomic.failWrite(output)
            throw error
        }
    }

    fun read(key: String): UnlockBlobRecord? = synchronized(gate) {
        validateKey(key)
        val input = try {
            atomicFile(key).openRead()
        } catch (_: FileNotFoundException) {
            return@synchronized null
        }
        try {
            DataInputStream(input.buffered()).use { data ->
                require(data.readInt() == MAGIC) { "unsupported unlock blob record" }
                require(data.readUnsignedByte() == VERSION) { "unsupported unlock blob version" }
                val alias = data.readUTF()
                require(alias.length in 1..MAX_ALIAS_BYTES) { "unlock key alias is invalid" }
                val levelOrdinal = data.readUnsignedByte()
                val level = UnlockKeySecurityLevel.entries.getOrNull(levelOrdinal)
                    ?: error("unlock key security level is invalid")
                val iv = readBounded(data, MAX_IV_BYTES, "unlock blob IV")
                val ciphertext = readBounded(data, MAX_CIPHERTEXT_BYTES, "unlock ciphertext")
                require(data.read() == -1) { "unlock blob record has trailing bytes" }
                UnlockBlobRecord(alias, iv, ciphertext, level)
            }
        } catch (error: EOFException) {
            throw IllegalStateException("unlock blob record is truncated", error)
        }
    }

    fun exists(key: String): Boolean = synchronized(gate) {
        validateKey(key)
        File(directory, "$key$SUFFIX").isFile ||
            File(directory, "$key$SUFFIX$LEGACY_BACKUP_SUFFIX").isFile
    }

    fun delete(key: String) = synchronized(gate) {
        validateKey(key)
        atomicFile(key).delete()
    }

    fun keys(): Set<String> = synchronized(gate) {
        directory.listFiles()
            ?.asSequence()
            ?.filter(File::isFile)
            ?.map(File::getName)
            ?.mapNotNull { name ->
                when {
                    name.endsWith("$SUFFIX$LEGACY_BACKUP_SUFFIX") ->
                        name.removeSuffix("$SUFFIX$LEGACY_BACKUP_SUFFIX")
                    name.endsWith(SUFFIX) -> name.removeSuffix(SUFFIX)
                    else -> null
                }
            }
            ?.filter(KEY_PATTERN::matches)
            ?.toSet()
            .orEmpty()
    }

    fun hasAny(): Boolean = keys().isNotEmpty()

    fun deleteAll() = synchronized(gate) {
        directory.listFiles()?.forEach { file ->
            check(file.delete() || !file.exists()) {
                "failed to delete unlock blob storage"
            }
        }
    }

    fun discardUncommittedWrites() = synchronized(gate) {
        directory.listFiles()
            ?.filter { it.name.endsWith("$SUFFIX$NEW_SUFFIX") }
            ?.forEach { file ->
                check(file.delete() || !file.exists()) {
                    "failed to discard an uncommitted unlock blob"
                }
            }
    }

    fun deleteDirectory() = synchronized(gate) {
        directory.deleteRecursively()
    }

    private fun atomicFile(key: String) = AtomicFile(File(directory, "$key$SUFFIX"))

    private fun validateKey(key: String) {
        require(KEY_PATTERN.matches(key)) { "unlock blob key is invalid" }
    }

    private fun readBounded(
        input: DataInputStream,
        maximum: Int,
        label: String,
    ): ByteArray {
        val size = input.readInt()
        require(size in 1..maximum) { "$label length is invalid" }
        return ByteArray(size).also(input::readFully)
    }

    companion object {
        private const val MAGIC = 0x564B5542
        private const val VERSION = 1
        private const val SUFFIX = ".blob"
        private const val LEGACY_BACKUP_SUFFIX = ".bak"
        private const val NEW_SUFFIX = ".new"
        private const val MAX_ALIAS_BYTES = 256
        private const val MAX_IV_BYTES = 32
        private const val MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024
        private val KEY_PATTERN = Regex("[A-Za-z0-9_.-]{1,160}")
    }
}
