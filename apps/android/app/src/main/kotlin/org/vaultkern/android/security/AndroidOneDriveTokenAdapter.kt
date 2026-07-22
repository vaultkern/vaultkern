package org.vaultkern.android.security

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import org.vaultkern.core.OneDriveTokenAdapter
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.VaultKernSensitiveString

data class OneDriveTokenRecord(
    val keyAlias: String,
    val iv: ByteArray,
    val ciphertext: ByteArray,
    val securityLevel: UnlockKeySecurityLevel,
) {
    override fun toString(): String =
        "OneDriveTokenRecord(keyAlias=[REDACTED], iv=[REDACTED], " +
            "ciphertext=[REDACTED], securityLevel=$securityLevel)"
}

class AtomicOneDriveTokenRecordStore(
    context: Context,
    directoryName: String = "onedrive-token",
) {
    private val directory = File(context.noBackupFilesDir, directoryName)
    private val atomic = AtomicFile(File(directory, FILE_NAME))
    private val gate = Any()

    fun write(record: OneDriveTokenRecord) = synchronized(gate) {
        require(record.keyAlias.length in 1..MAX_ALIAS_BYTES) { "token key alias is invalid" }
        require(record.iv.size in 1..MAX_IV_BYTES) { "token IV is invalid" }
        require(record.ciphertext.size in 1..MAX_CIPHERTEXT_BYTES) {
            "encrypted refresh token is invalid"
        }
        check(directory.mkdirs() || directory.isDirectory) {
            "OneDrive token directory is unavailable"
        }
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

    fun read(): OneDriveTokenRecord? = synchronized(gate) {
        val input = try {
            atomic.openRead()
        } catch (_: FileNotFoundException) {
            return@synchronized null
        }
        try {
            DataInputStream(input.buffered()).use { data ->
                require(data.readInt() == MAGIC) { "unsupported OneDrive token record" }
                require(data.readUnsignedByte() == VERSION) {
                    "unsupported OneDrive token version"
                }
                val alias = data.readUTF()
                require(alias.length in 1..MAX_ALIAS_BYTES) { "token key alias is invalid" }
                val security = UnlockKeySecurityLevel.entries
                    .getOrNull(data.readUnsignedByte())
                    ?: error("token key security level is invalid")
                val iv = readBounded(data, MAX_IV_BYTES, "token IV")
                val ciphertext = readBounded(
                    data,
                    MAX_CIPHERTEXT_BYTES,
                    "encrypted refresh token",
                )
                require(data.read() == -1) { "OneDrive token record has trailing bytes" }
                OneDriveTokenRecord(alias, iv, ciphertext, security)
            }
        } catch (error: EOFException) {
            throw IllegalStateException("OneDrive token record is truncated", error)
        }
    }

    fun exists(): Boolean = synchronized(gate) {
        File(directory, FILE_NAME).isFile || File(directory, "$FILE_NAME.bak").isFile
    }

    fun delete() = synchronized(gate) { atomic.delete() }

    fun discardUncommittedWrite() = synchronized(gate) {
        val pending = File(directory, "$FILE_NAME.new")
        check(pending.delete() || !pending.exists()) {
            "failed to discard uncommitted OneDrive token"
        }
    }

    fun deleteDirectory() = synchronized(gate) { directory.deleteRecursively() }

    private fun readBounded(input: DataInputStream, maximum: Int, label: String): ByteArray {
        val size = input.readInt()
        require(size in 1..maximum) { "$label length is invalid" }
        return ByteArray(size).also(input::readFully)
    }

    companion object {
        private const val MAGIC = 0x564B4F44
        private const val VERSION = 1
        private const val FILE_NAME = "refresh-token.bin"
        private const val MAX_ALIAS_BYTES = 256
        private const val MAX_IV_BYTES = 32
        private const val MAX_CIPHERTEXT_BYTES = 128 * 1024
    }
}

data class PreparedOneDriveTokenCipher(
    val keyAlias: String,
    val cipher: Cipher,
    val securityLevel: UnlockKeySecurityLevel,
)

interface OneDriveTokenCipherBackend {
    fun prepareEncryption(): PreparedOneDriveTokenCipher
    fun prepareDecryption(record: OneDriveTokenRecord): PreparedOneDriveTokenCipher
    fun contains(alias: String): Boolean
    fun delete(alias: String)
    fun aliases(): Set<String>
}

class AndroidKeystoreOneDriveTokenCipherBackend(
    context: Context,
    private val aliasPrefix: String = ALIAS_PREFIX,
) : OneDriveTokenCipherBackend {
    private val applicationContext = context.applicationContext

    override fun prepareEncryption(): PreparedOneDriveTokenCipher {
        val alias = "$aliasPrefix${UUID.randomUUID()}"
        val strongBoxRequested = applicationContext.packageManager.hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE,
        )
        val key = try {
            generateKey(alias, strongBoxRequested)
        } catch (_: StrongBoxUnavailableException) {
            generateKey(alias, false)
        }
        return try {
            PreparedOneDriveTokenCipher(
                alias,
                Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) },
                securityLevel(key),
            )
        } catch (error: Throwable) {
            delete(alias)
            throw error
        }
    }

    override fun prepareDecryption(record: OneDriveTokenRecord): PreparedOneDriveTokenCipher {
        val key = loadKey(record.keyAlias)
        return PreparedOneDriveTokenCipher(
            record.keyAlias,
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, record.iv))
            },
            securityLevel(key),
        )
    }

    override fun contains(alias: String): Boolean = keyStore().containsAlias(alias)

    override fun delete(alias: String) {
        val store = keyStore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }

    override fun aliases(): Set<String> {
        val aliases = keyStore().aliases()
        return buildSet {
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (alias.startsWith(aliasPrefix)) add(alias)
            }
        }
    }

    private fun generateKey(alias: String, strongBox: Boolean): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
        if (strongBox) builder.setIsStrongBoxBacked(true)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun loadKey(alias: String): SecretKey =
        keyStore().getKey(alias, null) as? SecretKey
            ?: throw MissingOneDriveTokenKeyException()

    private fun securityLevel(key: SecretKey): UnlockKeySecurityLevel {
        val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> UnlockKeySecurityLevel.STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                UnlockKeySecurityLevel.TRUSTED_ENVIRONMENT
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> UnlockKeySecurityLevel.SOFTWARE
            else -> UnlockKeySecurityLevel.UNKNOWN
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val ALIAS_PREFIX = "vaultkern.onedrive.token."
    }
}

class AndroidOneDriveTokenAdapter(
    private val records: AtomicOneDriveTokenRecordStore,
    private val cipherBackend: OneDriveTokenCipherBackend,
) : OneDriveTokenAdapter {
    private val maintenancePending = AtomicBoolean(false)

    init {
        maintenancePending.set(runCatching { reconcileStorageInternal() }.isFailure)
    }

    override fun loadRefreshToken(): VaultKernSensitiveString? {
        val record = try {
            records.read()
        } catch (error: Throwable) {
            revokeBrokenToken(null)
            throw unavailable(error)
        } ?: return null
        if (!cipherBackend.contains(record.keyAlias)) {
            revokeBrokenToken(record)
            throw unavailable(MissingOneDriveTokenKeyException())
        }
        val plaintext = try {
            val prepared = cipherBackend.prepareDecryption(record)
            prepared.cipher.updateAAD(TOKEN_AAD)
            prepared.cipher.doFinal(record.ciphertext)
        } catch (error: Throwable) {
            revokeBrokenToken(record)
            throw unavailable(error)
        }
        return try {
            VaultKernSensitiveString.fromUtf8Bytes(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    override fun storeRefreshToken(token: VaultKernSensitiveString) {
        val plaintext = try {
            token.copyUtf8Bytes()
        } finally {
            token.close()
        }
        val oldRecord = runCatching { records.read() }.getOrNull()
        var prepared: PreparedOneDriveTokenCipher? = null
        var ciphertext: ByteArray? = null
        var committed = false
        try {
            prepared = cipherBackend.prepareEncryption()
            prepared.cipher.updateAAD(TOKEN_AAD)
            ciphertext = prepared.cipher.doFinal(plaintext)
            records.write(
                OneDriveTokenRecord(
                    prepared.keyAlias,
                    prepared.cipher.iv.copyOf(),
                    ciphertext,
                    prepared.securityLevel,
                ),
            )
            committed = true
        } catch (error: Throwable) {
            if (!committed) prepared?.let { runCatching { cipherBackend.delete(it.keyAlias) } }
            throw unavailable(error)
        } finally {
            plaintext.fill(0)
            ciphertext?.fill(0)
        }
        oldRecord?.takeIf { it.keyAlias != prepared?.keyAlias }
            ?.let { runCatching { cipherBackend.delete(it.keyAlias) } }
        maintenancePending.set(runCatching { cleanupOrphans() }.isFailure)
    }

    override fun deleteRefreshToken() {
        val record = runCatching { records.read() }.getOrNull()
        try {
            records.delete()
            record?.let { cipherBackend.delete(it.keyAlias) }
            cleanupOrphans()
            maintenancePending.set(false)
        } catch (error: Throwable) {
            maintenancePending.set(true)
            throw unavailable(error)
        }
    }

    fun securityLevel(): UnlockKeySecurityLevel? =
        runCatching { records.read()?.securityLevel }.getOrNull()

    fun hasStoredToken(): Boolean = securityLevel() != null

    fun reconcileStorage() {
        try {
            reconcileStorageInternal()
            maintenancePending.set(false)
        } catch (error: Throwable) {
            maintenancePending.set(true)
            throw unavailable(error)
        }
    }

    fun maintenanceRequired(): Boolean = maintenancePending.get()

    private fun reconcileStorageInternal() {
        records.discardUncommittedWrite()
        val record = try {
            records.read()
        } catch (_: Throwable) {
            records.delete()
            null
        }
        if (record != null && !cipherBackend.contains(record.keyAlias)) {
            records.delete()
        }
        cleanupOrphans()
    }

    private fun cleanupOrphans() {
        val selected = runCatching { records.read()?.keyAlias }.getOrNull()
        cipherBackend.aliases()
            .filterNot { it == selected }
            .forEach(cipherBackend::delete)
    }

    private fun revokeBrokenToken(record: OneDriveTokenRecord?) {
        runCatching { records.delete() }
        record?.let { runCatching { cipherBackend.delete(it.keyAlias) } }
        maintenancePending.set(runCatching { cleanupOrphans() }.isFailure)
    }

    private fun unavailable(error: Throwable): PlatformAdapterException.Failure =
        PlatformAdapterException.Failure(
            "OneDrive authorization is unavailable (${error.javaClass.simpleName})",
        )

    companion object {
        private val TOKEN_AAD = "vaultkern:android:onedrive-refresh-token:v1".toByteArray()
    }
}

private class MissingOneDriveTokenKeyException :
    IllegalStateException("OneDrive token key is missing")
