package org.vaultkern.android.security

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

data class PreparedUnlockCipher(
    val keyAlias: String,
    val cipher: Cipher,
    val securityLevel: UnlockKeySecurityLevel,
)

interface UnlockCipherBackend {
    fun prepareEncryption(): PreparedUnlockCipher
    fun prepareDecryption(record: UnlockBlobRecord): PreparedUnlockCipher
    fun contains(alias: String): Boolean
    fun delete(alias: String)
    fun aliases(): Set<String>
}

class MissingUnlockKeyException(alias: String) :
    IllegalStateException("unlock key is missing: $alias")

class AndroidKeystoreUnlockCipherBackend(
    private val context: Context,
) : UnlockCipherBackend {
    override fun prepareEncryption(): PreparedUnlockCipher {
        val alias = "$ALIAS_PREFIX${UUID.randomUUID()}"
        val strongBoxRequested = context.packageManager.hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE,
        )
        val key = try {
            generateKey(alias, strongBoxRequested)
        } catch (_: StrongBoxUnavailableException) {
            generateKey(alias, false)
        }
        return try {
            PreparedUnlockCipher(
                keyAlias = alias,
                cipher = Cipher.getInstance(TRANSFORMATION).apply {
                    init(Cipher.ENCRYPT_MODE, key)
                },
                securityLevel = securityLevel(key),
            )
        } catch (error: Throwable) {
            delete(alias)
            throw error
        }
    }

    override fun prepareDecryption(record: UnlockBlobRecord): PreparedUnlockCipher {
        val key = loadKey(record.keyAlias)
        return PreparedUnlockCipher(
            keyAlias = record.keyAlias,
            cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, record.iv))
            },
            securityLevel = securityLevel(key),
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
                if (alias.startsWith(ALIAS_PREFIX)) add(alias)
            }
        }
    }

    private fun generateKey(alias: String, strongBox: Boolean): SecretKey {
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
        if (strongBox) builder.setIsStrongBoxBacked(true)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun loadKey(alias: String): SecretKey =
        keyStore().getKey(alias, null) as? SecretKey
            ?: throw MissingUnlockKeyException(alias)

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

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

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val ALIAS_PREFIX = "vaultkern.unlock."
    }
}
