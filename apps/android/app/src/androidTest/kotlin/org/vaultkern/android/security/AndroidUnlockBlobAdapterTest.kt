package org.vaultkern.android.security

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import java.security.SecureRandom
import java.security.UnrecoverableKeyException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.VaultKernSensitiveBytes

@RunWith(AndroidJUnit4::class)
class AndroidUnlockBlobAdapterTest {
    private lateinit var records: AtomicUnlockBlobRecordStore
    private lateinit var keys: FakeCipherBackend
    private lateinit var adapter: AndroidUnlockBlobAdapter
    private var freshUserVerifications = 0
    private var biometricFailure: Throwable? = null

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        records = AtomicUnlockBlobRecordStore(context, "m1-test-${System.nanoTime()}")
        keys = FakeCipherBackend()
        adapter = AndroidUnlockBlobAdapter(
            records = records,
            cipherBackend = keys,
            biometricGate = BiometricGate { _, cipher ->
                biometricFailure?.let { throw it }
                cipher
            },
            userVerificationGate = UserVerificationGate { freshUserVerifications += 1 },
            requireHardwareBacked = false,
        )
    }

    @After
    fun tearDown() {
        adapter.deleteAll()
        records.deleteDirectory()
    }

    @Test
    fun encryptedRecordRoundTripsAndRevokeDeletesCiphertextAndKey() {
        val payload = "master-credential-and-transformed-key".encodeToByteArray()

        adapter.authorizeStoreUserPresence()
        adapter.storeBlob(TEST_KEY, VaultKernSensitiveBytes.fromByteArray(payload.copyOf()))

        assertEquals(UnlockEnrollmentState.ENROLLED, adapter.enrollmentState())
        assertTrue(adapter.containsBlob(TEST_KEY))
        adapter.loadBlob(TEST_KEY)!!.use { loaded ->
            assertArrayEquals(payload, loaded.copyBytes())
        }

        val selectedAlias = records.read(TEST_KEY)!!.keyAlias
        assertTrue(keys.contains(selectedAlias))
        adapter.deleteBlob(TEST_KEY)
        assertFalse(records.exists(TEST_KEY))
        assertFalse(keys.contains(selectedAlias))
        assertEquals(UnlockEnrollmentState.NOT_ENROLLED, adapter.enrollmentState())
        payload.fill(0)
    }

    @Test
    fun permanentKeyInvalidationDeletesTheAtomicItemAndReportsInvalidated() {
        val payload = ByteArray(64) { it.toByte() }
        adapter.authorizeStoreUserPresence()
        adapter.storeBlob(TEST_KEY, VaultKernSensitiveBytes.fromByteArray(payload))
        val selectedAlias = records.read(TEST_KEY)!!.keyAlias
        keys.invalidatedAlias = selectedAlias

        val result = runCatching { adapter.loadBlob(TEST_KEY) }

        assertTrue(result.exceptionOrNull() is PlatformAdapterException.Invalidated)
        assertFalse(records.exists(TEST_KEY))
        assertFalse(keys.contains(selectedAlias))
        assertEquals(UnlockEnrollmentState.INVALIDATED, adapter.enrollmentState())

        // The core defensively deletes again after receiving Invalidated.
        // That idempotent cleanup must not erase the UI classification.
        adapter.deleteBlob(TEST_KEY)
        assertEquals(UnlockEnrollmentState.INVALIDATED, adapter.enrollmentState(TEST_KEY))

        // A later explicit revoke is distinct from the core's one cleanup
        // retry and must converge the visible state to not enrolled.
        adapter.deleteBlob(TEST_KEY)
        assertEquals(UnlockEnrollmentState.NOT_ENROLLED, adapter.enrollmentState(TEST_KEY))
    }

    @Test
    fun unrecoverableKeystoreKeyDeletesTheAtomicItemAndReportsInvalidated() {
        adapter.authorizeStoreUserPresence()
        adapter.storeBlob(
            TEST_KEY,
            VaultKernSensitiveBytes.fromByteArray(ByteArray(32) { 3 }),
        )
        val selectedAlias = records.read(TEST_KEY)!!.keyAlias
        keys.unrecoverableAlias = selectedAlias

        val result = runCatching { adapter.loadBlob(TEST_KEY) }

        assertTrue(result.exceptionOrNull() is PlatformAdapterException.Invalidated)
        assertFalse(records.exists(TEST_KEY))
        assertFalse(keys.contains(selectedAlias))
        assertEquals(UnlockEnrollmentState.INVALIDATED, adapter.enrollmentState(TEST_KEY))
    }

    @Test
    fun genericAuthorizationAlwaysRequestsFreshUserVerification() {
        adapter.authorize("Verify user for passkey")
        adapter.authorize("Verify user for passkey")

        assertEquals(2, freshUserVerifications)
    }

    @Test
    fun postCommitOrphanCleanupFailureNeverDeletesTheNewAtomicItem() {
        adapter.authorizeStoreUserPresence()
        adapter.storeBlob(
            TEST_KEY,
            VaultKernSensitiveBytes.fromByteArray(ByteArray(32) { 1 }),
        )
        val oldAlias = records.read(TEST_KEY)!!.keyAlias
        keys.failNextDeleteAlias = oldAlias

        adapter.authorizeStoreUserPresence()
        adapter.storeBlob(
            TEST_KEY,
            VaultKernSensitiveBytes.fromByteArray(ByteArray(32) { 2 }),
        )

        val committed = records.read(TEST_KEY)!!
        assertTrue(keys.contains(committed.keyAlias))
        assertEquals(UnlockEnrollmentState.ENROLLED, adapter.enrollmentState())
        assertTrue(adapter.maintenanceRequired())
        adapter.loadBlob(TEST_KEY)!!.use { loaded ->
            assertArrayEquals(ByteArray(32) { 2 }, loaded.copyBytes())
        }
        adapter.reconcileStorage()
        assertFalse(adapter.maintenanceRequired())
        assertFalse(keys.contains(oldAlias))
    }

    @Test
    fun biometricCancellationPreservesTheCommittedAtomicItem() {
        adapter.authorizeStoreUserPresence()
        adapter.storeBlob(
            TEST_KEY,
            VaultKernSensitiveBytes.fromByteArray(ByteArray(32) { 7 }),
        )
        val alias = records.read(TEST_KEY)!!.keyAlias
        biometricFailure = BiometricCancelledException()

        val result = runCatching { adapter.loadBlob(TEST_KEY) }

        assertTrue(result.exceptionOrNull() is PlatformAdapterException.Cancelled)
        assertTrue(records.exists(TEST_KEY))
        assertTrue(keys.contains(alias))
        assertEquals(UnlockEnrollmentState.ENROLLED, adapter.enrollmentState(TEST_KEY))
    }

    @Test
    fun cancelledReplacementEnrollmentKeepsThePreviousAtomicItem() {
        adapter.authorizeStoreUserPresence()
        adapter.storeBlob(
            TEST_KEY,
            VaultKernSensitiveBytes.fromByteArray(ByteArray(32) { 4 }),
        )
        val original = records.read(TEST_KEY)!!
        biometricFailure = BiometricCancelledException()

        val result = runCatching { adapter.authorizeStoreUserPresence() }

        assertTrue(result.exceptionOrNull() is PlatformAdapterException.Cancelled)
        assertEquals(original.keyAlias, records.read(TEST_KEY)!!.keyAlias)
        assertTrue(keys.contains(original.keyAlias))
        assertEquals(setOf(original.keyAlias), keys.aliases())
    }

    @Test
    fun storageReconciliationPreservesAnAuthorizedPendingKey() {
        adapter.authorizeStoreUserPresence()
        val pendingAlias = keys.aliases().single()

        adapter.reconcileStorage()

        assertTrue(keys.contains(pendingAlias))
        adapter.storeBlob(
            TEST_KEY,
            VaultKernSensitiveBytes.fromByteArray(ByteArray(32) { 6 }),
        )
        assertTrue(adapter.containsBlob(TEST_KEY))
    }

    @Test
    fun reconciliationScanCannotDeleteAConcurrentlyPreparedKey() {
        val executor = Executors.newFixedThreadPool(2)
        keys.blockNextAliasesScan = true

        try {
            val reconciliation = executor.submit { adapter.reconcileStorage() }
            assertTrue(keys.aliasesScanStarted.await(5, TimeUnit.SECONDS))

            val authorization = executor.submit { adapter.authorizeStoreUserPresence() }
            keys.encryptionPrepared.await(250, TimeUnit.MILLISECONDS)
            keys.finishAliasesScan.countDown()

            reconciliation.get(5, TimeUnit.SECONDS)
            authorization.get(5, TimeUnit.SECONDS)
            assertEquals(1, keys.aliases().size)
        } finally {
            keys.finishAliasesScan.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun releaseHardwarePolicyRefusesSoftwareKeysWithoutPersistingAnything() {
        val strict = AndroidUnlockBlobAdapter(
            records = records,
            cipherBackend = keys,
            biometricGate = BiometricGate { _, cipher -> cipher },
            userVerificationGate = UserVerificationGate { },
            requireHardwareBacked = true,
        )

        val result = runCatching { strict.authorizeStoreUserPresence() }

        assertTrue(result.exceptionOrNull() is PlatformAdapterException.Failure)
        assertFalse(records.exists(TEST_KEY))
        assertTrue(keys.aliases().isEmpty())
    }

    @Test
    fun releaseHardwarePolicyInvalidatesAndDeletesAnExistingSoftwareBlob() {
        adapter.authorizeStoreUserPresence()
        adapter.storeBlob(
            TEST_KEY,
            VaultKernSensitiveBytes.fromByteArray(ByteArray(32) { 8 }),
        )
        val alias = records.read(TEST_KEY)!!.keyAlias
        val strict = AndroidUnlockBlobAdapter(
            records = records,
            cipherBackend = keys,
            biometricGate = BiometricGate { _, cipher -> cipher },
            userVerificationGate = UserVerificationGate { },
            requireHardwareBacked = true,
        )

        val result = runCatching { strict.loadBlob(TEST_KEY) }

        assertTrue(result.exceptionOrNull() is PlatformAdapterException.Invalidated)
        assertFalse(records.exists(TEST_KEY))
        assertFalse(keys.contains(alias))
        assertEquals(UnlockEnrollmentState.INVALIDATED, strict.enrollmentState(TEST_KEY))
    }

    @Test
    fun productKeystoreKeyIsPerUseBiometricInvalidatedAndRecordsActualSecurity() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val biometricStatus = BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG,
        )
        assumeTrue(
            "requires an enrolled BIOMETRIC_STRONG authenticator",
            biometricStatus == BiometricManager.BIOMETRIC_SUCCESS,
        )
        val backend = AndroidKeystoreUnlockCipherBackend(context)
        val prepared = backend.prepareEncryption()

        try {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = store.getKey(prepared.keyAlias, null) as SecretKey
            val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            assertTrue(info.isUserAuthenticationRequired)
            assertEquals(0, info.userAuthenticationValidityDurationSeconds)
            assertTrue(info.isInvalidatedByBiometricEnrollment)
            val expected = when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> UnlockKeySecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                    UnlockKeySecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> UnlockKeySecurityLevel.SOFTWARE
                else -> UnlockKeySecurityLevel.UNKNOWN
            }
            assertEquals(expected, prepared.securityLevel)
        } finally {
            backend.delete(prepared.keyAlias)
        }
    }

    companion object {
        private const val TEST_KEY = "quick_unlock_instrumentation"
    }
}

private class FakeCipherBackend : UnlockCipherBackend {
    private val keys = ConcurrentHashMap<String, SecretKey>()
    var invalidatedAlias: String? = null
    var unrecoverableAlias: String? = null
    var failNextDeleteAlias: String? = null
    @Volatile
    var blockNextAliasesScan = false
    val aliasesScanStarted = CountDownLatch(1)
    val finishAliasesScan = CountDownLatch(1)
    val encryptionPrepared = CountDownLatch(1)

    override fun prepareEncryption(): PreparedUnlockCipher {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256, SecureRandom())
        val key = generator.generateKey()
        val alias = "test-${System.nanoTime()}"
        keys[alias] = key
        encryptionPrepared.countDown()
        return PreparedUnlockCipher(
            keyAlias = alias,
            cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.ENCRYPT_MODE, key)
            },
            securityLevel = UnlockKeySecurityLevel.SOFTWARE,
        )
    }

    override fun prepareDecryption(record: UnlockBlobRecord): PreparedUnlockCipher {
        if (invalidatedAlias == record.keyAlias) {
            throw KeyPermanentlyInvalidatedException()
        }
        if (unrecoverableAlias == record.keyAlias) {
            throw UnrecoverableKeyException("injected unrecoverable key")
        }
        val key = keys[record.keyAlias] ?: error("missing test key")
        return PreparedUnlockCipher(
            keyAlias = record.keyAlias,
            cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, record.iv))
            },
            securityLevel = record.securityLevel,
        )
    }

    override fun contains(alias: String): Boolean = keys.containsKey(alias)
    override fun delete(alias: String) {
        if (failNextDeleteAlias == alias) {
            failNextDeleteAlias = null
            error("injected key cleanup failure")
        }
        keys.remove(alias)
    }
    override fun aliases(): Set<String> {
        if (blockNextAliasesScan) {
            blockNextAliasesScan = false
            aliasesScanStarted.countDown()
            check(finishAliasesScan.await(5, TimeUnit.SECONDS))
        }
        return keys.keys.toSet()
    }

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
