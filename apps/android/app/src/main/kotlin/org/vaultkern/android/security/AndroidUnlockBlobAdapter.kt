package org.vaultkern.android.security

import android.security.keystore.KeyPermanentlyInvalidatedException
import java.security.InvalidKeyException
import java.security.UnrecoverableKeyException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.AEADBadTagException
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.UnlockBlobAdapter
import org.vaultkern.core.VaultKernSensitiveBytes

class AndroidUnlockBlobAdapter(
    private val records: AtomicUnlockBlobRecordStore,
    private val cipherBackend: UnlockCipherBackend,
    private val biometricGate: BiometricGate,
    private val userVerificationGate: UserVerificationGate,
    private val requireHardwareBacked: Boolean,
    private val biometricAvailable: () -> Boolean = { true },
) : UnlockBlobAdapter {
    private val pendingEncryption = AtomicReference<PreparedUnlockCipher?>()
    private val state = AtomicReference(UnlockEnrollmentState.NOT_ENROLLED)
    private val maintenancePending = AtomicBoolean(false)
    private val invalidatedKeys = ConcurrentHashMap.newKeySet<String>()
    private val pendingInvalidationDeletes = ConcurrentHashMap.newKeySet<String>()

    override fun supportsUnlockBlob(): Boolean = biometricAvailable()

    override fun authorize(reason: String) {
        try {
            userVerificationGate.authenticate(reason)
        } catch (error: Throwable) {
            throw mapPlatformError(error)
        }
    }

    override fun storeRequiresUserPresence(): Boolean = true
    override fun loadRequiresUserPresence(): Boolean = true

    @Synchronized
    override fun authorizeStoreUserPresence() {
        pendingEncryption.getAndSet(null)?.let { stale ->
            if (!deleteKey(stale.keyAlias)) maintenancePending.set(true)
        }
        pendingEncryption.set(prepareAuthorizedEncryption("Enable quick unlock"))
    }

    @Synchronized
    override fun storeBlob(key: String, value: VaultKernSensitiveBytes) {
        val plaintext = try {
            value.copyBytes()
        } finally {
            value.close()
        }
        var prepared = pendingEncryption.getAndSet(null)
        val oldRecord = runCatching { records.read(key) }.getOrNull()
        var committed = false
        var ciphertext: ByteArray? = null
        try {
            if (prepared == null) {
                prepared = prepareAuthorizedEncryption("Refresh quick unlock")
            }
            ciphertext = prepared.cipher.doFinal(plaintext)
            val record = UnlockBlobRecord(
                keyAlias = prepared.keyAlias,
                iv = prepared.cipher.iv.copyOf(),
                ciphertext = ciphertext,
                securityLevel = prepared.securityLevel,
            )
            records.write(key, record)
            committed = true
            invalidatedKeys.remove(key)
            pendingInvalidationDeletes.remove(key)
            state.set(UnlockEnrollmentState.ENROLLED)
        } catch (error: Throwable) {
            if (!committed) {
                prepared?.let { candidate ->
                    if (!deleteKey(candidate.keyAlias)) maintenancePending.set(true)
                }
            }
            throw mapPlatformError(error)
        } finally {
            plaintext.fill(0)
            ciphertext?.fill(0)
        }

        val cleanup = runCatching {
            runAllMaintenance(
                {
                    if (oldRecord != null && oldRecord.keyAlias != prepared?.keyAlias) {
                        cipherBackend.delete(oldRecord.keyAlias)
                    }
                },
                ::cleanupOrphans,
            )
        }
        maintenancePending.set(cleanup.isFailure)
    }

    @Synchronized
    override fun loadBlob(key: String): VaultKernSensitiveBytes? {
        val record = try {
            records.read(key)
        } catch (_: Throwable) {
            invalidate(key, null, expectCoreDelete = true)
            throw PlatformAdapterException.Invalidated()
        } ?: run {
            state.set(stateForMissingRecord(key))
            return null
        }

        val prepared = prepareCommittedDecryption(
            key = key,
            record = record,
            expectCoreDelete = true,
        )

        val authorized = try {
            biometricGate.authenticate("Unlock this vault", prepared.cipher)
        } catch (error: Throwable) {
            throw mapPlatformError(error)
        }
        val plaintext = try {
            authorized.doFinal(record.ciphertext)
        } catch (error: Throwable) {
            if (isPermanentInvalidation(error) || error is AEADBadTagException) {
                invalidate(key, record, expectCoreDelete = true)
                throw PlatformAdapterException.Invalidated()
            }
            throw mapPlatformError(error)
        }
        state.set(UnlockEnrollmentState.ENROLLED)
        return try {
            VaultKernSensitiveBytes.fromByteArray(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    @Synchronized
    override fun containsBlob(key: String): Boolean {
        val record = try {
            records.read(key)
        } catch (_: Throwable) {
            invalidate(key, null, expectCoreDelete = false)
            return false
        } ?: return false.also {
            state.set(stateForMissingRecord(key))
        }
        try {
            prepareCommittedDecryption(
                key = key,
                record = record,
                expectCoreDelete = false,
            )
        } catch (_: PlatformAdapterException.Invalidated) {
            return false
        }
        state.set(UnlockEnrollmentState.ENROLLED)
        return true
    }

    @Synchronized
    override fun deleteBlob(key: String) {
        val preserveInvalidatedState = pendingInvalidationDeletes.remove(key)
        val record = runCatching { records.read(key) }.getOrNull()
        records.delete(key)
        if (!preserveInvalidatedState) invalidatedKeys.remove(key)
        state.set(
            if (preserveInvalidatedState) UnlockEnrollmentState.INVALIDATED
            else UnlockEnrollmentState.NOT_ENROLLED,
        )
        val cleanup = runCatching {
            val pending = pendingEncryption.getAndSet(null)
            runAllMaintenance(
                { record?.let { cipherBackend.delete(it.keyAlias) } },
                { pending?.let { cipherBackend.delete(it.keyAlias) } },
                ::cleanupOrphans,
            )
        }
        maintenancePending.set(cleanup.isFailure)
        cleanup.exceptionOrNull()?.let { throw mapPlatformError(it) }
    }

    @Synchronized
    fun deleteAll() {
        val pending = pendingEncryption.getAndSet(null)
        invalidatedKeys.clear()
        pendingInvalidationDeletes.clear()
        val cleanup = runCatching {
            runAllMaintenance(
                records::deleteAll,
                { pending?.let { cipherBackend.delete(it.keyAlias) } },
                { deleteAliases(cipherBackend.aliases()) },
            )
        }
        state.set(
            if (records.hasAny()) UnlockEnrollmentState.INVALIDATED
            else UnlockEnrollmentState.NOT_ENROLLED,
        )
        maintenancePending.set(cleanup.isFailure)
        cleanup.exceptionOrNull()?.let { throw mapPlatformError(it) }
    }

    fun enrollmentState(): UnlockEnrollmentState = state.get()

    @Synchronized
    fun enrollmentState(key: String): UnlockEnrollmentState =
        if (invalidatedKeys.contains(key)) {
            UnlockEnrollmentState.INVALIDATED
        } else if (containsBlob(key)) {
            UnlockEnrollmentState.ENROLLED
        } else {
            stateForMissingRecord(key)
        }

    @Synchronized
    fun securityLevel(key: String): UnlockKeySecurityLevel? {
        val record = try {
            records.read(key)
        } catch (_: Throwable) {
            invalidate(key, null, expectCoreDelete = false)
            return null
        } ?: return null
        val prepared = try {
            prepareCommittedDecryption(
                key = key,
                record = record,
                expectCoreDelete = false,
            )
        } catch (_: PlatformAdapterException.Invalidated) {
            return null
        }
        state.set(UnlockEnrollmentState.ENROLLED)
        return prepared.securityLevel
    }

    fun maintenanceRequired(): Boolean = maintenancePending.get()

    @Synchronized
    fun finishStoreAttempt() {
        pendingEncryption.getAndSet(null)?.let { abandoned ->
            if (!deleteKey(abandoned.keyAlias)) maintenancePending.set(true)
        }
    }

    @Synchronized
    fun reconcileStorage() {
        try {
            cleanupOrphans()
            maintenancePending.set(false)
        } catch (error: Throwable) {
            maintenancePending.set(true)
            throw mapPlatformError(error)
        }
    }

    private fun prepareAuthorizedEncryption(reason: String): PreparedUnlockCipher {
        val prepared = try {
            cipherBackend.prepareEncryption()
        } catch (error: Throwable) {
            throw mapPlatformError(error)
        }
        return try {
            enforceHardwarePolicy(prepared)
            prepared.copy(cipher = biometricGate.authenticate(reason, prepared.cipher))
        } catch (error: Throwable) {
            if (!deleteKey(prepared.keyAlias)) maintenancePending.set(true)
            throw mapPlatformError(error)
        }
    }

    private fun enforceHardwarePolicy(prepared: PreparedUnlockCipher) {
        if (requireHardwareBacked && !prepared.securityLevel.isHardwareBacked) {
            throw UnsupportedUnlockKeySecurityException()
        }
    }

    private fun prepareCommittedDecryption(
        key: String,
        record: UnlockBlobRecord,
        expectCoreDelete: Boolean,
    ): PreparedUnlockCipher = try {
        cipherBackend.prepareDecryption(record).also(::enforceHardwarePolicy)
    } catch (error: Throwable) {
        if (isPermanentInvalidation(error) ||
            error is UnsupportedUnlockKeySecurityException
        ) {
            invalidate(key, record, expectCoreDelete)
            throw PlatformAdapterException.Invalidated()
        }
        throw mapPlatformError(error)
    }

    private fun invalidate(
        key: String,
        record: UnlockBlobRecord?,
        expectCoreDelete: Boolean,
    ) {
        records.delete(key)
        invalidatedKeys.add(key)
        if (expectCoreDelete) pendingInvalidationDeletes.add(key)
        else pendingInvalidationDeletes.remove(key)
        state.set(UnlockEnrollmentState.INVALIDATED)
        val cleanup = runCatching {
            runAllMaintenance(
                { record?.let { cipherBackend.delete(it.keyAlias) } },
                ::cleanupOrphans,
            )
        }
        maintenancePending.set(cleanup.isFailure)
    }

    private fun cleanupOrphans() {
        records.discardUncommittedWrites()
        val selected = buildSet {
            pendingEncryption.get()?.let { add(it.keyAlias) }
            records.keys().forEach { key ->
                val record = try {
                    records.read(key)
                } catch (_: Throwable) {
                    records.delete(key)
                    invalidatedKeys.add(key)
                    pendingInvalidationDeletes.remove(key)
                    state.set(UnlockEnrollmentState.INVALIDATED)
                    null
                }
                record?.let { add(it.keyAlias) }
            }
        }
        cipherBackend.aliases()
            .filterNot(selected::contains)
            .let(::deleteAliases)
    }

    private fun deleteAliases(aliases: Iterable<String>) {
        val actions = aliases.distinct().map { alias ->
            { cipherBackend.delete(alias) }
        }
        runAllMaintenance(*actions.toTypedArray())
    }

    private fun runAllMaintenance(vararg actions: () -> Unit) {
        var failure: Throwable? = null
        actions.forEach { action ->
            try {
                action()
            } catch (error: Throwable) {
                if (failure == null) {
                    failure = error
                } else if (failure !== error) {
                    failure?.addSuppressed(error)
                }
            }
        }
        failure?.let { throw it }
    }

    private fun deleteKey(alias: String): Boolean = runCatching {
        cipherBackend.delete(alias)
    }.isSuccess

    private fun stateForMissingRecord(key: String): UnlockEnrollmentState =
        if (invalidatedKeys.contains(key)) UnlockEnrollmentState.INVALIDATED
        else UnlockEnrollmentState.NOT_ENROLLED

    private fun mapPlatformError(error: Throwable): Exception = when (error) {
        is PlatformAdapterException -> error
        is BiometricCancelledException -> PlatformAdapterException.Cancelled()
        else -> PlatformAdapterException.Failure(error.javaClass.simpleName)
    }

    private fun isPermanentInvalidation(error: Throwable?): Boolean {
        var current = error
        while (current != null) {
            if (current is KeyPermanentlyInvalidatedException ||
                current is MissingUnlockKeyException ||
                current is UnrecoverableKeyException
            ) {
                return true
            }
            if (current is InvalidKeyException &&
                current.message?.contains("permanently invalidated", ignoreCase = true) == true
            ) {
                return true
            }
            current = current.cause
        }
        return false
    }
}

private class UnsupportedUnlockKeySecurityException :
    IllegalStateException("hardware-backed Android Keystore is unavailable")
