package org.vaultkern.android.credentials

import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import org.vaultkern.core.PlatformPasskeyCredential
import org.vaultkern.core.VaultPasskeyOperation
import org.vaultkern.core.VaultSession

fun interface FreshUserVerification {
    fun verify(reason: String)
}

class PasskeyCeremony(
    private val session: VaultSession,
    private val verifier: FreshUserVerification,
    private val codec: WebAuthnCodec = WebAuthnCodec(),
    private val operationId: () -> ByteArray = SecureOperationIdGenerator(),
    private val clock: MonotonicClock = MonotonicClock(System::nanoTime),
) {
    fun register(requestJson: String, context: PasskeyClientContext): String {
        val options = codec.parseCreationOptions(requestJson)
        val operation = session.beginPasskeyOperation(validOperationId())
        var primaryFailure: Throwable? = null
        try {
            ensureFreshUserVerification(operation, "Verify passkey registration")
            val credentials = operation.credentials()
            require(
                options.excludedCredentialIds.none { excluded ->
                    credentials.any { it.credentialId.contentEquals(excluded) }
                },
            ) { "an excluded passkey credential already exists" }
            val output = operation.registerPasskey(options.registrationInput())
            val response = codec.registrationResponse(options, context, output)
            operation.commitRegistration()
            return response
        } catch (error: Throwable) {
            primaryFailure = error
            throw error
        } finally {
            finishOperation(operation, primaryFailure)
        }
    }

    fun beginAssertion(
        requestJson: String,
        context: PasskeyClientContext,
    ): ActivePasskeyAssertion {
        val options = codec.parseRequestOptions(requestJson)
        val operation = session.beginPasskeyOperation(validOperationId())
        try {
            val verifiedAt = ensureFreshUserVerification(operation, "Verify passkey assertion")
            val candidates = operation.credentials().filter { credential ->
                credential.relyingParty == options.relyingParty &&
                    (options.allowedCredentialIds.isEmpty() ||
                        options.allowedCredentialIds.any { it.contentEquals(credential.credentialId) })
            }
            require(candidates.isNotEmpty()) { "no matching passkey credential" }
            return ActivePasskeyAssertion(
                operation,
                options,
                context,
                candidates,
                codec,
                FreshUserVerificationLease(verifier, clock, verifiedAt),
            )
        } catch (error: Throwable) {
            finishOperation(operation, error)
            throw error
        }
    }

    fun assert(
        requestJson: String,
        context: PasskeyClientContext,
        selectedCredentialId: ByteArray? = null,
    ): String = beginAssertion(requestJson, context).use { active ->
        active.complete(selectedCredentialId)
    }

    private fun ensureFreshUserVerification(operation: VaultPasskeyOperation, reason: String): Long {
        if (!operation.freshUserVerification()) verifier.verify(reason)
        return clock.nowNanos()
    }

    private fun validOperationId(): ByteArray = operationId().also { value ->
        require(value.size == OPERATION_ID_BYTES) { "passkey operation id must be 16 bytes" }
    }

    private class SecureOperationIdGenerator : () -> ByteArray {
        private val random = SecureRandom()
        override fun invoke(): ByteArray = ByteArray(OPERATION_ID_BYTES).also(random::nextBytes)
    }

    companion object {
        private const val OPERATION_ID_BYTES = 16
    }
}

class ActivePasskeyAssertion internal constructor(
    private val operation: VaultPasskeyOperation,
    private val options: ParsedRequestOptions,
    private val context: PasskeyClientContext,
    credentials: List<PlatformPasskeyCredential>,
    private val codec: WebAuthnCodec,
    private val verificationLease: FreshUserVerificationLease,
) : AutoCloseable {
    val candidates: List<PasskeyCandidate> = credentials.map(::PasskeyCandidate)
    private val completionStarted = AtomicBoolean(false)
    private val finished = AtomicBoolean(false)

    fun complete(selectedCredentialId: ByteArray?): String {
        val selected = when {
            selectedCredentialId != null -> selectedCredentialId.copyOf()
            candidates.size == 1 -> candidates.single().credentialId.copyOf()
            else -> throw IllegalArgumentException("a passkey credential selection is required")
        }
        require(candidates.any { it.credentialId.contentEquals(selected) }) {
            "selected passkey credential is not a candidate"
        }
        check(completionStarted.compareAndSet(false, true)) {
            "passkey assertion operation is already completing or closed"
        }
        check(!finished.get()) { "passkey assertion operation is already closed" }
        var primaryFailure: Throwable? = null
        try {
            verificationLease.refreshIfStale("Verify passkey assertion")
            val prepared = codec.prepareAssertion(options, context, selected)
            val output = operation.assertPasskey(prepared.input)
            return codec.assertionResponse(prepared, output)
        } catch (error: Throwable) {
            primaryFailure = error
            throw error
        } finally {
            closeWithPrimaryFailure(primaryFailure)
        }
    }

    override fun close() {
        if (completionStarted.get()) return
        closeWithPrimaryFailure(null)
    }

    private fun closeWithPrimaryFailure(primaryFailure: Throwable?) {
        if (!finished.compareAndSet(false, true)) return
        val finishFailure = finishOperationTwice(operation)
        if (finishFailure != null) {
            finished.set(false)
            if (primaryFailure == null) throw finishFailure
            primaryFailure.addSuppressed(finishFailure)
        }
    }
}

data class PasskeyCandidate(
    val credentialId: ByteArray,
    val relyingParty: String,
    val relyingPartyName: String,
    val userName: String,
    val userDisplayName: String,
) {
    internal constructor(value: PlatformPasskeyCredential) : this(
        credentialId = value.credentialId.copyOf(),
        relyingParty = value.relyingParty,
        relyingPartyName = value.relyingPartyName,
        userName = value.userName,
        userDisplayName = value.userDisplayName,
    )

    override fun toString(): String =
        "PasskeyCandidate(credentialId=[REDACTED], relyingParty=$relyingParty, " +
            "relyingPartyName=[REDACTED], userName=[REDACTED], userDisplayName=[REDACTED])"
}

private fun finishOperation(operation: VaultPasskeyOperation, primaryFailure: Throwable?) {
    finishOperationTwice(operation)?.let { finishFailure ->
        if (primaryFailure == null) throw finishFailure
        primaryFailure.addSuppressed(finishFailure)
    }
}

private fun finishOperationTwice(operation: VaultPasskeyOperation): Throwable? {
    var firstFailure: Throwable? = null
    repeat(2) {
        try {
            operation.finish()
            return null
        } catch (error: Throwable) {
            firstFailure?.addSuppressed(error) ?: run { firstFailure = error }
        }
    }
    return firstFailure
}
