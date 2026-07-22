package org.vaultkern.android.security

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher

fun interface BiometricGate {
    fun authenticate(reason: String, cipher: Cipher): Cipher
}

fun interface UserVerificationGate {
    fun authenticate(reason: String)
}

class BiometricCancelledException : Exception()
class BiometricUnavailableException : Exception()

class ProcessBiometricGate(
    private val context: Context,
) : BiometricGate, UserVerificationGate {
    override fun authenticate(reason: String, cipher: Cipher): Cipher {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "biometric authentication must run from a worker thread"
        }
        val token = BiometricRequestBroker.create(reason, cipher)
        val intent = Intent(context, BiometricGateActivity::class.java)
            .putExtra(BiometricGateActivity.EXTRA_TOKEN, token)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
        return try {
            context.startActivity(intent)
            BiometricRequestBroker.await(token) ?: throw BiometricUnavailableException()
        } catch (error: ExecutionException) {
            throw error.cause ?: error
        } finally {
            BiometricRequestBroker.remove(token)
        }
    }

    override fun authenticate(reason: String) {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "biometric authentication must run from a worker thread"
        }
        val token = BiometricRequestBroker.create(reason, null)
        val intent = Intent(context, BiometricGateActivity::class.java)
            .putExtra(BiometricGateActivity.EXTRA_TOKEN, token)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
        try {
            context.startActivity(intent)
            BiometricRequestBroker.await(token)
        } catch (error: ExecutionException) {
            throw error.cause ?: error
        } finally {
            BiometricRequestBroker.remove(token)
        }
    }
}

private data class PendingBiometricRequest(
    val reason: String,
    val cipher: Cipher?,
    val result: CompletableFuture<Cipher?> = CompletableFuture(),
)

private object BiometricRequestBroker {
    private val requests = ConcurrentHashMap<String, PendingBiometricRequest>()

    fun create(reason: String, cipher: Cipher?): String {
        val token = UUID.randomUUID().toString()
        requests[token] = PendingBiometricRequest(reason, cipher)
        return token
    }

    fun request(token: String): PendingBiometricRequest? = requests[token]

    fun await(token: String): Cipher? =
        requests[token]?.result?.get(TIMEOUT_MINUTES, TimeUnit.MINUTES)
            ?: throw BiometricUnavailableException()

    fun succeed(token: String, cipher: Cipher?) {
        requests[token]?.result?.complete(cipher)
    }

    fun fail(token: String, error: Throwable) {
        requests[token]?.result?.completeExceptionally(error)
    }

    fun remove(token: String) {
        requests.remove(token)
    }

    private const val TIMEOUT_MINUTES = 2L
}

class BiometricGateActivity : FragmentActivity() {
    private lateinit var token: String
    private var completed = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        token = intent.getStringExtra(EXTRA_TOKEN).orEmpty()
        val request = BiometricRequestBroker.request(token)
        if (request == null) {
            finish()
            return
        }
        val prompt = BiometricPrompt(
            this,
            mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult,
                ) {
                    val pending = BiometricRequestBroker.request(token)
                    val authorized = result.cryptoObject?.cipher
                    if (pending?.cipher != null && authorized == null) {
                        completeFailure(BiometricUnavailableException())
                    } else {
                        completed = true
                        BiometricRequestBroker.succeed(token, authorized)
                        finish()
                    }
                }

                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence,
                ) {
                    val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    completeFailure(
                        if (cancelled) BiometricCancelledException()
                        else BiometricUnavailableException(),
                    )
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(request.reason)
            .setSubtitle("Confirm your identity")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .build()
        if (request.cipher == null) {
            prompt.authenticate(info)
        } else {
            prompt.authenticate(info, BiometricPrompt.CryptoObject(request.cipher))
        }
    }

    override fun onDestroy() {
        if (!completed && ::token.isInitialized && !isChangingConfigurations) {
            BiometricRequestBroker.fail(token, BiometricCancelledException())
        }
        super.onDestroy()
    }

    private fun completeFailure(error: Throwable) {
        completed = true
        BiometricRequestBroker.fail(token, error)
        finish()
    }

    companion object {
        const val EXTRA_TOKEN = "org.vaultkern.android.biometric.TOKEN"
    }
}
