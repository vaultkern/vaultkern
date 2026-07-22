package org.vaultkern.android.credentials

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import org.vaultkern.android.VaultKernApplication

class VaultKernCredentialProviderService : CredentialProviderService() {
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (cancellationSignal.isCanceled) return
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            callback.onError(CreateCredentialUnknownException("Unsupported credential type"))
            return
        }
        val graph = (application as VaultKernApplication).graph
        val state = graph.session.sessionState()
        if (state.currentVaultRefId == null ||
            (!state.unlocked &&
                graph.currentEnrollmentState() != org.vaultkern.android.security.UnlockEnrollmentState.ENROLLED)
        ) {
            callback.onError(CreateCredentialUnknownException("Open VaultKern before creating a passkey"))
            return
        }
        val entry = CreateEntry.Builder(
            "VaultKern",
            pendingIntent(PasskeyCreateActivity::class.java),
        ).build()
        if (!cancellationSignal.isCanceled) {
            callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        if (cancellationSignal.isCanceled) return
        val options = request.beginGetCredentialOptions
            .filterIsInstance<BeginGetPublicKeyCredentialOption>()
        if (options.isEmpty()) {
            callback.onError(NoCredentialException("No public-key request"))
            return
        }
        val graph = (application as VaultKernApplication).graph
        val state = graph.session.sessionState()
        val builder = BeginGetCredentialResponse.Builder()
        var added = false
        if (state.unlocked) {
            val stored = try {
                graph.session.listPasskeyCredentials()
            } catch (_: Throwable) {
                callback.onError(androidx.credentials.exceptions.GetCredentialUnknownException())
                return
            }
            options.forEach { option ->
                val parsed = runCatching { graph.webAuthnCodec.parseRequestOptions(option.requestJson) }
                    .getOrNull() ?: return@forEach
                stored.asSequence()
                    .filter { credential ->
                        credential.relyingParty == parsed.relyingParty &&
                            (parsed.allowedCredentialIds.isEmpty() ||
                                parsed.allowedCredentialIds.any {
                                    it.contentEquals(credential.credentialId)
                                })
                    }
                    .forEach { credential ->
                        builder.addCredentialEntry(
                            PublicKeyCredentialEntry.Builder(
                                applicationContext,
                                credential.userName,
                                pendingIntent(
                                    PasskeyGetActivity::class.java,
                                    credential.credentialId,
                                    CredentialOptionBinding.key(
                                        option.requestJson,
                                        option.clientDataHash,
                                    ),
                                ),
                                option,
                            )
                                .setDisplayName(credential.userDisplayName)
                                .build(),
                        )
                        added = true
                    }
            }
        } else if (
            state.currentVaultRefId != null &&
            graph.currentEnrollmentState() ==
            org.vaultkern.android.security.UnlockEnrollmentState.ENROLLED
        ) {
            options.forEach { option ->
                builder.addCredentialEntry(
                    PublicKeyCredentialEntry.Builder(
                        applicationContext,
                        "Unlock VaultKern",
                        pendingIntent(
                            PasskeyGetActivity::class.java,
                            optionKey = CredentialOptionBinding.key(
                                option.requestJson,
                                option.clientDataHash,
                            ),
                        ),
                        option,
                    )
                        .setDisplayName("VaultKern passkey")
                        .build(),
                )
                added = true
            }
        }
        if (cancellationSignal.isCanceled) return
        if (added) callback.onResult(builder.build())
        else callback.onError(NoCredentialException("No matching VaultKern passkey"))
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        if (!cancellationSignal.isCanceled) callback.onResult(null)
    }

    private fun pendingIntent(
        activity: Class<*>,
        credentialId: ByteArray? = null,
        optionKey: String? = null,
    ): PendingIntent {
        val intent = Intent(this, activity)
        credentialId?.let {
            intent.putExtra(EXTRA_CREDENTIAL_ID, Base64.getUrlEncoder().withoutPadding().encodeToString(it))
        }
        optionKey?.let { intent.putExtra(EXTRA_OPTION_KEY, it) }
        return PendingIntent.getActivity(
            this,
            requestCodes.incrementAndGet(),
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    companion object {
        const val EXTRA_CREDENTIAL_ID = "org.vaultkern.android.passkey.CREDENTIAL_ID"
        const val EXTRA_OPTION_KEY = "org.vaultkern.android.passkey.OPTION_KEY"
        private val requestCodes = AtomicInteger(1_000)
    }
}
