package org.vaultkern.android.credentials

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.vaultkern.android.VaultKernApplication

class PasskeyGetActivity : FragmentActivity() {
    private val completionStarted = AtomicBoolean(false)
    private var activeAssertion: ActivePasskeyAssertion? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val providerRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (providerRequest == null) {
            finishWithError()
            return
        }
        val selectedCredentialId = intent.getStringExtra(
            VaultKernCredentialProviderService.EXTRA_CREDENTIAL_ID,
        )?.let(::decodeCredentialId)
        val selectedOptionKey = intent.getStringExtra(
            VaultKernCredentialProviderService.EXTRA_OPTION_KEY,
        )
        val options = providerRequest.credentialOptions
            .filterIsInstance<GetPublicKeyCredentialOption>()
        val graph = (application as VaultKernApplication).graph
        lifecycleScope.launch(Dispatchers.IO) {
            val result = runCatching {
                val request = selectRequest(
                    options,
                    selectedCredentialId,
                    selectedOptionKey,
                    graph.webAuthnCodec,
                )
                val parsed = graph.webAuthnCodec.parseRequestOptions(request.requestJson)
                val context = graph.passkeyClientContext.resolve(
                    parsed.relyingParty,
                    providerRequest.callingAppInfo,
                    request.clientDataHash,
                )
                Triple(
                    request,
                    selectedCredentialId,
                    graph.passkeyCeremony.beginAssertion(request.requestJson, context),
                )
            }
            withContext(Dispatchers.Main) {
                result.fold(
                    onSuccess = { (_, selected, active) ->
                        activeAssertion = active
                        when {
                            selected != null -> complete(selected)
                            active.candidates.size == 1 ->
                                complete(active.candidates.single().credentialId)
                            else -> showCandidates(active.candidates)
                        }
                    },
                    onFailure = { finishWithError() },
                )
            }
        }
    }

    override fun onDestroy() {
        closeAssertionBestEffort()
        activeAssertion = null
        super.onDestroy()
    }

    private fun showCandidates(candidates: List<PasskeyCandidate>) {
        setContent { PasskeyCandidatePicker(candidates, ::complete) }
    }

    private fun complete(credentialId: ByteArray) {
        if (!completionStarted.compareAndSet(false, true)) return
        val active = activeAssertion ?: run {
            finishWithError()
            return
        }
        lifecycleScope.launch(Dispatchers.IO) {
            val result = runCatching { active.complete(credentialId) }
            withContext(Dispatchers.Main) {
                activeAssertion = null
                result.fold(
                    onSuccess = ::finishWithResponse,
                    onFailure = { finishWithError() },
                )
            }
        }
    }

    private fun finishWithResponse(responseJson: String) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(
            result,
            GetCredentialResponse(PublicKeyCredential(responseJson)),
        )
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private fun finishWithError() {
        completionStarted.set(true)
        closeAssertionBestEffort()
        activeAssertion = null
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(
            result,
            GetCredentialUnknownException("VaultKern could not assert this passkey"),
        )
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private fun closeAssertionBestEffort() {
        val assertion = activeAssertion ?: return
        if (runCatching { assertion.close() }.isFailure) {
            runCatching { assertion.close() }
        }
    }

    private fun decodeCredentialId(value: String): ByteArray = try {
        Base64.getUrlDecoder().decode(value)
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException("selected credential id is invalid", error)
    }

    private fun selectRequest(
        options: List<GetPublicKeyCredentialOption>,
        selectedCredentialId: ByteArray?,
        selectedOptionKey: String?,
        codec: WebAuthnCodec,
    ): GetPublicKeyCredentialOption {
        require(!selectedOptionKey.isNullOrBlank()) { "credential option binding is missing" }
        return options.firstOrNull { option ->
            CredentialOptionBinding.key(option.requestJson, option.clientDataHash) ==
                selectedOptionKey &&
                (selectedCredentialId == null ||
                    runCatching { codec.parseRequestOptions(option.requestJson) }.getOrNull()
                        ?.let { parsed ->
                            parsed.allowedCredentialIds.isEmpty() ||
                                parsed.allowedCredentialIds.any {
                                    it.contentEquals(selectedCredentialId)
                                }
                        } == true)
        } ?: throw IllegalArgumentException("selected credential is not allowed by any request")
    }
}

@Composable
private fun PasskeyCandidatePicker(
    candidates: List<PasskeyCandidate>,
    onSelected: (ByteArray) -> Unit,
) {
    MaterialTheme {
        Column(
            modifier = Modifier.fillMaxSize().padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Choose a passkey", style = MaterialTheme.typography.headlineSmall)
            candidates.forEach { candidate ->
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelected(candidate.credentialId.copyOf()) }
                        .padding(vertical = 12.dp),
                ) {
                    Text(candidate.userDisplayName, style = MaterialTheme.typography.titleMedium)
                    Text(candidate.userName)
                    Text(candidate.relyingPartyName)
                }
            }
        }
    }
}
