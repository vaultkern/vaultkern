package org.vaultkern.android.credentials

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.vaultkern.android.VaultKernApplication

class PasskeyCreateActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val providerRequest = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val request = providerRequest?.callingRequest as? CreatePublicKeyCredentialRequest
        if (providerRequest == null || request == null) {
            finishWithError()
            return
        }
        val graph = (application as VaultKernApplication).graph
        lifecycleScope.launch(Dispatchers.IO) {
            val result = credentialResult {
                val options = graph.webAuthnCodec.parseCreationOptions(request.requestJson)
                val context = graph.passkeyClientContext.resolve(
                    options.relyingParty,
                    providerRequest.callingAppInfo,
                    request.clientDataHash,
                )
                graph.passkeyCeremony.register(request.requestJson, context)
            }
            withContext(Dispatchers.Main) {
                result.fold(
                    onSuccess = ::finishWithResponse,
                    onFailure = { finishWithError() },
                )
            }
        }
    }

    private fun finishWithResponse(responseJson: String) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(
            result,
            CreatePublicKeyCredentialResponse(responseJson),
        )
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private fun finishWithError() {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialException(
            result,
            CreateCredentialUnknownException("VaultKern could not create this passkey"),
        )
        setResult(Activity.RESULT_OK, result)
        finish()
    }
}
