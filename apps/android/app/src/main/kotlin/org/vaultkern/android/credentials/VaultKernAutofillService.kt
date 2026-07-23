package org.vaultkern.android.credentials

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.View
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger
import org.vaultkern.android.VaultKernApplication
import org.vaultkern.android.security.UnlockEnrollmentState

class VaultKernAutofillService : AutofillService() {
    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        if (cancellationSignal.isCanceled) return
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onFailure("No autofill structure")
            return
        }
        val parsed = try {
            AutofillStructureParser.find(structure)
        } catch (_: IllegalArgumentException) {
            callback.onFailure("Unsupported autofill origin")
            return
        }
        if (parsed.ids.isEmpty) {
            callback.onSuccess(null)
            return
        }
        val graph = (application as VaultKernApplication).graph
        val state = graph.session.sessionState()
        if (!state.unlocked && graph.currentEnrollmentState() != UnlockEnrollmentState.ENROLLED) {
            callback.onFailure("Open VaultKern and enable quick unlock")
            return
        }
        val intent = Intent(this, AutofillAuthActivity::class.java).apply {
            putExtra(AutofillAuthActivity.EXTRA_USERNAME_ID, parsed.ids.username)
            putExtra(AutofillAuthActivity.EXTRA_PASSWORD_ID, parsed.ids.password)
            putExtra(AutofillAuthActivity.EXTRA_TOTP_ID, parsed.ids.totp)
            putExtra(AutofillAuthActivity.EXTRA_CALLING_PACKAGE, parsed.origin.packageName)
            putExtra(AutofillAuthActivity.EXTRA_WEB_SCHEME, parsed.origin.webScheme)
            putExtra(AutofillAuthActivity.EXTRA_WEB_DOMAIN, parsed.origin.webDomain)
        }
        val authentication = PendingIntent.getActivity(
            this,
            requestCodes.incrementAndGet(),
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        if (cancellationSignal.isCanceled) return
        callback.onSuccess(
            FillResponse.Builder()
                .addDataset(AutofillDatasetFactory.locked(this, parsed.ids, authentication))
                .build(),
        )
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onFailure("VaultKern does not capture credentials from Autofill")
    }

    companion object {
        private val requestCodes = AtomicInteger(2_000)
    }
}

internal data class ParsedAutofillRequest(
    val ids: AutofillFieldIds,
    val origin: AutofillRequestOrigin,
)

internal object AutofillStructureParser {
    fun find(structure: AssistStructure): ParsedAutofillRequest {
        var username: android.view.autofill.AutofillId? = null
        var password: android.view.autofill.AutofillId? = null
        var totp: android.view.autofill.AutofillId? = null
        val webOrigins = mutableSetOf<Pair<String?, String>>()

        fun visit(
            node: AssistStructure.ViewNode,
            inheritedScheme: String? = null,
            inheritedDomain: String? = null,
        ) {
            val webScheme = node.webScheme ?: inheritedScheme
            val webDomain = node.webDomain ?: inheritedDomain
            val hints = buildList {
                addAll(node.autofillHints.orEmpty())
                node.hint?.let(::add)
                node.idEntry?.let(::add)
                node.htmlInfo?.attributes?.forEach { attribute ->
                    if (attribute.first.equals("autocomplete", ignoreCase = true)) {
                        add(attribute.second)
                    }
                }
            }.map { it.lowercase(Locale.ROOT) }
            val recognized = when {
                hints.any(::isTotpHint) -> {
                    if (totp == null) totp = node.autofillId
                    true
                }
                hints.any(::isPasswordHint) -> {
                    if (password == null) password = node.autofillId
                    true
                }
                hints.any(::isUsernameHint) -> {
                    if (username == null) username = node.autofillId
                    true
                }
                else -> false
            }
            if (recognized && !webDomain.isNullOrBlank()) {
                webOrigins += webScheme to webDomain
            }
            for (index in 0 until node.childCount) {
                visit(node.getChildAt(index), webScheme, webDomain)
            }
        }

        for (window in 0 until structure.windowNodeCount) {
            visit(structure.getWindowNodeAt(window).rootViewNode)
        }
        require(webOrigins.size <= 1) { "autofill fields span multiple web origins" }
        val webOrigin = webOrigins.singleOrNull()
        val packageName = structure.activityComponent?.packageName
        require(!packageName.isNullOrBlank()) { "autofill caller package is missing" }
        return ParsedAutofillRequest(
            ids = AutofillFieldIds(username, password, totp),
            origin = AutofillRequestOrigin(
                packageName = packageName,
                webScheme = webOrigin?.first,
                webDomain = webOrigin?.second,
            ),
        )
    }

    private fun isUsernameHint(value: String): Boolean =
        value == View.AUTOFILL_HINT_USERNAME.lowercase(Locale.ROOT) ||
            value == View.AUTOFILL_HINT_EMAIL_ADDRESS.lowercase(Locale.ROOT) ||
            value == "username" || value == "email"

    private fun isPasswordHint(value: String): Boolean =
        value == View.AUTOFILL_HINT_PASSWORD.lowercase(Locale.ROOT) ||
            value == "current-password" || value == "password"

    private fun isTotpHint(value: String): Boolean =
        value == "smsotp" || value == "one-time-code" || value == "onetimecode" ||
            value == "otp" || value == "totp"
}
