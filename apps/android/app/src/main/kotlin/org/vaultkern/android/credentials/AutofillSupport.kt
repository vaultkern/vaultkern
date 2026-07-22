package org.vaultkern.android.credentials

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.service.autofill.Dataset
import android.service.autofill.Field
import android.service.autofill.Presentations
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import org.vaultkern.android.vault.closeSecrets
import org.vaultkern.core.VaultSession

data class AutofillFieldIds(
    val username: AutofillId?,
    val password: AutofillId?,
    val totp: AutofillId?,
) {
    val isEmpty: Boolean get() = username == null && password == null && totp == null

    override fun toString(): String =
        "AutofillFieldIds(username=${username != null}, password=${password != null}, " +
            "totp=${totp != null})"
}

class AutofillCredential(
    val entryId: String,
    val label: String,
    val username: String,
    val password: String,
    val totp: String?,
) {
    override fun toString(): String =
        "AutofillCredential(entryId=$entryId, label=[REDACTED], username=[REDACTED], " +
            "password=[REDACTED], totp=[REDACTED])"
}

data class AutofillCandidate(
    val entryId: String,
    val label: String,
    val username: String,
    val hasTotp: Boolean,
) {
    override fun toString(): String =
        "AutofillCandidate(entryId=$entryId, label=[REDACTED], username=[REDACTED], " +
            "hasTotp=$hasTotp)"
}

class PopulatedAutofillDataset(
    val dataset: Dataset,
    val values: Map<AutofillId, AutofillValue>,
) {
    override fun toString(): String =
        "PopulatedAutofillDataset(fieldCount=${values.size}, values=[REDACTED])"
}

object AutofillDatasetFactory {
    fun locked(
        context: Context,
        ids: AutofillFieldIds,
        authentication: PendingIntent,
    ): Dataset {
        require(!ids.isEmpty) { "autofill request has no supported fields" }
        val presentations = presentations(context, "Unlock VaultKern")
        val builder = Dataset.Builder(presentations)
        ids.username?.let { builder.setField(it, Field.Builder().setPresentations(presentations).build()) }
        ids.password?.let { builder.setField(it, Field.Builder().setPresentations(presentations).build()) }
        ids.totp?.let { builder.setField(it, Field.Builder().setPresentations(presentations).build()) }
        return builder.setAuthentication(authentication.intentSender).build()
    }

    fun populated(
        context: Context,
        ids: AutofillFieldIds,
        credential: AutofillCredential,
    ): PopulatedAutofillDataset {
        val values = buildMap {
            ids.username?.let { put(it, AutofillValue.forText(credential.username)) }
            ids.password?.let { put(it, AutofillValue.forText(credential.password)) }
            ids.totp?.let { id ->
                credential.totp?.let { put(id, AutofillValue.forText(it)) }
            }
        }
        require(values.isNotEmpty()) { "selected entry has no value for the requested fields" }
        val presentations = presentations(context, credential.label)
        val builder = Dataset.Builder(presentations)
        values.forEach { (id, value) ->
            builder.setField(
                id,
                Field.Builder().setValue(value).setPresentations(presentations).build(),
            )
        }
        return PopulatedAutofillDataset(builder.build(), values)
    }

    fun authenticationResult(dataset: Dataset): Intent =
        Intent().putExtra(android.view.autofill.AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset)

    private fun presentation(context: Context, label: String): RemoteViews =
        RemoteViews(context.packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, label)
        }

    private fun presentations(context: Context, label: String): Presentations =
        Presentations.Builder()
            .setMenuPresentation(presentation(context, label))
            .build()
}

class AutofillVaultPort(private val session: VaultSession) {
    fun candidates(requireTotp: Boolean): List<AutofillCandidate> =
        session.listEntries(activeVaultId())
            .asSequence()
            .filter { !requireTotp || it.hasTotp }
            .map { entry ->
                AutofillCandidate(
                    entryId = entry.id,
                    label = entry.title,
                    username = entry.username,
                    hasTotp = entry.hasTotp,
                )
            }
            .toList()

    fun credential(entryId: String): AutofillCredential {
        val detail = session.readEntry(activeVaultId(), entryId)
        return try {
            AutofillCredential(
                entryId = detail.id.reveal(),
                label = detail.title.reveal(),
                username = detail.username.reveal(),
                password = detail.password.reveal(),
                totp = detail.totp?.reveal(),
            )
        } finally {
            detail.closeSecrets()
        }
    }

    private fun activeVaultId(): String =
        session.sessionState().activeVaultId
            ?: error("no unlocked vault is active")
}
