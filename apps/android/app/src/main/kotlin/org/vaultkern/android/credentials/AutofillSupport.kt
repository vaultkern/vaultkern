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
        label: String,
        username: String?,
        password: String?,
        totp: String?,
    ): Dataset {
        val values = autofillValues(ids, username, password, totp)
        require(values.isNotEmpty()) { "selected entry has no value for the requested fields" }
        val presentations = presentations(context, label)
        val builder = Dataset.Builder(presentations)
        values.forEach { (id, value) ->
            builder.setField(
                id,
                Field.Builder().setValue(value).setPresentations(presentations).build(),
            )
        }
        return builder.build()
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

internal fun autofillValues(
    ids: AutofillFieldIds,
    username: String?,
    password: String?,
    totp: String?,
): Map<AutofillId, AutofillValue> = buildMap {
    ids.username?.let { id -> username?.let { put(id, AutofillValue.forText(it)) } }
    ids.password?.let { id -> password?.let { put(id, AutofillValue.forText(it)) } }
    ids.totp?.let { id -> totp?.let { put(id, AutofillValue.forText(it)) } }
}

class AutofillVaultPort(private val session: VaultSession) {
    fun candidates(
        target: AutofillTarget,
        requireTotp: Boolean,
    ): List<AutofillCandidate> =
        session.findFillCandidates(activeVaultId(), target.matchUrl)
            .asSequence()
            .filter { target.accepts(it.url) }
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

    fun populatedDataset(
        context: Context,
        ids: AutofillFieldIds,
        entryId: String,
    ): Dataset {
        val detail = session.readEntry(activeVaultId(), entryId)
        return try {
            AutofillDatasetFactory.populated(
                context = context,
                ids = ids,
                label = detail.title.reveal(),
                username = if (ids.username == null) null else detail.username.reveal(),
                password = if (ids.password == null) null else detail.password.reveal(),
                totp = if (ids.totp == null) null else detail.totp?.reveal(),
            )
        } finally {
            detail.closeSecrets()
        }
    }

    private fun activeVaultId(): String =
        session.sessionState().activeVaultId
            ?: error("no unlocked vault is active")
}
