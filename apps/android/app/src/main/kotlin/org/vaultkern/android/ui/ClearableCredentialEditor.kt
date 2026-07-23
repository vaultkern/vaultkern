package org.vaultkern.android.ui

import android.text.Editable
import android.text.InputType
import android.view.View
import android.widget.EditText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView

internal fun takeAndClearCredential(editor: Editable): CharArray {
    val credential = CharArray(editor.length)
    try {
        editor.getChars(0, editor.length, credential, 0)
        eraseEditor(editor)
        return credential
    } catch (error: Throwable) {
        credential.fill('\u0000')
        runCatching { eraseEditor(editor) }
        throw error
    }
}

private fun eraseEditor(editor: Editable) {
    repeat(editor.length) { index ->
        editor.replace(index, index + 1, ZERO_CHARACTER)
    }
    editor.clearSpans()
    editor.clear()
}

internal class ClearableCredentialEditor {
    private var field: EditText? = null

    fun bind(field: EditText) {
        if (this.field !== field) clear()
        this.field = field
    }

    fun take(): CharArray = field?.editableText?.let(::takeAndClearCredential) ?: CharArray(0)

    fun clear() {
        field?.editableText?.let(::eraseEditor)
    }

    fun unbind() {
        clear()
        field = null
    }
}

@Composable
internal fun ClearableMasterPasswordField(
    editor: ClearableCredentialEditor,
    enabled: Boolean,
    modifier: Modifier = Modifier,
) {
    AndroidView(
        modifier = modifier,
        factory = { context ->
            EditText(context).apply {
                hint = "Master password"
                inputType = InputType.TYPE_CLASS_TEXT or
                    InputType.TYPE_TEXT_VARIATION_PASSWORD or
                    InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                isSingleLine = true
                isSaveEnabled = false
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                editor.bind(this)
            }
        },
        update = { field ->
            editor.bind(field)
            field.isEnabled = enabled
        },
    )
    DisposableEffect(editor) {
        onDispose(editor::unbind)
    }
}

private const val ZERO_CHARACTER = "\u0000"
