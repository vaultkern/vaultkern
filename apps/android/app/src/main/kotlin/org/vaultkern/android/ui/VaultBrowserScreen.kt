package org.vaultkern.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.vaultkern.android.vault.VaultEntryDraft
import org.vaultkern.android.vault.VaultEntryListItem

@Composable
fun VaultBrowserScreen(
    entries: List<VaultEntryListItem>,
    editor: VaultEntryDraft?,
    busy: Boolean,
    status: String,
    conflictCopyPath: String?,
    onEntrySelected: (String) -> Unit,
    onDraftChanged: (VaultEntryDraft) -> Unit,
    onSave: () -> Unit,
    onCloseEditor: () -> Unit,
    onLock: () -> Unit,
) {
    MaterialTheme {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("VaultKern", style = MaterialTheme.typography.headlineMedium)
                OutlinedButton(onClick = onLock, enabled = !busy) { Text("Lock") }
            }
            Text(status, modifier = Modifier.testTag("vault-status"))
            conflictCopyPath?.let { path ->
                Column(modifier = Modifier.testTag("conflict-copy")) {
                    Text("Foreign change detected. Your edit is in this conflict copy:")
                    Text(path, modifier = Modifier.testTag("conflict-copy-path"))
                }
            }
            if (editor == null) {
                EntryList(entries, busy, onEntrySelected)
            } else {
                EntryEditor(editor, busy, onDraftChanged, onSave, onCloseEditor)
            }
        }
    }
}

@Composable
private fun EntryList(
    entries: List<VaultEntryListItem>,
    busy: Boolean,
    onEntrySelected: (String) -> Unit,
) {
    if (entries.isEmpty()) {
        Text("No entries")
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("entry-list"),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(entries, key = VaultEntryListItem::id) { entry ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(enabled = !busy) { onEntrySelected(entry.id) }
                    .padding(vertical = 10.dp)
                    .testTag("entry-${entry.id}"),
            ) {
                Text(entry.title, style = MaterialTheme.typography.titleMedium)
                Text(entry.username)
                if (entry.hasTotp) Text("TOTP")
            }
        }
    }
}

@Composable
private fun EntryEditor(
    draft: VaultEntryDraft,
    busy: Boolean,
    onDraftChanged: (VaultEntryDraft) -> Unit,
    onSave: () -> Unit,
    onClose: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("entry-editor"),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            OutlinedTextField(
                value = draft.title,
                onValueChange = { onDraftChanged(draft.copy(title = it)) },
                enabled = !busy,
                label = { Text("Title") },
                modifier = Modifier.fillMaxWidth().testTag("edit-title"),
            )
        }
        item {
            OutlinedTextField(
                value = draft.username,
                onValueChange = { onDraftChanged(draft.copy(username = it)) },
                enabled = !busy,
                label = { Text("Username") },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item {
            OutlinedTextField(
                value = draft.password,
                onValueChange = { onDraftChanged(draft.copy(password = it)) },
                enabled = !busy,
                label = { Text("Password") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth().testTag("edit-password"),
            )
        }
        item {
            OutlinedTextField(
                value = draft.url,
                onValueChange = { onDraftChanged(draft.copy(url = it)) },
                enabled = !busy,
                label = { Text("URL") },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item {
            OutlinedTextField(
                value = draft.notes,
                onValueChange = { onDraftChanged(draft.copy(notes = it)) },
                enabled = !busy,
                label = { Text("Notes") },
                minLines = 3,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item {
            OutlinedTextField(
                value = draft.totpUri.orEmpty(),
                onValueChange = { value ->
                    onDraftChanged(draft.copy(totpUri = value.ifBlank { null }))
                },
                enabled = !busy,
                label = { Text("TOTP URI") },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = onSave,
                    enabled = !busy,
                    modifier = Modifier.weight(1f).testTag("save-entry"),
                ) {
                    Text("Save")
                }
                OutlinedButton(
                    onClick = onClose,
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Cancel")
                }
            }
        }
    }
}
