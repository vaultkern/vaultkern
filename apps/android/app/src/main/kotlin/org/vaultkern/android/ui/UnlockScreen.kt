package org.vaultkern.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.security.UnlockKeySecurityLevel
import org.vaultkern.android.sync.AndroidSyncStatus
import org.vaultkern.android.sync.OneDriveBrowserItem
import org.vaultkern.android.vault.VaultEntryDraft
import org.vaultkern.android.vault.VaultEntryListItem

data class UnlockUiState(
    val vaultPath: String = "",
    val selectedVaultName: String? = null,
    val password: String = "",
    val quickUnlockDesired: Boolean = false,
    val enrollmentState: UnlockEnrollmentState = UnlockEnrollmentState.NOT_ENROLLED,
    val keySecurityLevel: UnlockKeySecurityLevel? = null,
    val busy: Boolean = false,
    val status: String = "Select a vault and unlock it",
    val currentVaultSelected: Boolean = false,
    val vaultUnlocked: Boolean = false,
    val entries: List<VaultEntryListItem> = emptyList(),
    val editor: VaultEntryDraft? = null,
    val conflictCopyPath: String? = null,
    val oneDriveAuthPending: Boolean = false,
    val oneDriveConnected: Boolean = false,
    val oneDriveAccountLabel: String? = null,
    val oneDriveItems: List<OneDriveBrowserItem> = emptyList(),
    val oneDriveFolderId: String? = null,
    val oneDriveVaultSelected: Boolean = false,
    val oneDriveSelectedName: String? = null,
    val syncStatus: AndroidSyncStatus? = null,
) {
    override fun toString(): String =
        "UnlockUiState(" +
            "vaultPath=${if (vaultPath.isBlank()) "none" else "[APP-PRIVATE]"}, " +
            "selectedVaultName=${if (selectedVaultName == null) "none" else "[REDACTED]"}, " +
            "password=[REDACTED], " +
            "quickUnlockDesired=$quickUnlockDesired, " +
            "enrollmentState=$enrollmentState, " +
            "keySecurityLevel=$keySecurityLevel, " +
            "busy=$busy, " +
            "status=$status, " +
            "currentVaultSelected=$currentVaultSelected, " +
            "vaultUnlocked=$vaultUnlocked, " +
            "entryCount=${entries.size}, " +
            "editor=${if (editor == null) "closed" else "[REDACTED]"}, " +
            "conflictCopyPath=${if (conflictCopyPath == null) "none" else "[REDACTED]"}, " +
            "oneDriveAuthPending=$oneDriveAuthPending, " +
            "oneDriveConnected=$oneDriveConnected, " +
            "oneDriveAccountLabel=${if (oneDriveAccountLabel == null) "none" else "[REDACTED]"}, " +
            "oneDriveItemCount=${oneDriveItems.size}, " +
            "oneDriveFolderId=${if (oneDriveFolderId == null) "root" else "[REDACTED]"}, " +
            "oneDriveVaultSelected=$oneDriveVaultSelected, " +
            "oneDriveSelectedName=${if (oneDriveSelectedName == null) "none" else "[REDACTED]"}, " +
            "syncStatus=$syncStatus)"
}

@Composable
fun VaultKernUnlockScreen(
    state: UnlockUiState,
    onPasswordChanged: (String) -> Unit,
    onInteractiveUnlock: () -> Unit,
    onQuickUnlock: () -> Unit,
    onQuickUnlockDesiredChanged: (Boolean) -> Unit,
    onChooseLocalVault: () -> Unit = {},
    onBeginOneDriveLogin: () -> Unit = {},
    onCompleteOneDriveLogin: () -> Unit = {},
    onOneDriveItemSelected: (OneDriveBrowserItem) -> Unit = {},
    onOneDriveRoot: () -> Unit = {},
) {
    MaterialTheme {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("VaultKern", style = MaterialTheme.typography.headlineMedium)
            Text(state.status, modifier = Modifier.testTag("unlock-status"))
            Button(
                onClick = onChooseLocalVault,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth().testTag("choose-local-vault"),
            ) {
                Text("Choose local vault")
            }
            Text(
                state.selectedVaultName?.let { "Selected: $it" } ?: "No local vault selected",
                modifier = Modifier.testTag("selected-vault-name"),
            )
            OutlinedTextField(
                value = state.password,
                onValueChange = onPasswordChanged,
                enabled = !state.busy,
                label = { Text("Master password") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth().testTag("master-password"),
            )
            Button(
                onClick = onInteractiveUnlock,
                enabled = !state.busy &&
                    (state.vaultPath.isNotBlank() || state.currentVaultSelected),
                modifier = Modifier.fillMaxWidth().testTag("interactive-unlock"),
            ) {
                Text(if (state.oneDriveVaultSelected) "Unlock selected OneDrive vault" else "Open and unlock")
            }
            Button(
                onClick = onQuickUnlock,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth().testTag("biometric-unlock"),
            ) {
                Text("Unlock with biometrics")
            }
            Spacer(Modifier.height(4.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("Enable quick unlock")
                Switch(
                    checked = state.quickUnlockDesired,
                    onCheckedChange = onQuickUnlockDesiredChanged,
                    enabled = !state.busy,
                    modifier = Modifier.testTag("quick-unlock-toggle"),
                )
            }
            Text(
                enrollmentLabel(state.enrollmentState),
                modifier = Modifier.testTag("unlock-enrollment-state"),
            )
            Text(
                securityLabel(state.keySecurityLevel),
                modifier = Modifier.testTag("unlock-security-level"),
            )
            Spacer(Modifier.height(8.dp))
            Text("OneDrive", style = MaterialTheme.typography.titleMedium)
            state.oneDriveAccountLabel?.let { Text("Connected account: $it") }
            state.oneDriveSelectedName?.let {
                Text("Selected vault: $it", modifier = Modifier.testTag("onedrive-selected"))
            }
            if (state.oneDriveAuthPending) {
                Button(
                    onClick = onCompleteOneDriveLogin,
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth().testTag("onedrive-complete-login"),
                ) {
                    Text("Complete OneDrive sign-in")
                }
                Text("Finish sign-in in the browser, then return and tap Complete.")
            } else if (!state.oneDriveConnected) {
                OutlinedButton(
                    onClick = onBeginOneDriveLogin,
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth().testTag("onedrive-begin-login"),
                ) {
                    Text("Connect OneDrive")
                }
            } else {
                OutlinedButton(
                    onClick = onOneDriveRoot,
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth().testTag("onedrive-browse"),
                ) {
                    Text("Browse OneDrive")
                }
            }
            if (state.oneDriveFolderId != null) {
                OutlinedButton(
                    onClick = onOneDriveRoot,
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Back to OneDrive root") }
            }
            state.oneDriveItems.forEach { item ->
                OutlinedButton(
                    onClick = { onOneDriveItemSelected(item) },
                    enabled = !state.busy && (item.folder || item.name.endsWith(".kdbx", true)),
                    modifier = Modifier.fillMaxWidth().testTag("onedrive-item-${item.itemId}"),
                ) {
                    Text(if (item.folder) "Folder: ${item.name}" else item.name)
                }
            }
        }
    }
}

private fun enrollmentLabel(state: UnlockEnrollmentState): String = when (state) {
    UnlockEnrollmentState.ENROLLED -> "Quick unlock enrolled"
    UnlockEnrollmentState.NOT_ENROLLED -> "Quick unlock not enrolled"
    UnlockEnrollmentState.INVALIDATED -> "Quick unlock invalidated; re-enroll after unlock"
}

private fun securityLabel(level: UnlockKeySecurityLevel?): String = when (level) {
    UnlockKeySecurityLevel.STRONGBOX -> "Key security: StrongBox"
    UnlockKeySecurityLevel.TRUSTED_ENVIRONMENT -> "Key security: trusted environment"
    UnlockKeySecurityLevel.SOFTWARE -> "Key security: software (debug emulator only)"
    UnlockKeySecurityLevel.UNKNOWN -> "Key security: unknown"
    null -> "Key security: not recorded"
}
