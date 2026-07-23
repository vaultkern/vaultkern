package org.vaultkern.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.vaultkern.android.handOffCredential
import org.vaultkern.android.security.UnlockEnrollmentState
import org.vaultkern.android.security.UnlockKeySecurityLevel

data class UnlockUiState(
    val selectedVaultName: String? = null,
    val currentVaultSelected: Boolean = false,
    val selectedKeyFileName: String? = null,
    val quickUnlockDesired: Boolean = false,
    val quickUnlockDraftDirty: Boolean = false,
    val enrollmentState: UnlockEnrollmentState = UnlockEnrollmentState.NOT_ENROLLED,
    val keySecurityLevel: UnlockKeySecurityLevel? = null,
    val busy: Boolean = false,
    val status: String = "Select a vault and unlock it",
) {
    override fun toString(): String =
        "UnlockUiState(" +
            "selectedVault=${if (selectedVaultName == null) "none" else "[REDACTED]"}, " +
            "currentVaultSelected=$currentVaultSelected, " +
            "selectedKeyFile=${if (selectedKeyFileName == null) "none" else "[REDACTED]"}, " +
            "quickUnlockDesired=$quickUnlockDesired, " +
            "quickUnlockDraftDirty=$quickUnlockDraftDirty, " +
            "enrollmentState=$enrollmentState, " +
            "keySecurityLevel=$keySecurityLevel, " +
            "busy=$busy, " +
            "status=$status)"
}

@Composable
fun VaultKernUnlockScreen(
    state: UnlockUiState,
    onInteractiveUnlock: (CharArray) -> Unit,
    onQuickUnlock: () -> Unit,
    onQuickUnlockDesiredChanged: (Boolean) -> Unit,
    onChooseLocalVault: () -> Unit = {},
    onChooseKeyFile: () -> Unit = {},
) {
    val credentialEditor = remember { ClearableCredentialEditor() }
    MaterialTheme {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("VaultKern", style = MaterialTheme.typography.headlineMedium)
            Text(state.status, modifier = Modifier.testTag("unlock-status"))
            Button(
                onClick = {
                    credentialEditor.clear()
                    onChooseLocalVault()
                },
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth().testTag("choose-local-vault"),
            ) {
                Text("Choose local vault")
            }
            Text(
                state.selectedVaultName?.let { "Selected: $it" } ?: "No local vault selected",
                modifier = Modifier.testTag("selected-vault-name"),
            )
            ClearableMasterPasswordField(
                editor = credentialEditor,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth().testTag("master-password"),
            )
            Button(
                onClick = onChooseKeyFile,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth().testTag("choose-key-file"),
            ) {
                Text("Choose key file (optional)")
            }
            Text(
                state.selectedKeyFileName?.let { "Key file selected: $it" }
                    ?: "No key file selected",
                modifier = Modifier.testTag("selected-key-file"),
            )
            Button(
                onClick = {
                    handOffCredential(credentialEditor.take(), onInteractiveUnlock)
                },
                enabled = !state.busy && state.currentVaultSelected,
                modifier = Modifier.fillMaxWidth().testTag("interactive-unlock"),
            ) {
                Text("Open and unlock")
            }
            Button(
                onClick = {
                    credentialEditor.clear()
                    onQuickUnlock()
                },
                enabled = !state.busy && state.currentVaultSelected,
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
            if (state.quickUnlockDraftDirty) {
                Text(
                    "Quick-unlock change is not saved",
                    modifier = Modifier.testTag("quick-unlock-unsaved"),
                )
            }
            Text(
                securityLabel(state.keySecurityLevel),
                modifier = Modifier.testTag("unlock-security-level"),
            )
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
