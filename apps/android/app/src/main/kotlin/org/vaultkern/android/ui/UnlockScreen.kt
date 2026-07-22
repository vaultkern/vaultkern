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
import org.vaultkern.android.vault.VaultEntryDraft
import org.vaultkern.android.vault.VaultEntryListItem

data class UnlockUiState(
    val vaultPath: String = "",
    val password: String = "",
    val quickUnlockDesired: Boolean = false,
    val enrollmentState: UnlockEnrollmentState = UnlockEnrollmentState.NOT_ENROLLED,
    val keySecurityLevel: UnlockKeySecurityLevel? = null,
    val busy: Boolean = false,
    val status: String = "Select a vault and unlock it",
    val vaultUnlocked: Boolean = false,
    val entries: List<VaultEntryListItem> = emptyList(),
    val editor: VaultEntryDraft? = null,
    val conflictCopyPath: String? = null,
) {
    override fun toString(): String =
        "UnlockUiState(" +
            "vaultPath=$vaultPath, " +
            "password=[REDACTED], " +
            "quickUnlockDesired=$quickUnlockDesired, " +
            "enrollmentState=$enrollmentState, " +
            "keySecurityLevel=$keySecurityLevel, " +
            "busy=$busy, " +
            "status=$status, " +
            "vaultUnlocked=$vaultUnlocked, " +
            "entryCount=${entries.size}, " +
            "editor=${if (editor == null) "closed" else "[REDACTED]"}, " +
            "conflictCopyPath=$conflictCopyPath)"
}

@Composable
fun VaultKernUnlockScreen(
    state: UnlockUiState,
    onPathChanged: (String) -> Unit,
    onPasswordChanged: (String) -> Unit,
    onInteractiveUnlock: () -> Unit,
    onQuickUnlock: () -> Unit,
    onQuickUnlockDesiredChanged: (Boolean) -> Unit,
) {
    MaterialTheme {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("VaultKern", style = MaterialTheme.typography.headlineMedium)
            Text(state.status, modifier = Modifier.testTag("unlock-status"))
            OutlinedTextField(
                value = state.vaultPath,
                onValueChange = onPathChanged,
                enabled = !state.busy,
                label = { Text("Vault path") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("vault-path"),
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
                enabled = !state.busy && state.vaultPath.isNotBlank(),
                modifier = Modifier.fillMaxWidth().testTag("interactive-unlock"),
            ) {
                Text("Open and unlock")
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
