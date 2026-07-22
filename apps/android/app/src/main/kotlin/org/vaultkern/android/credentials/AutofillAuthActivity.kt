package org.vaultkern.android.credentials

import android.app.Activity
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillId
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
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.vaultkern.android.VaultKernApplication

class AutofillAuthActivity : FragmentActivity() {
    private val completed = AtomicBoolean(false)
    private lateinit var ids: AutofillFieldIds
    private lateinit var verificationLease: FreshUserVerificationLease

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        ids = AutofillFieldIds(
            username = intent.getParcelableExtra(EXTRA_USERNAME_ID, AutofillId::class.java),
            password = intent.getParcelableExtra(EXTRA_PASSWORD_ID, AutofillId::class.java),
            totp = intent.getParcelableExtra(EXTRA_TOTP_ID, AutofillId::class.java),
        )
        if (ids.isEmpty) {
            cancel()
            return
        }
        val graph = (application as VaultKernApplication).graph
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching {
                verificationLease = graph.credentialRelease.ensureUnlockedWithFreshUserVerification(
                    "Verify autofill",
                )
                graph.autofillVault.candidates(requireTotp = ids.totp != null)
            }.fold(
                onSuccess = { candidates ->
                    withContext(Dispatchers.Main) {
                        when (candidates.size) {
                            0 -> cancel()
                            1 -> select(candidates.single().entryId)
                            else -> showCandidates(candidates)
                        }
                    }
                },
                onFailure = { withContext(Dispatchers.Main) { cancel() } },
            )
        }
    }

    private fun showCandidates(candidates: List<AutofillCandidate>) {
        if (completed.get()) return
        setContent {
            AutofillCandidatePicker(candidates, ::select)
        }
    }

    private fun select(entryId: String) {
        if (!completed.compareAndSet(false, true)) return
        val graph = (application as VaultKernApplication).graph
        lifecycleScope.launch(Dispatchers.IO) {
            val result = runCatching {
                verificationLease.refreshIfStale("Verify autofill")
                val credential = graph.autofillVault.credential(entryId)
                AutofillDatasetFactory.populated(this@AutofillAuthActivity, ids, credential).dataset
            }
            withContext(Dispatchers.Main) {
                result.fold(
                    onSuccess = { dataset ->
                        setResult(
                            Activity.RESULT_OK,
                            AutofillDatasetFactory.authenticationResult(dataset),
                        )
                        finish()
                    },
                    onFailure = {
                        setResult(Activity.RESULT_CANCELED)
                        finish()
                    },
                )
            }
        }
    }

    private fun cancel() {
        if (!completed.compareAndSet(false, true)) return
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    companion object {
        const val EXTRA_USERNAME_ID = "org.vaultkern.android.autofill.USERNAME_ID"
        const val EXTRA_PASSWORD_ID = "org.vaultkern.android.autofill.PASSWORD_ID"
        const val EXTRA_TOTP_ID = "org.vaultkern.android.autofill.TOTP_ID"
    }
}

@Composable
private fun AutofillCandidatePicker(
    candidates: List<AutofillCandidate>,
    onSelected: (String) -> Unit,
) {
    MaterialTheme {
        Column(
            modifier = Modifier.fillMaxSize().padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Choose an entry", style = MaterialTheme.typography.headlineSmall)
            candidates.forEach { candidate ->
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelected(candidate.entryId) }
                        .padding(vertical = 12.dp),
                ) {
                    Text(candidate.label, style = MaterialTheme.typography.titleMedium)
                    Text(candidate.username)
                    if (candidate.hasTotp) Text("TOTP")
                }
            }
        }
    }
}
