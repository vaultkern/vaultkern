package org.vaultkern.android

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import org.vaultkern.android.ui.UnlockUiState

internal class UnlockActionGate(
    private val state: MutableStateFlow<UnlockUiState>,
) {
    fun tryBegin(
        status: String,
        requireCurrentVault: Boolean = false,
        update: (UnlockUiState) -> UnlockUiState = { it },
    ): Boolean {
        while (true) {
            val current = state.value
            if (current.busy ||
                requireCurrentVault && !current.currentVaultSelected
            ) {
                return false
            }
            val next = update(current).copy(busy = true, status = status)
            if (state.compareAndSet(current, next)) return true
        }
    }
}

internal fun CoroutineScope.launchOwnedCredential(
    credential: CharArray,
    context: CoroutineContext,
    operation: suspend (CharArray) -> Unit,
): Job {
    val job = try {
        launch(context) {
            operation(credential)
        }
    } catch (error: Throwable) {
        credential.fill('\u0000')
        throw error
    }
    job.invokeOnCompletion {
        credential.fill('\u0000')
    }
    return job
}

internal inline fun handOffCredential(
    credential: CharArray,
    accept: (CharArray) -> Unit,
) {
    try {
        accept(credential)
    } catch (error: Throwable) {
        credential.fill('\u0000')
        throw error
    }
}
