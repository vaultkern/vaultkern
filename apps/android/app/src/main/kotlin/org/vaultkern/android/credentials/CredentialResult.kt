package org.vaultkern.android.credentials

import java.util.concurrent.CancellationException

internal inline fun <T> credentialResult(block: () -> T): Result<T> = try {
    Result.success(block())
} catch (cancelled: CancellationException) {
    throw cancelled
} catch (error: Exception) {
    Result.failure(error)
}
