package org.vaultkern.android.storage

import org.junit.Assert.assertTrue
import org.junit.Test

class LocalDocumentSnapshotHygieneTest {
    @Test
    fun metadataFailureClearsAlreadyReadDocumentBytes() {
        val bytes = ByteArray(48) { 61 }

        val result = runCatching {
            localDocumentSnapshot(bytes) {
                throw IllegalStateException("injected metadata failure")
            }
        }

        assertTrue(result.isFailure)
        assertTrue(bytes.all { it == 0.toByte() })
    }
}
