package org.vaultkern.android.storage

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.vaultkern.core.VaultKernSensitiveBytes

@RunWith(AndroidJUnit4::class)
class SelectedKeyFileTest {
    @Test
    fun cloudStyleKeyFilePipeIsHandedOffAsClearableContentWithoutAPath() {
        var handedOff: VaultKernSensitiveBytes? = null
        val selected = ParcelFileDescriptorKeyFile("selected.key") {
            val (read, write) = ParcelFileDescriptor.createPipe()
            Thread {
                ParcelFileDescriptor.AutoCloseOutputStream(write).use { output ->
                    output.write(byteArrayOf(1, 3, 3, 7))
                }
            }.start()
            read
        }

        val observed = selected.withSensitiveBytes { content ->
            handedOff = content
            content.copyBytes()
        }

        try {
            assertArrayEquals(byteArrayOf(1, 3, 3, 7), observed)
            assertTrue(requireNotNull(handedOff).copyBytes().isEmpty())
            assertTrue(selected.toString().contains("[REDACTED]"))
        } finally {
            observed.fill(0)
            handedOff?.close()
        }
    }
}
