package org.vaultkern.android.security

import android.content.ContextWrapper
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class BiometricGateTest {
    @Test
    fun activityLaunchFailureDoesNotRetainThePendingCipherRequest() {
        val base = ApplicationProvider.getApplicationContext<android.content.Context>()
        val context = object : ContextWrapper(base) {
            override fun startActivity(intent: Intent) {
                throw IllegalStateException("injected launch failure")
            }
        }
        val gate = ProcessBiometricGate(context)
        val executor = Executors.newSingleThreadExecutor()
        val requests = pendingRequests()
        val before = requests.size

        try {
            val result = runCatching {
                executor.submit<Cipher> {
                    gate.authenticate("test", encryptionCipher())
                }.get(5, TimeUnit.SECONDS)
            }

            assertTrue(result.isFailure)
            assertEquals(before, requests.size)
        } finally {
            requests.clear()
            executor.shutdownNow()
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun pendingRequests(): ConcurrentHashMap<String, *> {
        val broker = Class.forName(
            "org.vaultkern.android.security.BiometricRequestBroker",
        )
        val instance = broker.getDeclaredField("INSTANCE").run {
            isAccessible = true
            get(null)
        }
        return broker.getDeclaredField("requests").run {
            isAccessible = true
            get(instance) as ConcurrentHashMap<String, *>
        }
    }

    private fun encryptionCipher(): Cipher {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256, SecureRandom())
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, generator.generateKey())
        }
    }
}
