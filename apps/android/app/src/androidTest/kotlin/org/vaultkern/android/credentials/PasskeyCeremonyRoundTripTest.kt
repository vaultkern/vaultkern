package org.vaultkern.android.credentials

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.vaultkern.core.OneDriveTokenAdapter
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.ResidentPlatform
import org.vaultkern.core.UnlockBlobAdapter
import org.vaultkern.core.VaultKernSensitiveBytes
import org.vaultkern.core.VaultKernSensitiveString
import org.vaultkern.core.VaultSession
import org.vaultkern.core.VaultSessionConfig

@RunWith(AndroidJUnit4::class)
class PasskeyCeremonyRoundTripTest {
    @Test
    fun registrationPersistsKpexAndAssertionSignsAfterFreshUv() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val root = File(context.noBackupFilesDir, "m3-passkey-${System.nanoTime()}")
        val vault = File(root, "vault.kdbx")
        root.mkdirs()
        instrumentation.context.assets.open("keepassxc-2.7.6-kdbx4.1.kdbx").use { input ->
            vault.outputStream().use(input::copyTo)
        }
        val uvCount = AtomicInteger()
        val operationCounter = AtomicInteger()
        val clientContext = PasskeyClientContext(
            origin = "android:apk-key-hash:instrumentation",
            packageName = "org.vaultkern.android.test",
            suppliedClientDataHash = null,
        )

        val credentialId = newSession(root.resolve("register")).use { session ->
            unlock(session, vault)
            val ceremony = ceremony(session, uvCount, operationCounter)
            val response = JSONObject(ceremony.register(CREATION_JSON, clientContext))
            Base64.getUrlDecoder().decode(response.getString("rawId"))
        }

        newSession(root.resolve("assert")).use { session ->
            unlock(session, vault)
            val stored = session.listPasskeyCredentials().single {
                it.relyingParty == RELYING_PARTY
            }
            assertArrayEquals(credentialId, stored.credentialId)
            val request = JSONObject(ASSERTION_JSON).apply {
                put(
                    "allowCredentials",
                    org.json.JSONArray().put(
                        JSONObject()
                            .put("type", "public-key")
                            .put("id", Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId)),
                    ),
                )
            }
            val response = JSONObject(
                ceremony(session, uvCount, operationCounter).assert(
                    request.toString(),
                    clientContext,
                    credentialId,
                ),
            )
            assertArrayEquals(credentialId, Base64.getUrlDecoder().decode(response.getString("id")))
            val body = response.getJSONObject("response")
            assertTrue(Base64.getUrlDecoder().decode(body.getString("signature")).isNotEmpty())
            val authenticatorData = Base64.getUrlDecoder().decode(body.getString("authenticatorData"))
            assertTrue(authenticatorData[32].toInt() and 0x04 != 0)
        }

        assertEquals(2, uvCount.get())
        root.deleteRecursively()
    }

    private fun ceremony(
        session: VaultSession,
        uvCount: AtomicInteger,
        operationCounter: AtomicInteger,
    ): PasskeyCeremony = PasskeyCeremony(
        session = session,
        verifier = FreshUserVerification { uvCount.incrementAndGet() },
        operationId = {
            ByteArray(16).also { it[15] = operationCounter.incrementAndGet().toByte() }
        },
    )

    private fun newSession(root: File): VaultSession = VaultSession(
        VaultSessionConfig(
            ResidentPlatform.ANDROID,
            root.resolve("state").absolutePath,
            root.resolve("temporary").absolutePath,
        ),
        RoundTripUnlockBlobAdapter(),
        RoundTripOneDriveAdapter(),
    )

    private fun unlock(session: VaultSession, vault: File) {
        val handle = session.openVault(vault.absolutePath)
        VaultKernSensitiveString.fromString(FIXTURE_PASSWORD).use { password ->
            session.unlock().use { unlock ->
                unlock.unlockVault(handle.vaultId, password, null, false)
            }
        }
    }

    companion object {
        private const val FIXTURE_PASSWORD = "vaultkern-external-fixture"
        private const val RELYING_PARTY = "android-m3.example"
        private val CREATION_JSON = """
            {
              "challenge":"Y3JlYXRlLWNoYWxsZW5nZQ",
              "rp":{"id":"$RELYING_PARTY","name":"Android M3"},
              "user":{"id":"YW5kcm9pZC1tMy11c2Vy","name":"alice@example.com","displayName":"Alice"},
              "pubKeyCredParams":[{"type":"public-key","alg":-7}],
              "excludeCredentials":[]
            }
        """.trimIndent()
        private val ASSERTION_JSON = """
            {
              "challenge":"YXNzZXJ0LWNoYWxsZW5nZQ",
              "rpId":"$RELYING_PARTY",
              "userVerification":"required"
            }
        """.trimIndent()
    }
}

private class RoundTripUnlockBlobAdapter : UnlockBlobAdapter {
    override fun supportsUnlockBlob(): Boolean = true
    override fun authorize(reason: String) = Unit
    override fun storeRequiresUserPresence(): Boolean = false
    override fun loadRequiresUserPresence(): Boolean = false
    override fun authorizeStoreUserPresence() = Unit
    override fun storeBlob(key: String, value: VaultKernSensitiveBytes) = value.close()
    override fun loadBlob(key: String): VaultKernSensitiveBytes? = null
    override fun containsBlob(key: String): Boolean = false
    override fun deleteBlob(key: String) = Unit
}

private class RoundTripOneDriveAdapter : OneDriveTokenAdapter {
    override fun loadRefreshToken(): VaultKernSensitiveString? = null
    override fun storeRefreshToken(token: VaultKernSensitiveString) {
        token.close()
        throw PlatformAdapterException.Failure("OneDrive is not configured")
    }
    override fun deleteRefreshToken() = Unit
}
