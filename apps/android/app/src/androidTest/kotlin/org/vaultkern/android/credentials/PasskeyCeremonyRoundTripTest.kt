package org.vaultkern.android.credentials

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.vaultkern.android.storage.LocalDocumentAccess
import org.vaultkern.android.storage.LocalDocumentSnapshot
import org.vaultkern.android.storage.LocalDocumentWorkspace
import org.vaultkern.android.vault.SelectedLocalDocumentSaveCoordinator
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

    @Test
    fun registrationPublishesThroughTheSelectedDocumentAuthority() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val root = File(
            instrumentation.targetContext.noBackupFilesDir,
            "m3-passkey-selected-document-${System.nanoTime()}",
        )
        val uri = "content://documents/local/passkeys.kdbx"
        val sourceBytes = instrumentation.context.assets
            .open("keepassxc-2.7.6-kdbx4.1.kdbx")
            .use { it.readBytes() }
        val documents = RoundTripLocalDocuments(uri, sourceBytes)
        val workspace = LocalDocumentWorkspace(root.resolve("documents"), documents)
        val selected = workspace.select(uri, "passkeys.kdbx")
        val privateVault = File(selected.privatePath)
        val beforeRegistration = documents.bytes()

        try {
            newSession(root.resolve("register")).use { session ->
                unlock(session, privateVault)
                PasskeyCeremony(
                    session = session,
                    verifier = FreshUserVerification { },
                    selectedLocalDocuments = SelectedLocalDocumentSaveCoordinator(workspace),
                ).register(
                    CREATION_JSON,
                    PasskeyClientContext(
                        origin = "android:apk-key-hash:instrumentation",
                        packageName = "org.vaultkern.android.test",
                        suppliedClientDataHash = null,
                    ),
                )
            }

            val published = documents.bytes()
            try {
                assertTrue(!beforeRegistration.contentEquals(published))
                assertArrayEquals(privateVault.readBytes(), published)
            } finally {
                published.fill(0)
            }
        } finally {
            beforeRegistration.fill(0)
            sourceBytes.fill(0)
            root.deleteRecursively()
        }
    }

    @Test
    fun invalidCandidateEndsTheAssertionOperation() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val root = File(
            instrumentation.targetContext.noBackupFilesDir,
            "m3-passkey-invalid-candidate-${System.nanoTime()}",
        )
        val vault = root.resolve("vault.kdbx")
        root.mkdirs()
        instrumentation.context.assets.open("keepassxc-2.7.6-kdbx4.1.kdbx").use { input ->
            vault.outputStream().use(input::copyTo)
        }
        val clientContext = PasskeyClientContext(
            origin = "android:apk-key-hash:instrumentation",
            packageName = "org.vaultkern.android.test",
            suppliedClientDataHash = null,
        )

        try {
            newSession(root.resolve("session")).use { session ->
                unlock(session, vault)
                val ceremony = PasskeyCeremony(
                    session = session,
                    verifier = FreshUserVerification { },
                )
                val registration = JSONObject(ceremony.register(CREATION_JSON, clientContext))
                val credentialId = Base64.getUrlDecoder().decode(registration.getString("rawId"))
                val active = ceremony.beginAssertion(ASSERTION_JSON, clientContext)

                assertThrows(IllegalArgumentException::class.java) {
                    active.complete(byteArrayOf(0x7f))
                }
                assertThrows(IllegalStateException::class.java) {
                    active.complete(credentialId)
                }
            }
        } finally {
            root.deleteRecursively()
        }
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

private class RoundTripLocalDocuments(
    private val uri: String,
    sourceBytes: ByteArray,
) : LocalDocumentAccess {
    private var stored = sourceBytes.copyOf()
    private var modifiedAt = 1L

    override fun read(uri: String): LocalDocumentSnapshot {
        require(uri == this.uri)
        return LocalDocumentSnapshot(stored.copyOf(), modifiedAt)
    }

    override fun replace(uri: String, bytes: ByteArray) {
        require(uri == this.uri)
        stored.fill(0)
        stored = bytes.copyOf()
        modifiedAt += 1
    }

    override fun createConflictCopy(
        sourceUri: String,
        displayName: String,
        bytes: ByteArray,
    ): String? = null

    fun bytes(): ByteArray = stored.copyOf()
}
