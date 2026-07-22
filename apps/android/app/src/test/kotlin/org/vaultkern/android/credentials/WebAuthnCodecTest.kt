package org.vaultkern.android.credentials

import java.security.MessageDigest
import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import org.vaultkern.core.PlatformPasskeyAssertionOutput
import org.vaultkern.core.PlatformPasskeyCredential
import org.vaultkern.core.PlatformPasskeyRegistrationOutput

class WebAuthnCodecTest {
    private val codec = WebAuthnCodec()
    private val nativeContext = PasskeyClientContext(
        origin = "android:apk-key-hash:caller",
        packageName = "com.example.caller",
        suppliedClientDataHash = null,
    )

    @Test
    fun registrationUsesCoreAuthenticatorDataAndNativeClientData() {
        val parsed = codec.parseCreationOptions(CREATION_JSON)
        assertEquals("example.com", parsed.relyingParty)
        assertEquals("Example", parsed.relyingPartyName)
        assertEquals("alice@example.com", parsed.userName)
        assertArrayEquals("alice-user".toByteArray(), parsed.userHandle)
        assertEquals(-7, parsed.publicKeyAlgorithm)

        val credentialId = byteArrayOf(1, 2, 3, 4)
        val authData = authenticatorData(attested = true, credentialId = credentialId)
        val response = JSONObject(
            codec.registrationResponse(
                parsed,
                nativeContext,
                PlatformPasskeyRegistrationOutput(
                    entryId = "entry-id",
                    credential = PlatformPasskeyCredential(
                        credentialId = credentialId,
                        relyingParty = "example.com",
                        relyingPartyName = "Example",
                        userHandle = "alice-user".toByteArray(),
                        userName = "alice@example.com",
                        userDisplayName = "Alice",
                    ),
                    authenticatorData = authData,
                ),
            ),
        )

        assertEquals(base64Url(credentialId), response.getString("id"))
        val clientData = JSONObject(
            String(decode(response.getJSONObject("response").getString("clientDataJSON"))),
        )
        assertEquals("webauthn.create", clientData.getString("type"))
        assertEquals("android:apk-key-hash:caller", clientData.getString("origin"))
        assertEquals("com.example.caller", clientData.getString("androidPackageName"))
        assertEquals("Y3JlYXRlLWNoYWxsZW5nZQ", clientData.getString("challenge"))
        assertTrue(
            response.getJSONObject("clientExtensionResults")
                .getJSONObject("credProps")
                .getBoolean("rk"),
        )

        val attestation = decode(
            response.getJSONObject("response").getString("attestationObject"),
        )
        assertTrue(attestation.size > authData.size)
        assertArrayEquals(authData, attestation.copyOfRange(attestation.size - authData.size, attestation.size))
    }

    @Test
    fun assertionHashesExactClientDataAndReturnsCoreSignature() {
        val parsed = codec.parseRequestOptions(ASSERTION_JSON)
        val prepared = codec.prepareAssertion(parsed, nativeContext, null)
        val expectedHash = MessageDigest.getInstance("SHA-256").digest(prepared.clientDataJson!!)

        assertEquals("example.com", prepared.input.relyingParty)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), prepared.input.allowedCredentialIds.single())
        assertArrayEquals(expectedHash, prepared.input.clientDataHash)
        assertTrue(prepared.input.userVerified)

        val assertionAuthData = authenticatorData(attested = false)
        val response = JSONObject(
            codec.assertionResponse(
                prepared,
                PlatformPasskeyAssertionOutput(
                    credentialId = byteArrayOf(1, 2, 3, 4),
                    authenticatorData = assertionAuthData,
                    signatureDer = byteArrayOf(7, 8, 9),
                    userHandle = "alice-user".toByteArray(),
                ),
            ),
        )
        val body = response.getJSONObject("response")
        assertEquals(base64Url(assertionAuthData), body.getString("authenticatorData"))
        assertEquals("BwgJ", body.getString("signature"))
        assertEquals(base64Url("alice-user".toByteArray()), body.getString("userHandle"))
        assertFalse(body.getString("clientDataJSON").contains("="))
    }

    @Test
    fun privilegedClientUsesSuppliedHashAndPlaceholderClientData() {
        val supplied = ByteArray(32) { 9 }
        val context = PasskeyClientContext(
            origin = "https://example.com",
            packageName = null,
            suppliedClientDataHash = supplied,
        )
        val prepared = codec.prepareAssertion(codec.parseRequestOptions(ASSERTION_JSON), context, null)

        assertArrayEquals(supplied, prepared.input.clientDataHash)
        assertEquals(null, prepared.clientDataJson)
        val response = JSONObject(
            codec.assertionResponse(
                prepared,
                PlatformPasskeyAssertionOutput(
                    byteArrayOf(1, 2, 3, 4),
                    authenticatorData(attested = false),
                    byteArrayOf(3),
                    byteArrayOf(4),
                ),
            ),
        )
        assertEquals("e30", response.getJSONObject("response").getString("clientDataJSON"))
    }

    @Test
    fun malformedOrUnsupportedRequestsFailBeforeCoreMutation() {
        val unsupported = JSONObject(CREATION_JSON).apply {
            put("pubKeyCredParams", org.json.JSONArray().put(JSONObject().put("type", "public-key").put("alg", -257)))
        }
        assertThrows(IllegalArgumentException::class.java) {
            codec.parseCreationOptions(unsupported.toString())
        }
        assertThrows(IllegalArgumentException::class.java) {
            codec.parseCreationOptions(JSONObject(CREATION_JSON).put("challenge", "***").toString())
        }
        assertThrows(IllegalArgumentException::class.java) {
            codec.prepareAssertion(
                codec.parseRequestOptions(ASSERTION_JSON),
                nativeContext.copy(suppliedClientDataHash = byteArrayOf(1)),
                null,
            )
        }
    }

    @Test
    fun credentialOptionBindingSeparatesChallengesAndPrivilegedHashes() {
        val first = CredentialOptionBinding.key(ASSERTION_JSON, null)
        val otherChallenge = CredentialOptionBinding.key(
            JSONObject(ASSERTION_JSON).put("challenge", "b3RoZXItY2hhbGxlbmdl").toString(),
            null,
        )
        val privileged = CredentialOptionBinding.key(ASSERTION_JSON, ByteArray(32) { 7 })

        assertEquals(first, CredentialOptionBinding.key(ASSERTION_JSON, null))
        assertFalse(first == otherChallenge)
        assertFalse(first == privileged)
    }

    private fun base64Url(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)

    private fun authenticatorData(
        attested: Boolean,
        credentialId: ByteArray = byteArrayOf(1, 2, 3, 4),
    ): ByteArray {
        val rpHash = MessageDigest.getInstance("SHA-256").digest("example.com".toByteArray())
        val flags = if (attested) 0x45 else 0x05
        val header = rpHash + byteArrayOf(flags.toByte(), 0, 0, 0, 0)
        return if (attested) {
            header + ByteArray(16) +
                byteArrayOf((credentialId.size ushr 8).toByte(), credentialId.size.toByte()) +
                credentialId + byteArrayOf(0xa1.toByte(), 0x01, 0x02)
        } else {
            header
        }
    }

    companion object {
        private val CREATION_JSON = """
            {
              "challenge":"Y3JlYXRlLWNoYWxsZW5nZQ",
              "rp":{"id":"example.com","name":"Example"},
              "user":{"id":"YWxpY2UtdXNlcg","name":"alice@example.com","displayName":"Alice"},
              "pubKeyCredParams":[{"type":"public-key","alg":-7}],
              "excludeCredentials":[],
              "extensions":{"credProps":true}
            }
        """.trimIndent()

        private val ASSERTION_JSON = """
            {
              "challenge":"YXNzZXJ0LWNoYWxsZW5nZQ",
              "rpId":"example.com",
              "allowCredentials":[{"type":"public-key","id":"AQIDBA"}],
              "userVerification":"required"
            }
        """.trimIndent()
    }
}
