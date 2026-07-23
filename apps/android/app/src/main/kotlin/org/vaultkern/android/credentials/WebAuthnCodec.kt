package org.vaultkern.android.credentials

import java.net.IDN
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.vaultkern.core.PlatformPasskeyAssertionInput
import org.vaultkern.core.PlatformPasskeyAssertionOutput
import org.vaultkern.core.PlatformPasskeyRegistrationInput
import org.vaultkern.core.PlatformPasskeyRegistrationOutput

data class PasskeyClientContext(
    val origin: String,
    val packageName: String?,
    val suppliedClientDataHash: ByteArray?,
) {
    override fun toString(): String =
        "PasskeyClientContext(origin=[REDACTED], packageName=[REDACTED], " +
            "suppliedClientDataHash=${if (suppliedClientDataHash == null) "absent" else "[REDACTED]"})"
}

data class ParsedCreationOptions(
    val challenge: ByteArray,
    val relyingParty: String,
    val relyingPartyName: String,
    val userName: String,
    val userDisplayName: String,
    val userHandle: ByteArray,
    val publicKeyAlgorithm: Int,
    val excludedCredentialIds: List<ByteArray>,
    val credentialPropertiesRequested: Boolean,
) {
    fun registrationInput(): PlatformPasskeyRegistrationInput =
        PlatformPasskeyRegistrationInput(
            relyingParty = relyingParty,
            relyingPartyName = relyingPartyName,
            userName = userName,
            userDisplayName = userDisplayName,
            userHandle = userHandle.copyOf(),
            publicKeyAlgorithm = publicKeyAlgorithm,
            userVerified = true,
        )

    override fun toString(): String =
        "ParsedCreationOptions(relyingParty=$relyingParty, relyingPartyName=[REDACTED], " +
            "userName=[REDACTED], userDisplayName=[REDACTED], userHandle=[REDACTED], " +
            "challenge=[REDACTED], publicKeyAlgorithm=$publicKeyAlgorithm, " +
            "excludedCredentialCount=${excludedCredentialIds.size}, " +
            "credentialPropertiesRequested=$credentialPropertiesRequested)"
}

data class ParsedRequestOptions(
    val challenge: ByteArray,
    val relyingParty: String,
    val allowedCredentialIds: List<ByteArray>,
) {
    override fun toString(): String =
        "ParsedRequestOptions(relyingParty=$relyingParty, challenge=[REDACTED], " +
            "allowedCredentialCount=${allowedCredentialIds.size})"
}

data class PreparedAssertion(
    val input: PlatformPasskeyAssertionInput,
    val clientDataJson: ByteArray?,
) {
    override fun toString(): String =
        "PreparedAssertion(relyingParty=${input.relyingParty}, clientData=[REDACTED], " +
            "allowedCredentialCount=${input.allowedCredentialIds.size})"
}

class WebAuthnCodec {
    fun parseCreationOptions(requestJson: String): ParsedCreationOptions {
        val root = parseObject(requestJson)
        val rp = root.requiredObject("rp")
        val user = root.requiredObject("user")
        val parameters = root.requiredArray("pubKeyCredParams")
        val algorithm = (0 until parameters.length())
            .map { parameters.getJSONObject(it) }
            .firstOrNull { it.requiredString("type") == PUBLIC_KEY_TYPE && it.getInt("alg") == ES256 }
            ?.getInt("alg")
            ?: throw IllegalArgumentException("request does not support ES256")
        val excluded = root.optJSONArray("excludeCredentials")
            ?.credentialIds()
            .orEmpty()
        val authenticatorAttachment = root.optJSONObject("authenticatorSelection")
            ?.optString("authenticatorAttachment", "")
            .orEmpty()
        require(authenticatorAttachment != "cross-platform") {
            "a platform provider cannot satisfy a cross-platform authenticator request"
        }
        val userHandle = decodeBase64Url(user.requiredString("id"), "user.id")
        require(userHandle.size in 1..MAX_USER_HANDLE_BYTES) {
            "user.id must contain 1..$MAX_USER_HANDLE_BYTES bytes"
        }
        return ParsedCreationOptions(
            challenge = decodeBase64Url(root.requiredString("challenge"), "challenge"),
            relyingParty = validateRpId(rp.requiredString("id")),
            relyingPartyName = rp.requiredString("name"),
            userName = user.requiredString("name"),
            userDisplayName = user.requiredString("displayName"),
            userHandle = userHandle,
            publicKeyAlgorithm = algorithm,
            excludedCredentialIds = excluded,
            credentialPropertiesRequested = root.optJSONObject("extensions")
                ?.optBoolean("credProps", false)
                ?: false,
        )
    }

    fun parseRequestOptions(requestJson: String): ParsedRequestOptions {
        val root = parseObject(requestJson)
        return ParsedRequestOptions(
            challenge = decodeBase64Url(root.requiredString("challenge"), "challenge"),
            relyingParty = validateRpId(root.requiredString("rpId")),
            allowedCredentialIds = root.optJSONArray("allowCredentials")
                ?.credentialIds()
                .orEmpty(),
        )
    }

    fun prepareAssertion(
        options: ParsedRequestOptions,
        context: PasskeyClientContext,
        selectedCredentialId: ByteArray?,
    ): PreparedAssertion {
        val allowed = when {
            selectedCredentialId == null -> options.allowedCredentialIds.map(ByteArray::copyOf)
            options.allowedCredentialIds.isEmpty() -> listOf(selectedCredentialId.copyOf())
            options.allowedCredentialIds.any { it.contentEquals(selectedCredentialId) } ->
                listOf(selectedCredentialId.copyOf())
            else -> throw IllegalArgumentException("selected credential is not allowed")
        }
        val clientData = clientData(
            type = "webauthn.get",
            challenge = options.challenge,
            context = context,
        )
        return PreparedAssertion(
            input = PlatformPasskeyAssertionInput(
                relyingParty = options.relyingParty,
                allowedCredentialIds = allowed,
                clientDataHash = clientData.hash,
                userVerified = true,
            ),
            clientDataJson = clientData.json,
        )
    }

    fun registrationResponse(
        options: ParsedCreationOptions,
        context: PasskeyClientContext,
        output: PlatformPasskeyRegistrationOutput,
    ): String {
        require(output.credential.relyingParty == options.relyingParty) {
            "core registration relying party mismatch"
        }
        require(output.credential.userHandle.contentEquals(options.userHandle)) {
            "core registration user handle mismatch"
        }
        validateAuthenticatorData(
            output.authenticatorData,
            options.relyingParty,
            requireAttestedCredentialData = true,
            expectedCredentialId = output.credential.credentialId,
        )
        require(output.credential.credentialId.isNotEmpty()) { "core returned an empty credential id" }
        val clientData = clientData(
            type = "webauthn.create",
            challenge = options.challenge,
            context = context,
        )
        val response = JSONObject()
            .put("clientDataJSON", responseClientData(clientData.json))
            .put("attestationObject", encodeBase64Url(noneAttestation(output.authenticatorData)))
            .put("transports", JSONArray().put("internal"))
        val extensions = JSONObject()
        if (options.credentialPropertiesRequested) {
            extensions.put("credProps", JSONObject().put("rk", true))
        }
        return credentialResponse(output.credential.credentialId, response, extensions).toString()
    }

    fun assertionResponse(
        prepared: PreparedAssertion,
        output: PlatformPasskeyAssertionOutput,
    ): String {
        require(output.credentialId.isNotEmpty()) { "core returned an empty credential id" }
        if (prepared.input.allowedCredentialIds.isNotEmpty()) {
            require(prepared.input.allowedCredentialIds.any { it.contentEquals(output.credentialId) }) {
                "core assertion credential was not allowed"
            }
        }
        validateAuthenticatorData(
            output.authenticatorData,
            prepared.input.relyingParty,
            requireAttestedCredentialData = false,
            expectedCredentialId = null,
        )
        require(output.signatureDer.isNotEmpty()) { "core returned an empty assertion signature" }
        val response = JSONObject()
            .put("clientDataJSON", responseClientData(prepared.clientDataJson))
            .put("authenticatorData", encodeBase64Url(output.authenticatorData))
            .put("signature", encodeBase64Url(output.signatureDer))
            .put("userHandle", encodeBase64Url(output.userHandle))
        return credentialResponse(output.credentialId, response, JSONObject()).toString()
    }

    private fun clientData(
        type: String,
        challenge: ByteArray,
        context: PasskeyClientContext,
    ): ClientData {
        context.suppliedClientDataHash?.let { supplied ->
            require(supplied.size == SHA256_BYTES) { "supplied clientDataHash must be 32 bytes" }
            require(context.packageName == null) {
                "native Android callers must not supply clientDataHash"
            }
            return ClientData(json = null, hash = supplied.copyOf())
        }
        require(context.origin.isNotBlank()) { "passkey origin is empty" }
        val jsonObject = JSONObject()
            .put("type", type)
            .put("challenge", encodeBase64Url(challenge))
            .put("origin", context.origin)
        context.packageName?.let { jsonObject.put("androidPackageName", it) }
        val json = jsonObject.toString().toByteArray(StandardCharsets.UTF_8)
        return ClientData(json = json, hash = sha256(json))
    }

    private fun credentialResponse(
        credentialId: ByteArray,
        response: JSONObject,
        clientExtensionResults: JSONObject,
    ): JSONObject {
        val encodedId = encodeBase64Url(credentialId)
        return JSONObject()
            .put("id", encodedId)
            .put("rawId", encodedId)
            .put("type", PUBLIC_KEY_TYPE)
            .put("authenticatorAttachment", "platform")
            .put("response", response)
            .put("clientExtensionResults", clientExtensionResults)
    }

    private fun responseClientData(clientDataJson: ByteArray?): String =
        encodeBase64Url(clientDataJson ?: EMPTY_CLIENT_DATA_JSON)

    private fun validateAuthenticatorData(
        authenticatorData: ByteArray,
        relyingParty: String,
        requireAttestedCredentialData: Boolean,
        expectedCredentialId: ByteArray?,
    ) {
        require(authenticatorData.size >= AUTHENTICATOR_DATA_HEADER_BYTES) {
            "core returned truncated authenticator data"
        }
        require(
            authenticatorData.copyOfRange(0, SHA256_BYTES)
                .contentEquals(sha256(relyingParty.toByteArray(StandardCharsets.UTF_8))),
        ) { "core authenticator data relying party hash mismatch" }
        val flags = authenticatorData[SHA256_BYTES].toInt() and 0xff
        require(flags and USER_PRESENT_FLAG != 0) { "core authenticator data omitted UP" }
        require(flags and USER_VERIFIED_FLAG != 0) { "core authenticator data omitted UV" }
        if (requireAttestedCredentialData) {
            require(flags and ATTESTED_CREDENTIAL_DATA_FLAG != 0) {
                "core registration authenticator data omitted attested credential data"
            }
            require(authenticatorData.size >= ATTESTED_CREDENTIAL_ID_OFFSET) {
                "core returned truncated attested credential data"
            }
            val credentialIdLength =
                ((authenticatorData[53].toInt() and 0xff) shl 8) or
                    (authenticatorData[54].toInt() and 0xff)
            require(authenticatorData.size >= ATTESTED_CREDENTIAL_ID_OFFSET + credentialIdLength) {
                "core returned truncated attested credential id"
            }
            require(
                expectedCredentialId != null &&
                    credentialIdLength == expectedCredentialId.size &&
                    authenticatorData.copyOfRange(
                        ATTESTED_CREDENTIAL_ID_OFFSET,
                        ATTESTED_CREDENTIAL_ID_OFFSET + credentialIdLength,
                    ).contentEquals(expectedCredentialId),
            ) { "core authenticator data credential id mismatch" }
        }
    }

    private fun noneAttestation(authenticatorData: ByteArray): ByteArray {
        val fmtKey = cborText("fmt")
        val fmtValue = cborText("none")
        val statementKey = cborText("attStmt")
        val authDataKey = cborText("authData")
        return byteArrayOf(0xa3.toByte()) +
            fmtKey + fmtValue +
            statementKey + byteArrayOf(0xa0.toByte()) +
            authDataKey + cborBytes(authenticatorData)
    }

    private fun cborText(value: String): ByteArray {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        return cborLength(3, bytes.size) + bytes
    }

    private fun cborBytes(value: ByteArray): ByteArray = cborLength(2, value.size) + value

    private fun cborLength(majorType: Int, length: Int): ByteArray = when {
        length < 24 -> byteArrayOf(((majorType shl 5) or length).toByte())
        length <= 0xff -> byteArrayOf(((majorType shl 5) or 24).toByte(), length.toByte())
        length <= 0xffff -> byteArrayOf(
            ((majorType shl 5) or 25).toByte(),
            (length ushr 8).toByte(),
            length.toByte(),
        )
        else -> throw IllegalArgumentException("CBOR value is too large")
    }

    private fun JSONArray.credentialIds(): List<ByteArray> =
        (0 until length()).map { index ->
            val descriptor = getJSONObject(index)
            require(descriptor.requiredString("type") == PUBLIC_KEY_TYPE) {
                "unsupported credential descriptor type"
            }
            decodeBase64Url(descriptor.requiredString("id"), "credential id")
        }

    private fun parseObject(value: String): JSONObject = try {
        JSONObject(value)
    } catch (error: Exception) {
        throw IllegalArgumentException("requestJson is not a JSON object", error)
    }

    private fun JSONObject.requiredObject(name: String): JSONObject = try {
        getJSONObject(name)
    } catch (error: Exception) {
        throw IllegalArgumentException("missing or invalid $name", error)
    }

    private fun JSONObject.requiredArray(name: String): JSONArray = try {
        getJSONArray(name)
    } catch (error: Exception) {
        throw IllegalArgumentException("missing or invalid $name", error)
    }

    private fun JSONObject.requiredString(name: String): String = try {
        getString(name).also { require(it.isNotBlank()) { "$name is empty" } }
    } catch (error: Exception) {
        throw IllegalArgumentException("missing or invalid $name", error)
    }

    private fun validateRpId(value: String): String {
        val ascii = try {
            IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).lowercase()
        } catch (error: Exception) {
            throw IllegalArgumentException("invalid relying party id", error)
        }
        require(ascii == value && ascii.length <= 253) {
            "relying party id must be lower-case ASCII without a trailing dot"
        }
        require(ascii == "localhost" || ascii.split('.').all { label ->
            label.isNotEmpty() && label.length <= 63 &&
                label.first().isLetterOrDigit() && label.last().isLetterOrDigit()
        }) { "invalid relying party id" }
        return ascii
    }

    private fun decodeBase64Url(value: String, field: String): ByteArray {
        require(value.isNotEmpty() && BASE64_URL.matches(value)) { "$field is not base64url" }
        return try {
            Base64.getUrlDecoder().decode(value)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("$field is not base64url", error)
        }
    }

    private fun encodeBase64Url(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private data class ClientData(val json: ByteArray?, val hash: ByteArray)

    companion object {
        private const val PUBLIC_KEY_TYPE = "public-key"
        private const val ES256 = -7
        private const val MAX_USER_HANDLE_BYTES = 64
        private const val SHA256_BYTES = 32
        private const val AUTHENTICATOR_DATA_HEADER_BYTES = 37
        private const val ATTESTED_CREDENTIAL_ID_OFFSET = 55
        private const val USER_PRESENT_FLAG = 0x01
        private const val USER_VERIFIED_FLAG = 0x04
        private const val ATTESTED_CREDENTIAL_DATA_FLAG = 0x40
        private val BASE64_URL = Regex("[A-Za-z0-9_-]+")
        private val EMPTY_CLIENT_DATA_JSON = "{}".toByteArray(StandardCharsets.UTF_8)
    }
}
