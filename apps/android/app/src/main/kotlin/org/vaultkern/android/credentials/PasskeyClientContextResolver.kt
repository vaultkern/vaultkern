package org.vaultkern.android.credentials

import android.content.Context
import android.content.pm.SigningInfo
import androidx.annotation.RawRes
import androidx.credentials.provider.CallingAppInfo
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject
import org.vaultkern.android.R

class PasskeyClientContextResolver(
    context: Context,
    private val assetLinks: NativeAssetLinkVerifier = GoogleDigitalAssetLinkVerifier(),
    @RawRes private val privilegedAllowlistResource: Int = R.raw.gpm_passkeys_privileged_apps,
) {
    private val applicationContext = context.applicationContext
    // Snapshot from https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json
    // on 2026-07-22; SHA-256 594a83e3cb3475e8af8da22595b3481cbefb61b747c7a67a66aa2e47433ed79c.
    private val privilegedAllowlist: String by lazy {
        applicationContext.resources.openRawResource(privilegedAllowlistResource)
            .bufferedReader(StandardCharsets.UTF_8)
            .use { reader -> reader.readText() }
            .also { require(it.isNotBlank()) { "privileged caller allowlist is empty" } }
    }

    fun resolve(
        relyingParty: String,
        callingApp: CallingAppInfo,
        suppliedClientDataHash: ByteArray?,
    ): PasskeyClientContext {
        if (callingApp.isOriginPopulated()) {
            val suppliedHash = suppliedClientDataHash
            require(suppliedHash?.size == SHA256_BYTES) {
                "a privileged passkey request must supply a 32-byte clientDataHash"
            }
            val origin = callingApp.getOrigin(privilegedAllowlist)
                ?: throw IllegalArgumentException("trusted privileged caller omitted its origin")
            validateWebOrigin(origin)
            return PasskeyClientContext(
                origin = origin,
                packageName = null,
                suppliedClientDataHash = suppliedHash!!.copyOf(),
            )
        }

        require(suppliedClientDataHash == null) {
            "a native passkey request must not supply clientDataHash"
        }
        val certificate = currentSigningCertificate(callingApp.signingInfo)
        val fingerprint = normalizedSha256Fingerprint(certificate)
        require(
            assetLinks.verify(
                relyingParty = relyingParty,
                packageName = callingApp.packageName,
                certificateFingerprint = fingerprint,
            ),
        ) { "the native caller is not linked to the relying party" }
        return PasskeyClientContext(
            origin = "android:apk-key-hash:${base64Url(sha256(certificate))}",
            packageName = callingApp.packageName,
            suppliedClientDataHash = null,
        )
    }

    private fun currentSigningCertificate(signingInfo: SigningInfo): ByteArray {
        require(!signingInfo.hasMultipleSigners()) {
            "native passkey callers with multiple current signers are unsupported"
        }
        return signingInfo.apkContentsSigners.singleOrNull()?.toByteArray()
            ?: throw IllegalArgumentException("native passkey caller has no signing certificate")
    }

    private fun validateWebOrigin(value: String) {
        val origin = try {
            URI(value)
        } catch (error: Exception) {
            throw IllegalArgumentException("privileged caller supplied an invalid origin", error)
        }
        require(
            origin.scheme == "https" && origin.host != null && origin.rawUserInfo == null &&
                origin.rawPath.orEmpty().isEmpty() && origin.rawQuery == null && origin.rawFragment == null,
        ) { "privileged caller supplied a non-HTTPS or non-origin value" }
    }

    private fun normalizedSha256Fingerprint(value: ByteArray): String =
        sha256(value).joinToString(":") { byte -> "%02X".format(byte.toInt() and 0xff) }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private fun base64Url(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    companion object {
        private const val SHA256_BYTES = 32
    }
}

fun interface NativeAssetLinkVerifier {
    fun verify(
        relyingParty: String,
        packageName: String,
        certificateFingerprint: String,
    ): Boolean
}

class GoogleDigitalAssetLinkVerifier : NativeAssetLinkVerifier {
    override fun verify(
        relyingParty: String,
        packageName: String,
        certificateFingerprint: String,
    ): Boolean {
        val connection = digitalAssetLinkCheckUri(
            relyingParty,
            packageName,
            certificateFingerprint,
        ).toURL().openConnection() as HttpsURLConnection
        connection.connectTimeout = TIMEOUT_MILLIS
        connection.readTimeout = TIMEOUT_MILLIS
        connection.instanceFollowRedirects = false
        connection.requestMethod = "GET"
        connection.setRequestProperty("Accept", "application/json")
        return try {
            require(connection.responseCode == HttpsURLConnection.HTTP_OK) {
                "Digital Asset Links check failed"
            }
            val body = connection.inputStream.use { input ->
                val bytes = input.readNBytes(MAX_RESPONSE_BYTES + 1)
                require(bytes.size <= MAX_RESPONSE_BYTES) { "Digital Asset Links response is too large" }
                String(bytes, StandardCharsets.UTF_8)
            }
            JSONObject(body).optBoolean("linked", false)
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        private const val TIMEOUT_MILLIS = 5_000
        private const val MAX_RESPONSE_BYTES = 64 * 1024
    }
}

internal fun digitalAssetLinkCheckUri(
    relyingParty: String,
    packageName: String,
    certificateFingerprint: String,
): URI {
    val query = listOf(
        "source.web.site" to "https://$relyingParty",
        "target.android_app.package_name" to packageName,
        "target.android_app.certificate.sha256_fingerprint" to certificateFingerprint,
        "relation" to "delegate_permission/common.get_login_creds",
    ).joinToString("&") { (key, value) ->
        "${encodeDigitalAssetLinkParameter(key)}=${encodeDigitalAssetLinkParameter(value)}"
    }
    return URI("https://digitalassetlinks.googleapis.com/v1/assetlinks:check?$query")
}

private fun encodeDigitalAssetLinkParameter(value: String): String =
    URLEncoder.encode(value, StandardCharsets.UTF_8.name())
