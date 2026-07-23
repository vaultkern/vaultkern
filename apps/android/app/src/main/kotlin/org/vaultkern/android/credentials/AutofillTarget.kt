package org.vaultkern.android.credentials

import android.content.Context
import android.content.pm.PackageManager
import java.net.IDN
import java.net.URI
import java.security.MessageDigest
import org.json.JSONObject

data class AutofillRequestOrigin(
    val packageName: String,
    val webScheme: String? = null,
    val webDomain: String? = null,
) {
    override fun toString(): String =
        "AutofillRequestOrigin(packageName=[REDACTED], webScheme=$webScheme, " +
            "webDomain=${if (webDomain == null) "absent" else "[REDACTED]"})"
}

sealed interface AutofillTarget {
    val matchUrl: String
    fun accepts(entryUrl: String): Boolean

    data class Native(val packageName: String) : AutofillTarget {
        override val matchUrl: String = "androidapp://$packageName"

        override fun accepts(entryUrl: String): Boolean {
            val parsed = try {
                URI(entryUrl)
            } catch (_: Exception) {
                return false
            }
            return parsed.scheme.equals("androidapp", ignoreCase = true) &&
                parsed.host.equals(packageName, ignoreCase = true)
        }

        override fun toString(): String = "AutofillTarget.Native(packageName=[REDACTED])"
    }

    data class Web(override val matchUrl: String) : AutofillTarget {
        override fun accepts(entryUrl: String): Boolean {
            val targetScheme = try {
                URI(matchUrl).scheme?.lowercase()
            } catch (_: Exception) {
                return false
            }
            val parsedEntry = try {
                URI(entryUrl.trim()).takeIf { it.host != null }
                    ?: URI("https://${entryUrl.trim()}")
            } catch (_: Exception) {
                return false
            }
            val entryScheme = parsedEntry.scheme?.lowercase()
            if (entryScheme != "https" && entryScheme != "http") return false
            return targetScheme != "http" || entryScheme == "http"
        }

        override fun toString(): String = "AutofillTarget.Web(matchUrl=[REDACTED])"
    }
}

class AutofillTargetResolver(
    private val signingFingerprints: (String) -> List<String>,
    private val assetLinks: NativeAssetLinkVerifier,
    private val privilegedAllowlist: () -> String,
) {
    fun resolve(origin: AutofillRequestOrigin): AutofillTarget? {
        require(origin.packageName.isNotBlank()) { "autofill caller package is empty" }
        val domain = origin.webDomain ?: return AutofillTarget.Native(origin.packageName)
        val webOrigin = normalizedWebOrigin(origin.webScheme, domain) ?: return null
        val fingerprints = signingFingerprints(origin.packageName)
            .map(::normalizeFingerprint)
            .distinct()
        if (fingerprints.isEmpty()) return null
        val privileged = privilegedAllowlistContains(
            privilegedAllowlist(),
            origin.packageName,
            fingerprints,
        )
        if (privileged) return AutofillTarget.Web(webOrigin)
        val normalizedDomain = requireNotNull(URI(webOrigin).host)
        val linked = fingerprints.any { fingerprint ->
            try {
                assetLinks.verify(normalizedDomain, origin.packageName, fingerprint)
            } catch (_: Exception) {
                false
            }
        }
        return if (linked) AutofillTarget.Web(webOrigin) else null
    }
}

internal fun signingCertificateFingerprints(context: Context, packageName: String): List<String> {
    val signingInfo = context.packageManager.getPackageInfo(
        packageName,
        PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
    ).signingInfo ?: return emptyList()
    val signers = if (signingInfo.hasMultipleSigners()) {
        signingInfo.apkContentsSigners
    } else {
        signingInfo.signingCertificateHistory
    }
    return signers.map { signature ->
        MessageDigest.getInstance("SHA-256")
            .digest(signature.toByteArray())
            .joinToString(":") { byte -> "%02X".format(byte.toInt() and 0xff) }
    }
}

private fun normalizedWebOrigin(scheme: String?, domain: String): String? {
    val normalizedScheme = scheme?.lowercase() ?: "https"
    if (normalizedScheme != "https" && normalizedScheme != "http") return null
    val asciiDomain = try {
        IDN.toASCII(domain, IDN.USE_STD3_ASCII_RULES).lowercase()
    } catch (_: IllegalArgumentException) {
        return null
    }
    if (asciiDomain.isBlank() || asciiDomain.endsWith('.')) return null
    val parsed = try {
        URI("$normalizedScheme://$asciiDomain")
    } catch (_: Exception) {
        return null
    }
    if (parsed.host != asciiDomain || parsed.rawUserInfo != null || parsed.port != -1) return null
    return parsed.toString()
}

private fun privilegedAllowlistContains(
    json: String,
    packageName: String,
    fingerprints: List<String>,
): Boolean = try {
    val accepted = fingerprints.toSet()
    val apps = JSONObject(json).getJSONArray("apps")
    (0 until apps.length()).any { index ->
        val app = apps.getJSONObject(index)
        if (app.optString("type") != "android") return@any false
        val info = app.getJSONObject("info")
        if (info.optString("package_name") != packageName) return@any false
        val signatures = info.getJSONArray("signatures")
        (0 until signatures.length()).any { signatureIndex ->
            normalizeFingerprint(
                signatures.getJSONObject(signatureIndex)
                    .optString("cert_fingerprint_sha256"),
            ) in accepted
        }
    }
} catch (_: Exception) {
    false
}

private fun normalizeFingerprint(value: String): String = value.trim().uppercase()
