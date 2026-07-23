package org.vaultkern.android.credentials

import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillTargetResolverTest {
    @Test
    fun nativeAppsOnlyMatchExplicitAndroidAppEntries() {
        val target = resolver().resolve(
            AutofillRequestOrigin(packageName = "com.example.app"),
        ) as AutofillTarget.Native

        assertEquals("androidapp://com.example.app", target.matchUrl)
        assertTrue(target.accepts("androidapp://com.example.app"))
        assertFalse(target.accepts("https://com.example.app/login"))
        assertFalse(target.accepts("androidapp://com.example.other"))
    }

    @Test
    fun unverifiedWebViewCannotClaimAWebsite() {
        val target = resolver(
            fingerprints = listOf("AA:BB"),
            linked = false,
        ).resolve(
            AutofillRequestOrigin(
                packageName = "com.untrusted.webview",
                webScheme = "https",
                webDomain = "accounts.example.com",
            ),
        )

        assertNull(target)
    }

    @Test
    fun credentialSharingAssetLinkAuthorizesAWebViewTarget() {
        val target = resolver(
            fingerprints = listOf("AA:BB"),
            linked = true,
        ).resolve(
            AutofillRequestOrigin(
                packageName = "com.example.webview",
                webScheme = "https",
                webDomain = "accounts.example.com",
            ),
        ) as AutofillTarget.Web

        assertEquals("https://accounts.example.com", target.matchUrl)
        assertTrue(target.accepts("https://accounts.example.com/login"))
        assertTrue(target.accepts("http://accounts.example.com/login"))
        assertFalse(target.accepts("androidapp://accounts.example.com"))
    }

    @Test
    fun insecureWebTargetsDoNotReceiveCredentialsStoredForHttps() {
        val target = AutofillTarget.Web("http://accounts.example.com")

        assertTrue(target.accepts("http://accounts.example.com/login"))
        assertFalse(target.accepts("https://accounts.example.com/login"))
        assertFalse(target.accepts("accounts.example.com/login"))
    }

    @Test
    fun signedPrivilegedBrowserCanRepresentArbitraryWebOrigins() {
        val assetLinkChecks = AtomicInteger()
        val allowlist = """
            {
              "apps": [{
                "type": "android",
                "info": {
                  "package_name": "com.example.browser",
                  "signatures": [{"cert_fingerprint_sha256": "AA:BB"}]
                }
              }]
            }
        """.trimIndent()
        val target = AutofillTargetResolver(
            signingFingerprints = { listOf("AA:BB") },
            assetLinks = NativeAssetLinkVerifier { _, _, _ ->
                assetLinkChecks.incrementAndGet()
                false
            },
            privilegedAllowlist = { allowlist },
        ).resolve(
            AutofillRequestOrigin(
                packageName = "com.example.browser",
                webScheme = "https",
                webDomain = "accounts.example.com",
            ),
        )

        assertEquals("https://accounts.example.com", target?.matchUrl)
        assertEquals(0, assetLinkChecks.get())
    }

    private fun resolver(
        fingerprints: List<String> = emptyList(),
        linked: Boolean = false,
        allowlist: String = "{\"apps\":[]}",
    ): AutofillTargetResolver = AutofillTargetResolver(
        signingFingerprints = { fingerprints },
        assetLinks = NativeAssetLinkVerifier { _, _, _ -> linked },
        privilegedAllowlist = { allowlist },
    )
}
