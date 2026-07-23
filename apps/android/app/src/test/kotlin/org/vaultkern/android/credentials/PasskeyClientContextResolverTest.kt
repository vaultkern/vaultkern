package org.vaultkern.android.credentials

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class PasskeyClientContextResolverTest {
    @Test
    fun nativePasskeyVerificationRequestsCredentialSharingPermission() {
        val uri = digitalAssetLinkCheckUri(
            relyingParty = "example.com",
            packageName = "com.example.app",
            certificateFingerprint = "AA:BB:CC",
        )
        val query = uri.rawQuery.split('&').associate { parameter ->
            val (key, value) = parameter.split('=', limit = 2)
            URLDecoder.decode(key, StandardCharsets.UTF_8) to
                URLDecoder.decode(value, StandardCharsets.UTF_8)
        }

        assertEquals(
            "delegate_permission/common.get_login_creds",
            query["relation"],
        )
        assertFalse(query.values.contains("delegate_permission/common.handle_all_urls"))
    }
}
