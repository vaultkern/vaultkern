package org.vaultkern.android.credentials

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CredentialServiceProcessTest {
    @Test
    fun autofillAndCredentialProviderShareTheResidentApplicationProcess() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val packageManager = context.packageManager
        val appProcess = context.applicationInfo.processName

        val autofill = packageManager.getServiceInfo(
            ComponentName(context, VaultKernAutofillService::class.java),
            PackageManager.ComponentInfoFlags.of(0),
        )
        val passkeys = packageManager.getServiceInfo(
            ComponentName(context, VaultKernCredentialProviderService::class.java),
            PackageManager.ComponentInfoFlags.of(0),
        )

        assertEquals(appProcess, autofill.processName)
        assertEquals(appProcess, passkeys.processName)
        assertEquals("android.permission.BIND_AUTOFILL_SERVICE", autofill.permission)
        assertEquals("android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE", passkeys.permission)

        val allowlist = context.resources.openRawResource(
            org.vaultkern.android.R.raw.gpm_passkeys_privileged_apps,
        ).use { it.readBytes() }
        val digest = MessageDigest.getInstance("SHA-256").digest(allowlist)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        assertEquals(
            "594a83e3cb3475e8af8da22595b3481cbefb61b747c7a67a66aa2e47433ed79c",
            digest,
        )
    }
}
