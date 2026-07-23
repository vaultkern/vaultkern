package org.vaultkern.android.sync

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import java.net.URI

class AndroidOneDriveAuthPresenter(context: Context) : OneDriveAuthPresenter {
    private val applicationContext = context.applicationContext

    @SuppressLint("QueryPermissionsNeeded")
    override fun open(authUrl: String) {
        val parsed = try {
            URI(authUrl)
        } catch (error: Throwable) {
            throw IllegalArgumentException("OneDrive authorization URL is invalid", error)
        }
        require(parsed.scheme == "https" && parsed.host != null && parsed.rawUserInfo == null) {
            "OneDrive authorization URL must be HTTPS"
        }
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(authUrl)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        require(intent.resolveActivity(applicationContext.packageManager) != null) {
            "no browser is available for OneDrive authorization"
        }
        applicationContext.startActivity(intent)
    }
}
