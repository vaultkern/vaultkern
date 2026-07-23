package org.vaultkern.android

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidManifestContractTest {
    @Test
    fun oneDriveAuthorizationCanResolveAnHttpsBrowserUnderPackageVisibility() {
        val manifest = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(File("src/main/AndroidManifest.xml"))
        val intents = manifest.getElementsByTagName("intent")
        var browserQueryDeclared = false
        for (index in 0 until intents.length) {
            val intent = intents.item(index)
            val attributes = intent.childNodes
            var view = false
            var https = false
            for (childIndex in 0 until attributes.length) {
                val child = attributes.item(childIndex)
                val name = child.attributes?.getNamedItem("android:name")?.nodeValue
                val scheme = child.attributes?.getNamedItem("android:scheme")?.nodeValue
                view = view || name == "android.intent.action.VIEW"
                https = https || scheme == "https"
            }
            browserQueryDeclared = browserQueryDeclared ||
                (intent.parentNode?.nodeName == "queries" && view && https)
        }

        assertTrue("HTTPS browser query must be declared", browserQueryDeclared)
    }
}
