package org.vaultkern.android.credentials

import android.content.Context
import android.view.View
import android.view.autofill.AutofillValue
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AutofillDatasetFactoryTest {
    @Test
    fun populatedDatasetCarriesPasswordAndTotpWithoutLeakingDiagnostics() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val ids = AutofillFieldIds(
            username = View(context).apply { id = View.generateViewId() }.autofillId,
            password = View(context).apply { id = View.generateViewId() }.autofillId,
            totp = View(context).apply { id = View.generateViewId() }.autofillId,
        )
        val values = autofillValues(
            ids = ids,
            username = "alice@example.com",
            password = "correct horse battery staple",
            totp = "123456",
        )
        val dataset = AutofillDatasetFactory.populated(
            context = context,
            ids = ids,
            label = "Example",
            username = "alice@example.com",
            password = "correct horse battery staple",
            totp = "123456",
        )

        assertNotNull(dataset)
        assertEquals(AutofillValue.forText("alice@example.com"), values[ids.username])
        assertEquals(AutofillValue.forText("correct horse battery staple"), values[ids.password])
        assertEquals(AutofillValue.forText("123456"), values[ids.totp])
    }
}
