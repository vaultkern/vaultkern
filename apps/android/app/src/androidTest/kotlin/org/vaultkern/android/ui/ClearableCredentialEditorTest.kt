package org.vaultkern.android.ui

import android.text.SpannableStringBuilder
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ClearableCredentialEditorTest {
    @Test
    fun takingTheCredentialCopiesIntoClearableOwnershipAndErasesTheEditor() {
        val editor = SpannableStringBuilder("one-use-master-secret")

        val credential = takeAndClearCredential(editor)

        assertArrayEquals("one-use-master-secret".toCharArray(), credential)
        assertEquals(0, editor.length)
        credential.fill('\u0000')
        assertTrue(credential.all { it == '\u0000' })
    }
}
