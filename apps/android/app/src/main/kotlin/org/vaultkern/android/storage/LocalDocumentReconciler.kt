package org.vaultkern.android.storage

class LocalDocumentReconciler(
    private val reconcilePending: () -> Unit,
    private val refreshAuthorities: () -> Unit,
) {
    fun prepareForUnlock(
        vaultUnlocked: Boolean,
        currentSourceIsLocal: Boolean,
    ) {
        if (vaultUnlocked || !currentSourceIsLocal) return
        reconcilePending()
        refreshAuthorities()
    }

    fun reconcile(
        vaultUnlocked: Boolean,
        refreshAuthority: Boolean = true,
    ) {
        reconcilePending()
        if (!vaultUnlocked && refreshAuthority) refreshAuthorities()
    }
}
