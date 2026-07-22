package org.vaultkern.android.storage

interface PersistableLocalDocumentAccess : LocalDocumentAccess {
    fun retainReadWrite(uri: String)
    fun displayName(uri: String): String
}

class LocalDocumentSelectionService(
    private val access: PersistableLocalDocumentAccess,
    private val workspace: LocalDocumentWorkspace,
    private val openSelectedPrivateVault: (String) -> Unit = {},
) {
    fun select(uri: String): SelectedLocalDocument {
        access.retainReadWrite(uri)
        val selected = workspace.select(uri, access.displayName(uri))
        openSelectedPrivateVault(selected.privatePath)
        return selected
    }
}
