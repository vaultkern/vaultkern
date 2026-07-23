package org.vaultkern.android.storage

interface PersistableLocalDocumentAccess : LocalDocumentAccess {
    fun retainReadWrite(uri: String)
    fun displayName(uri: String): String
}

class LocalDocumentSelectionService(
    private val access: PersistableLocalDocumentAccess,
    private val workspace: LocalDocumentWorkspace,
) {
    fun select(uri: String): SelectedLocalDocument {
        access.retainReadWrite(uri)
        return workspace.select(uri, access.displayName(uri))
    }
}
