package org.vaultkern.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import org.vaultkern.android.ui.VaultKernUnlockScreen
import org.vaultkern.android.ui.VaultBrowserScreen

class MainActivity : FragmentActivity() {
    private val chooseLocalVault = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri?.let { viewModel.selectLocalDocument(it.toString()) }
    }

    private val viewModel: UnlockViewModel by lazy {
        val graph = (application as VaultKernApplication).graph
        ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T =
                    UnlockViewModel(graph) as T
            },
        )[UnlockViewModel::class.java]
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            val state by viewModel.state.collectAsState()
            if (state.vaultUnlocked) {
                VaultBrowserScreen(
                    entries = state.entries,
                    editor = state.editor,
                    busy = state.busy,
                    status = state.status,
                    conflictCopyPath = state.conflictCopyPath,
                    syncStatus = state.syncStatus,
                    onEntrySelected = viewModel::selectEntry,
                    onDraftChanged = viewModel::updateDraft,
                    onSave = viewModel::saveEditor,
                    onCloseEditor = viewModel::closeEditor,
                    onSync = viewModel::syncOneDrive,
                    onLock = viewModel::lockVault,
                )
            } else {
                VaultKernUnlockScreen(
                    state = state,
                    onPasswordChanged = viewModel::onPasswordChanged,
                    onInteractiveUnlock = viewModel::interactiveUnlock,
                    onQuickUnlock = viewModel::quickUnlock,
                    onQuickUnlockDesiredChanged = viewModel::setQuickUnlockDesired,
                    onChooseLocalVault = {
                        chooseLocalVault.launch(
                            arrayOf(
                                org.vaultkern.android.storage.AndroidLocalDocumentAccess
                                    .KEEPASS_MIME_TYPE,
                                "application/octet-stream",
                            ),
                        )
                    },
                    onBeginOneDriveLogin = viewModel::beginOneDriveLogin,
                    onCompleteOneDriveLogin = viewModel::completeOneDriveLogin,
                    onOneDriveItemSelected = viewModel::selectOneDriveItem,
                    onOneDriveRoot = viewModel::browseOneDriveRoot,
                )
            }
        }
    }
}
