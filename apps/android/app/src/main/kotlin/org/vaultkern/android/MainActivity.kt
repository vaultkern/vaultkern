package org.vaultkern.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import org.vaultkern.android.ui.VaultKernUnlockScreen

class MainActivity : FragmentActivity() {
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
            VaultKernUnlockScreen(
                state = state,
                onPathChanged = viewModel::onPathChanged,
                onPasswordChanged = viewModel::onPasswordChanged,
                onInteractiveUnlock = viewModel::interactiveUnlock,
                onQuickUnlock = viewModel::quickUnlock,
                onQuickUnlockDesiredChanged = viewModel::setQuickUnlockDesired,
            )
        }
    }
}
