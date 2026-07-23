package org.vaultkern.android

import android.app.Application

class VaultKernApplication : Application() {
    lateinit var graph: VaultKernGraph
        private set

    override fun onCreate() {
        super.onCreate()
        graph = VaultKernGraph(this)
    }
}
