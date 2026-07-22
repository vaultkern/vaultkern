package org.vaultkern.core.smoke

import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import org.vaultkern.core.PlatformAdapterException
import org.vaultkern.core.UnlockBlobAdapter
import org.vaultkern.core.VaultSession

private class FakeUnlockBlobAdapter : UnlockBlobAdapter {
    private val blobs = ConcurrentHashMap<String, ByteArray>()
    private val cancelNextLoad = AtomicBoolean(false)

    override fun supportsUnlockBlob() = true
    override fun authorize(reason: String) = Unit
    override fun storeRequiresUserPresence() = false
    override fun loadRequiresUserPresence() = false
    override fun authorizeStoreUserPresence() = Unit
    fun cancelNextBlobLoad() {
        cancelNextLoad.set(true)
    }
    override fun storeBlob(key: String, value: ByteArray) {
        blobs[key] = value.copyOf()
    }
    override fun loadBlob(key: String): ByteArray? {
        if (cancelNextLoad.getAndSet(false)) {
            throw PlatformAdapterException.Cancelled()
        }
        return blobs[key]?.copyOf()
    }
    override fun containsBlob(key: String) = blobs.containsKey(key)
    override fun deleteBlob(key: String) {
        blobs.remove(key)
    }
}

fun main(args: Array<String>) {
    check(args.size == 2) { "usage: VaultKernSmoke <fixture.kdbx> <password>" }
    val vault = Files.createTempFile("vaultkern-kotlin-smoke", ".kdbx")
    Files.copy(java.nio.file.Path.of(args[0]), vault, StandardCopyOption.REPLACE_EXISTING)

    try {
        val adapter = FakeUnlockBlobAdapter()
        val session = VaultSession(adapter)
        val unlock = session.unlock()
        val opened = session.openVault(vault.toString())
        unlock.unlockVault(opened.vaultId, args[1], null)
        check(session.listEntries(opened.vaultId).isNotEmpty())

        unlock.enroll(args[1], null)
        check(!session.closeVault().unlocked)
        check(unlock.unlockWithBlob().unlocked)
        check(session.listEntries(opened.vaultId).isNotEmpty())
        session.closeVault()
        adapter.cancelNextBlobLoad()
        check(runCatching { unlock.unlockWithBlob() }.isFailure)
        check(unlock.unlockWithBlob().unlocked)
        unlock.revoke()
        session.closeVault()
        check(runCatching { unlock.unlockWithBlob() }.isFailure)
        println("KOTLIN_SMOKE_PASS")
    } finally {
        Files.deleteIfExists(vault)
    }
}
