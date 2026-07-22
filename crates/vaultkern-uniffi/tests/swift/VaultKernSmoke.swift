import Foundation
import VaultKernCore

private final class FakeUnlockBlobAdapter: UnlockBlobAdapter, @unchecked Sendable {
    private let lock = NSLock()
    private var blobs: [String: Data] = [:]
    private var cancelNextLoad = false

    func supportsUnlockBlob() throws -> Bool { true }
    func authorize(reason: String) throws {}
    func storeRequiresUserPresence() throws -> Bool { false }
    func loadRequiresUserPresence() throws -> Bool { false }
    func authorizeStoreUserPresence() throws {}

    func cancelNextBlobLoad() {
        lock.lock()
        defer { lock.unlock() }
        cancelNextLoad = true
    }

    func storeBlob(key: String, value: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        blobs[key] = value
    }

    func loadBlob(key: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if cancelNextLoad {
            cancelNextLoad = false
            throw PlatformAdapterError.Cancelled
        }
        return blobs[key]
    }

    func containsBlob(key: String) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return blobs[key] != nil
    }

    func deleteBlob(key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        blobs.removeValue(forKey: key)
    }
}

guard CommandLine.arguments.count == 3 else {
    fatalError("usage: VaultKernSmoke <fixture.kdbx> <password>")
}

let fixture = URL(fileURLWithPath: CommandLine.arguments[1])
let password = CommandLine.arguments[2]
let vault = FileManager.default.temporaryDirectory
    .appendingPathComponent("vaultkern-swift-smoke-\(UUID().uuidString).kdbx")
try FileManager.default.copyItem(at: fixture, to: vault)
defer { try? FileManager.default.removeItem(at: vault) }

let adapter = FakeUnlockBlobAdapter()
let session = VaultSession(unlockBlobAdapter: adapter)
let unlock = session.unlock()
let opened = try session.openVault(path: vault.path)
_ = try unlock.unlockVault(vaultId: opened.vaultId, password: password, keyFilePath: nil)
let initialEntries = try session.listEntries(vaultId: opened.vaultId)
precondition(!initialEntries.isEmpty)

_ = try unlock.enroll(password: password, keyFilePath: nil)
let closed = try session.closeVault()
precondition(!closed.unlocked)
let blobUnlocked = try unlock.unlockWithBlob()
precondition(blobUnlocked.unlocked)
let reopenedEntries = try session.listEntries(vaultId: opened.vaultId)
precondition(!reopenedEntries.isEmpty)
_ = try session.closeVault()
adapter.cancelNextBlobLoad()
do {
    _ = try unlock.unlockWithBlob()
    fatalError("cancelled unlock blob read unexpectedly unlocked the vault")
} catch {}
let unlockedAfterCancellation = try unlock.unlockWithBlob()
precondition(unlockedAfterCancellation.unlocked)
_ = try unlock.revoke()
_ = try session.closeVault()
do {
    _ = try unlock.unlockWithBlob()
    fatalError("revoked unlock blob unexpectedly unlocked the vault")
} catch {}
print("SWIFT_SMOKE_PASS")
