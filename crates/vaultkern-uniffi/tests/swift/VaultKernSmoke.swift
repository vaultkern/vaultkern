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

    func storeBlob(key: String, value: VaultKernSensitiveBytes) throws {
        lock.lock()
        defer { lock.unlock() }
        blobs[key] = value.copyData()
        value.close()
    }

    func loadBlob(key: String) throws -> VaultKernSensitiveBytes? {
        lock.lock()
        defer { lock.unlock() }
        if cancelNextLoad {
            cancelNextLoad = false
            throw PlatformAdapterError.Cancelled
        }
        return blobs[key].map(VaultKernSensitiveBytes.init)
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

private final class FakeOneDriveTokenAdapter: OneDriveTokenAdapter, @unchecked Sendable {
    private let lock = NSLock()
    private var token: VaultKernSensitiveString?

    func loadRefreshToken() throws -> VaultKernSensitiveString? {
        lock.lock()
        defer { lock.unlock() }
        return token.map { VaultKernSensitiveString($0.reveal()) }
    }

    func storeRefreshToken(token: VaultKernSensitiveString) throws {
        lock.lock()
        defer { lock.unlock() }
        self.token?.close()
        self.token = VaultKernSensitiveString(token.reveal())
        token.close()
    }

    func deleteRefreshToken() throws {
        lock.lock()
        defer { lock.unlock() }
        token?.close()
        token = nil
    }
}

guard CommandLine.arguments.count == 3 else {
    fatalError("usage: VaultKernSmoke <fixture.kdbx> <password>")
}

let fixture = URL(fileURLWithPath: CommandLine.arguments[1])
let password = VaultKernSensitiveString(CommandLine.arguments[2])
let root = FileManager.default.temporaryDirectory
    .resolvingSymlinksInPath()
    .appendingPathComponent("vaultkern-swift-smoke-\(UUID().uuidString)", isDirectory: true)
try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
let vault = root.appendingPathComponent("smoke.kdbx")
try FileManager.default.copyItem(at: fixture, to: vault)
defer {
    password.close()
    try? FileManager.default.removeItem(at: root)
}

private let adapter = FakeUnlockBlobAdapter()
let session = try VaultSession(
    config: VaultSessionConfig(
        platform: .macos,
        stateDirectory: root.appendingPathComponent("state", isDirectory: true).path,
        temporaryDirectory: root.appendingPathComponent("temporary", isDirectory: true).path
    ),
    unlockBlobAdapter: adapter,
    oneDriveTokenAdapter: FakeOneDriveTokenAdapter()
)
let unlock = session.unlock()
let opened = try session.openVault(path: vault.path)
_ = try unlock.unlockVault(
    vaultId: opened.vaultId,
    password: password,
    keyFilePath: nil,
    kdfConfirmed: false
)
let initialEntries = try session.listEntries(vaultId: opened.vaultId)
precondition(!initialEntries.isEmpty)

_ = try unlock.enroll(password: password, keyFilePath: nil, kdfConfirmed: false)
let closed = try session.lockSession()
precondition(!closed.unlocked)
let blobUnlocked = try unlock.unlockWithBlob(kdfConfirmed: false)
precondition(blobUnlocked.status == .unlocked)
precondition(blobUnlocked.state.unlocked)
let reopenedEntries = try session.listEntries(vaultId: opened.vaultId)
precondition(!reopenedEntries.isEmpty)
_ = try session.lockSession()
adapter.cancelNextBlobLoad()
let cancelled = try unlock.unlockWithBlob(kdfConfirmed: false)
precondition(cancelled.status == .cancelled)
let unlockedAfterCancellation = try unlock.unlockWithBlob(kdfConfirmed: false)
precondition(unlockedAfterCancellation.status == .unlocked)
_ = try unlock.revoke()
_ = try session.lockSession()
let revoked = try unlock.unlockWithBlob(kdfConfirmed: false)
precondition(revoked.status == .notEnrolled)
_ = try session.closeVault(vaultId: opened.vaultId)
print("SWIFT_SMOKE_PASS")
