import Foundation
import XCTest

@testable import VaultKern

@MainActor
final class VaultAppModelTests: XCTestCase {
  func testRetryAfterSaveFailureDoesNotApplyEditTwice() async throws {
    let runtime = ModelTestRuntime(failFirstSave: true)
    let model = VaultAppModel(runtime: runtime)

    try await openTestVault(model)
    let password = VaultKernSensitiveString("master-password")
    await model.unlockWithPassword(password, keyFileURL: nil)
    await model.selectEntry("entry")
    model.updateDraft(\.notes, value: "changed")

    await model.saveDraft()
    XCTAssertEqual(model.saveProgress, .staged)
    XCTAssertEqual(runtime.editCount, 1)
    XCTAssertEqual(runtime.saveCount, 1)
    XCTAssertEqual(password.reveal(), "")

    await model.saveDraft()
    XCTAssertEqual(model.saveProgress, .clean)
    XCTAssertEqual(runtime.editCount, 1)
    XCTAssertEqual(runtime.saveCount, 2)
  }

  func testCancellingKDFConfirmationClosesRetainedCredential() async throws {
    let runtime = ModelTestRuntime(requiresKDFConfirmation: true)
    let model = VaultAppModel(runtime: runtime)
    try await openTestVault(model)
    let password = VaultKernSensitiveString("master-password")

    await model.unlockWithPassword(password, keyFileURL: nil)
    XCTAssertNotNil(model.kdfPrompt)
    XCTAssertEqual(password.reveal(), "master-password")

    model.cancelKDF()
    XCTAssertNil(model.kdfPrompt)
    XCTAssertEqual(password.reveal(), "")
  }

  func testVaultDirectoryScopeIsRetainedUntilClose() async throws {
    let runtime = ModelTestRuntime()
    let scopedAccess = ModelTestScopedAccess()
    let model = VaultAppModel(runtime: runtime, scopedAccess: scopedAccess)
    let location = try TestVaultLocation()
    defer { location.remove() }

    await model.openVault(
      location.vaultURL,
      authorizedDirectoryURL: location.directoryURL
    )

    XCTAssertEqual(scopedAccess.retained, [location.vaultURL, location.directoryURL])
    XCTAssertTrue(scopedAccess.released.isEmpty)

    await model.closeVault()

    XCTAssertEqual(scopedAccess.released, [location.directoryURL, location.vaultURL])
  }

  func testRejectedVaultSelectionReleasesBothScopes() async throws {
    let scopedAccess = ModelTestScopedAccess()
    let model = VaultAppModel(runtime: ModelTestRuntime(), scopedAccess: scopedAccess)
    let location = try TestVaultLocation()
    defer { location.remove() }
    let wrongDirectoryURL = location.directoryURL.deletingLastPathComponent()

    await model.openVault(location.vaultURL, authorizedDirectoryURL: wrongDirectoryURL)

    XCTAssertNil(model.currentVault)
    XCTAssertEqual(scopedAccess.retained, [location.vaultURL, wrongDirectoryURL])
    XCTAssertEqual(scopedAccess.released, [wrongDirectoryURL, location.vaultURL])
  }

  func testRejectedUnlockReleasesKeyFileScopeAndCredential() async {
    let scopedAccess = ModelTestScopedAccess()
    let model = VaultAppModel(runtime: ModelTestRuntime(), scopedAccess: scopedAccess)
    let keyFileURL = URL(fileURLWithPath: "/private/tmp/model-test.key")
    let password = VaultKernSensitiveString("master-password")

    await model.unlockWithPassword(password, keyFileURL: keyFileURL)

    XCTAssertEqual(password.reveal(), "")
    XCTAssertEqual(scopedAccess.retained, [keyFileURL])
    XCTAssertEqual(scopedAccess.released, [keyFileURL])
  }

  private func openTestVault(_ model: VaultAppModel) async throws {
    let location = try TestVaultLocation()
    defer { location.remove() }
    await model.openVault(
      location.vaultURL,
      authorizedDirectoryURL: location.directoryURL
    )
  }
}

@MainActor
private final class ModelTestScopedAccess: SecurityScopedAccessing {
  private(set) var retained: [URL] = []
  private(set) var released: [URL] = []

  func retain(_ url: URL) {
    retained.append(url)
  }

  func release(_ url: URL) {
    released.append(url)
  }

  func releaseAll() {
    for url in retained.reversed() where !released.contains(url) {
      released.append(url)
    }
  }
}

private struct TestVaultLocation {
  let directoryURL: URL
  let vaultURL: URL

  init() throws {
    directoryURL = FileManager.default.temporaryDirectory
      .appendingPathComponent("vaultkern-model-\(UUID().uuidString)", isDirectory: true)
    vaultURL = directoryURL.appendingPathComponent("model-test.kdbx")
    try FileManager.default.createDirectory(
      at: directoryURL,
      withIntermediateDirectories: false
    )
    try Data().write(to: vaultURL)
  }

  func remove() {
    try? FileManager.default.removeItem(at: directoryURL)
  }
}

private final class ModelTestRuntime: VaultRuntimeClient, @unchecked Sendable {
  private let lock = NSLock()
  private let failFirstSave: Bool
  private let requiresKDFConfirmation: Bool
  private var mutableEditCount = 0
  private var mutableSaveCount = 0
  private var currentDraft = EntryDraft(
    id: "entry",
    title: "Example",
    username: "alice",
    password: "secret",
    url: "https://example.com",
    notes: "initial",
    totpURI: "",
    customFields: [],
    attachments: [],
    passkeyRelyingParty: nil
  )

  init(failFirstSave: Bool = false, requiresKDFConfirmation: Bool = false) {
    self.failFirstSave = failFirstSave
    self.requiresKDFConfirmation = requiresKDFConfirmation
  }

  var editCount: Int { lock.withLock { mutableEditCount } }
  var saveCount: Int { lock.withLock { mutableSaveCount } }

  func openVault(path: String) throws -> VaultHandleDto {
    VaultHandleDto(vaultId: "vault", name: "Test", path: path)
  }

  func sessionState() throws -> SessionStateDto { state(unlocked: false) }

  func unlockVault(
    vaultID: String,
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto {
    if requiresKDFConfirmation && !kdfConfirmed {
      throw VaultKernError.KdfConfirmationRequired(
        algorithm: "Argon2id",
        resource: "memory_kib",
        observed: 300_000,
        limit: 262_144
      )
    }
    return state(unlocked: true)
  }

  func unlockWithBlob(kdfConfirmed: Bool) throws -> UnlockBlobResultDto {
    UnlockBlobResultDto(status: .notEnrolled, state: state(unlocked: false))
  }

  func enroll(
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto { state(unlocked: true) }

  func revoke() throws -> SessionStateDto { state(unlocked: true) }
  func lockSession() throws -> SessionStateDto { state(unlocked: false) }
  func closeVault(vaultID: String) throws -> SessionStateDto { state(unlocked: false) }

  func listEntries(vaultID: String) throws -> [EntrySummaryDto] {
    [
      EntrySummaryDto(
        id: "entry",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "root",
        hasTotp: false
      )
    ]
  }

  func readEntry(vaultID: String, entryID: String) throws -> EntryDraft {
    lock.withLock { currentDraft }
  }

  func editEntry(
    vaultID: String,
    entryID: String,
    fields: OwnedEntryFields
  ) throws -> EntryDraft {
    defer { fields.close() }
    return lock.withLock {
      mutableEditCount += 1
      currentDraft.notes = "changed"
      return currentDraft
    }
  }

  func save(vaultID: String) throws -> SaveVaultResultDto {
    try lock.withLock {
      mutableSaveCount += 1
      if failFirstSave && mutableSaveCount == 1 {
        throw ModelTestError.saveFailed
      }
      return SaveVaultResultDto(status: .saved, mergeSummary: nil, conflictCopyPath: nil)
    }
  }

  private func state(unlocked: Bool) -> SessionStateDto {
    SessionStateDto(
      unlocked: unlocked,
      activeVaultId: unlocked ? "vault" : nil,
      currentVaultRefId: nil,
      supportsBiometricUnlock: false,
      sourceStatus: nil
    )
  }
}

private enum ModelTestError: LocalizedError {
  case saveFailed

  var errorDescription: String? { "simulated save failure" }
}
