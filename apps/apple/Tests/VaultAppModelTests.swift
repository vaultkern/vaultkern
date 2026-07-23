import AppKit
import Foundation
import XCTest

@testable import VaultKern

@MainActor
final class VaultAppModelTests: XCTestCase {
  func testQuickUnlockDesiredStatePersistsAcrossStoreInstances() throws {
    let suiteName = "VaultKernTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
    defer { defaults.removePersistentDomain(forName: suiteName) }
    let first = UserDefaultsQuickUnlockSettingsStore(defaults: defaults)

    first.setEnabled(true)

    let reopened = UserDefaultsQuickUnlockSettingsStore(defaults: defaults)
    XCTAssertTrue(reopened.isEnabled)
  }

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
    XCTAssertEqual(model.terminationRisk, .stagedSave)
    XCTAssertEqual(runtime.editCount, 1)
    XCTAssertEqual(runtime.saveCount, 1)
    XCTAssertEqual(password.reveal(), "")

    await model.saveDraft()
    XCTAssertEqual(model.saveProgress, .clean)
    XCTAssertNil(model.terminationRisk)
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
    XCTAssertEqual(model.terminationRisk, .kdfConfirmation)
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

  func testStartupReconciliationPurgesQuickUnlockWhenDesiredStateIsDisabled() async {
    let runtime = ModelTestRuntime()
    let settings = VolatileQuickUnlockSettingsStore(isEnabled: false)
    let model = VaultAppModel(runtime: runtime, quickUnlockSettings: settings)

    await model.reconcileStartupSettings()

    XCTAssertEqual(runtime.reconcileCount, 1)
    XCTAssertEqual(runtime.lastReconcileEnabled, false)
    XCTAssertFalse(model.isUnlocked)
  }

  func testPasswordUnlockReconcilesPersistedQuickUnlockIntentBeforeClearingCredential()
    async throws
  {
    let runtime = ModelTestRuntime()
    let settings = VolatileQuickUnlockSettingsStore(isEnabled: true)
    let model = VaultAppModel(runtime: runtime, quickUnlockSettings: settings)
    try await openTestVault(model)
    let password = VaultKernSensitiveString("master-password")

    await model.unlockWithPassword(password, keyFileURL: nil)

    XCTAssertTrue(settings.isEnabled)
    XCTAssertTrue(model.quickUnlockDesiredEnabled)
    XCTAssertEqual(runtime.reconcileCount, 1)
    XCTAssertEqual(runtime.lastReconcileEnabled, true)
    XCTAssertEqual(runtime.lastReconcileHadPassword, true)
    XCTAssertEqual(password.reveal(), "")
  }

  func testStaleBiometricCredentialIsReconciledByNextPasswordUnlock() async throws {
    let runtime = ModelTestRuntime(blobStatus: .credentialRequired)
    let settings = VolatileQuickUnlockSettingsStore(isEnabled: true)
    let model = VaultAppModel(runtime: runtime, quickUnlockSettings: settings)
    try await openTestVault(model)

    await model.unlockWithBiometrics()
    XCTAssertEqual(model.quickUnlockKnownEnrolled, false)
    XCTAssertEqual(runtime.reconcileCount, 0)

    let password = VaultKernSensitiveString("current-password")
    await model.unlockWithPassword(password, keyFileURL: nil)

    XCTAssertEqual(runtime.reconcileCount, 1)
    XCTAssertEqual(runtime.lastReconcileEnabled, true)
    XCTAssertEqual(runtime.lastReconcileHadPassword, true)
    XCTAssertEqual(model.quickUnlockKnownEnrolled, true)
    XCTAssertEqual(password.reveal(), "")
  }

  func testEnabledQuickUnlockDoesNotClaimEnrollmentWhenPlatformIsUnsupported() async throws {
    let runtime = ModelTestRuntime(supportsQuickUnlock: false)
    let settings = VolatileQuickUnlockSettingsStore(isEnabled: true)
    let model = VaultAppModel(runtime: runtime, quickUnlockSettings: settings)
    try await openTestVault(model)

    await model.unlockWithPassword(
      VaultKernSensitiveString("master-password"),
      keyFileURL: nil
    )

    XCTAssertNil(model.quickUnlockKnownEnrolled)
    XCTAssertEqual(runtime.reconcileCount, 1)
  }

  func testDisablingQuickUnlockPersistsIntentBeforeReconciliation() async throws {
    let runtime = ModelTestRuntime()
    let settings = VolatileQuickUnlockSettingsStore(isEnabled: true)
    let model = VaultAppModel(runtime: runtime, quickUnlockSettings: settings)
    try await openTestVault(model)
    await model.unlockWithPassword(
      VaultKernSensitiveString("master-password"),
      keyFileURL: nil
    )

    await model.disableQuickUnlock()

    XCTAssertFalse(settings.isEnabled)
    XCTAssertFalse(model.quickUnlockDesiredEnabled)
    XCTAssertEqual(runtime.lastReconcileEnabled, false)
    XCTAssertEqual(model.quickUnlockKnownEnrolled, false)
  }

  func testDisablingQuickUnlockReconcilesImmediatelyWhileVaultIsLocked() async {
    let runtime = ModelTestRuntime()
    let settings = VolatileQuickUnlockSettingsStore(isEnabled: true)
    let model = VaultAppModel(runtime: runtime, quickUnlockSettings: settings)

    await model.disableQuickUnlock()

    XCTAssertFalse(settings.isEnabled)
    XCTAssertEqual(runtime.reconcileCount, 1)
    XCTAssertEqual(runtime.lastReconcileEnabled, false)
  }

  func testTerminationRequiresExplicitConfirmationForDirtyDraft() async throws {
    let runtime = ModelTestRuntime()
    let model = VaultAppModel(runtime: runtime)
    try await openTestVault(model)
    await model.unlockWithPassword(
      VaultKernSensitiveString("master-password"),
      keyFileURL: nil
    )
    await model.selectEntry("entry")
    model.updateDraft(\.notes, value: "unsaved")
    let appDelegate = VaultKernAppDelegate()

    appDelegate.confirmsTermination = { _ in false }
    XCTAssertEqual(appDelegate.terminationReply(for: model), .terminateCancel)

    appDelegate.confirmsTermination = { risk in
      XCTAssertEqual(risk, .dirtyDraft)
      return true
    }
    XCTAssertEqual(appDelegate.terminationReply(for: model), .terminateNow)
  }

  func testCredentialSubmissionReservationClosesTheTaskSchedulingGap() async {
    let model = VaultAppModel(runtime: ModelTestRuntime())

    XCTAssertTrue(model.registerCredentialSubmission())
    XCTAssertFalse(model.registerCredentialSubmission())
    XCTAssertEqual(model.terminationRisk, .operationInProgress)

    await model.unlockWithBiometrics()
    XCTAssertFalse(model.hasPendingCredentialSubmission)
    XCTAssertNil(model.terminationRisk)
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
  private let blobStatus: UnlockBlobStatusDto
  private let supportsQuickUnlock: Bool
  private var mutableEditCount = 0
  private var mutableSaveCount = 0
  private var mutableReconcileCount = 0
  private var mutableLastReconcileEnabled: Bool?
  private var mutableLastReconcileHadPassword: Bool?
  private var mutableUnlocked = false
  private var currentNotes = "initial"

  init(
    failFirstSave: Bool = false,
    requiresKDFConfirmation: Bool = false,
    blobStatus: UnlockBlobStatusDto = .notEnrolled,
    supportsQuickUnlock: Bool = true
  ) {
    self.failFirstSave = failFirstSave
    self.requiresKDFConfirmation = requiresKDFConfirmation
    self.blobStatus = blobStatus
    self.supportsQuickUnlock = supportsQuickUnlock
  }

  var editCount: Int { lock.withLock { mutableEditCount } }
  var saveCount: Int { lock.withLock { mutableSaveCount } }
  var reconcileCount: Int { lock.withLock { mutableReconcileCount } }
  var lastReconcileEnabled: Bool? { lock.withLock { mutableLastReconcileEnabled } }
  var lastReconcileHadPassword: Bool? {
    lock.withLock { mutableLastReconcileHadPassword }
  }

  func openVault(path: String) throws -> VaultHandleDto {
    VaultHandleDto(vaultId: "vault", name: "Test", path: path)
  }

  func sessionState() throws -> SessionStateDto {
    lock.withLock { state(unlocked: mutableUnlocked) }
  }

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
    lock.withLock { mutableUnlocked = true }
    return state(unlocked: true)
  }

  func unlockWithBlob(kdfConfirmed: Bool) throws -> UnlockBlobResultDto {
    lock.withLock { mutableUnlocked = blobStatus == .unlocked }
    return UnlockBlobResultDto(
      status: blobStatus,
      state: state(unlocked: blobStatus == .unlocked)
    )
  }

  func reconcileQuickUnlock(
    enabled: Bool,
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto {
    lock.withLock {
      mutableReconcileCount += 1
      mutableLastReconcileEnabled = enabled
      mutableLastReconcileHadPassword = password != nil
      return state(unlocked: mutableUnlocked)
    }
  }

  func lockSession() throws -> SessionStateDto {
    lock.withLock {
      mutableUnlocked = false
      return state(unlocked: false)
    }
  }

  func closeVault(vaultID: String) throws -> SessionStateDto {
    lock.withLock {
      mutableUnlocked = false
      return state(unlocked: false)
    }
  }

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
    lock.withLock { makeDraft(notes: currentNotes) }
  }

  func editEntry(
    vaultID: String,
    entryID: String,
    fields: OwnedEntryFields
  ) throws -> EntryDraft {
    defer { fields.close() }
    return lock.withLock {
      mutableEditCount += 1
      currentNotes = fields.value.notes.reveal()
      return makeDraft(notes: currentNotes)
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
      supportsBiometricUnlock: supportsQuickUnlock,
      sourceStatus: nil
    )
  }

  private func makeDraft(notes: String) -> EntryDraft {
    EntryDraft(
      id: "entry",
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: notes,
      totpURI: "",
      customFields: [],
      attachments: [],
      passkeyRelyingParty: nil
    )
  }
}

private enum ModelTestError: LocalizedError {
  case saveFailed

  var errorDescription: String? { "simulated save failure" }
}
