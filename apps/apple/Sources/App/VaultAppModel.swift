import Combine
import Foundation

struct KDFConfirmationPrompt: Identifiable, Equatable {
  let id = UUID()
  let message: String
}

enum OneDriveBrowserState: Equatable, Sendable {
  case idle
  case checking
  case needsAuthorization
  case authorizing
  case awaitingCallback
  case browsing(accountLabel: String?)
  case failed(message: String)
}

struct OneDriveFolderLevel: Identifiable, Equatable, Sendable {
  let id: String
  let name: String
  let itemID: String?

  static let root = OneDriveFolderLevel(id: "root", name: "OneDrive", itemID: nil)
}

@MainActor
final class VaultAppModel: ObservableObject {
  @Published private(set) var bootError: String?
  @Published private(set) var currentVault: VaultHandleDto?
  @Published private(set) var selectedRemoteVault: VaultReferenceDto?
  @Published private(set) var entries: [EntrySummaryDto] = []
  @Published private(set) var selectedEntryID: String?
  @Published private(set) var draft: EntryDraft?
  @Published private(set) var saveProgress: SaveProgress = .clean
  @Published private(set) var isBusy = false
  @Published private(set) var isUnlocked = false
  @Published private(set) var supportsBiometricUnlock = false
  @Published private(set) var quickUnlockKnownEnrolled: Bool?
  @Published private(set) var sourceStatus: VaultSourceStatusDto?
  @Published private(set) var oneDriveBrowserState: OneDriveBrowserState = .idle
  @Published private(set) var oneDriveItems: [OneDriveItemDto] = []
  @Published private(set) var oneDriveFolders: [OneDriveFolderLevel] = [.root]
  @Published private(set) var oneDriveAuthorizationURL: URL?
  @Published var errorMessage: String?
  @Published var noticeMessage: String?
  @Published var kdfPrompt: KDFConfirmationPrompt?

  private let runtime: (any VaultRuntimeClient)?
  private let scopedAccess = SecurityScopedAccess()
  private var vaultURL: URL?
  private var loadedVaultID: String?
  private var pendingKDF: PendingKDFOperation?
  private var residentIPC: ResidentIPCController?

  init() {
    do {
      let liveRuntime = try LiveVaultRuntimeClient(configuration: AppConfiguration.live())
      let reference = try liveRuntime.currentVaultReference()
      let state = try liveRuntime.sessionState()
      runtime = liveRuntime
      bootError = nil
      if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil {
        let controller = ResidentIPCController {
          liveRuntime.makeProtocolSession()
        }
        do {
          try controller.start()
          residentIPC = controller
        } catch {
          fputs("VaultKern native messaging unavailable: \(error.localizedDescription)\n", stderr)
        }
      }
      apply(state)
      if let reference, reference.sourceKind == "onedrive" {
        selectedRemoteVault = reference
        quickUnlockKnownEnrolled = reference.supportsQuickUnlock
      }
    } catch {
      runtime = nil
      bootError = Self.describe(error)
    }
  }

  init(runtime: any VaultRuntimeClient) {
    self.runtime = runtime
    bootError = nil
  }

  var hasUncommittedChanges: Bool { saveProgress.hasUncommittedChanges }

  var hasSelectedVault: Bool { currentVault != nil || selectedRemoteVault != nil }

  var selectedVaultName: String? {
    currentVault?.name ?? selectedRemoteVault?.displayName
  }

  var isRemoteVault: Bool { selectedRemoteVault != nil }

  var canChangeVault: Bool {
    !isBusy && !saveProgress.hasUncommittedChanges && pendingKDF == nil
  }

  func openVault(_ url: URL) async {
    guard let runtime, beginOperation() else { return }
    defer { endOperation() }
    guard !hasSelectedVault else {
      errorMessage = "Close the current vault before opening another one."
      return
    }

    scopedAccess.retain(url)
    do {
      let opened = try await BackgroundWork.run {
        let handle = try runtime.openVault(path: url.path)
        do {
          return OpenedVault(handle: handle, state: try runtime.sessionState())
        } catch {
          _ = try? runtime.closeVault(vaultID: handle.vaultId)
          throw error
        }
      }
      vaultURL = url
      currentVault = opened.handle
      selectedRemoteVault = nil
      loadedVaultID = opened.handle.vaultId
      apply(opened.state)
      quickUnlockKnownEnrolled = nil
      noticeMessage = nil
      errorMessage = nil
    } catch {
      scopedAccess.release(url)
      errorMessage = Self.describe(error)
    }
  }

  func unlockWithPassword(
    _ password: VaultKernSensitiveString?,
    keyFileURL: URL?
  ) async {
    guard let runtime, let target = unlockTarget, beginOperation() else {
      password?.close()
      return
    }
    defer { endOperation() }
    if let keyFileURL {
      scopedAccess.retain(keyFileURL)
    }

    do {
      let state = try await BackgroundWork.run {
        try target.unlock(
          runtime: runtime,
          password: password,
          keyFilePath: keyFileURL?.path,
          kdfConfirmed: false
        )
      }
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
      try await finishUnlock(state, runtime: runtime)
    } catch let error as VaultKernError {
      if captureKDFConfirmation(
        error,
        operation: .unlock(target: target, password: password, keyFileURL: keyFileURL)
      ) {
        return
      }
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
      errorMessage = Self.describe(error)
    } catch {
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
      errorMessage = Self.describe(error)
    }
  }

  func unlockWithBiometrics() async {
    guard let runtime, hasSelectedVault, beginOperation() else { return }
    defer { endOperation() }
    do {
      let result = try await BackgroundWork.run {
        try runtime.unlockWithBlob(kdfConfirmed: false)
      }
      try await handleBlobResult(result, runtime: runtime)
    } catch let error as VaultKernError {
      if captureKDFConfirmation(error, operation: .unlockBlob) {
        return
      }
      errorMessage = Self.describe(error)
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func enrollQuickUnlock(
    password: VaultKernSensitiveString?,
    keyFileURL: URL?
  ) async {
    guard let runtime, isUnlocked, beginOperation() else {
      password?.close()
      return
    }
    defer { endOperation() }
    if let keyFileURL {
      scopedAccess.retain(keyFileURL)
    }
    do {
      let state = try await BackgroundWork.run {
        try runtime.enroll(
          password: password,
          keyFilePath: keyFileURL?.path,
          kdfConfirmed: false
        )
      }
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
      apply(state)
      quickUnlockKnownEnrolled = true
      noticeMessage = "Touch ID quick unlock is enabled."
      errorMessage = nil
    } catch let error as VaultKernError {
      if captureKDFConfirmation(
        error,
        operation: .enroll(password: password, keyFileURL: keyFileURL)
      ) {
        return
      }
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
      errorMessage = Self.describe(error)
    } catch {
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
      errorMessage = Self.describe(error)
    }
  }

  func revokeQuickUnlock() async {
    guard let runtime, isUnlocked, beginOperation() else { return }
    defer { endOperation() }
    do {
      let state = try await BackgroundWork.run { try runtime.revoke() }
      apply(state)
      quickUnlockKnownEnrolled = false
      noticeMessage = "Touch ID quick unlock is disabled."
      errorMessage = nil
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func confirmKDF() async {
    guard let runtime, let operation = pendingKDF, beginOperation(allowPendingKDF: true) else {
      return
    }
    pendingKDF = nil
    kdfPrompt = nil
    defer {
      operation.close(using: scopedAccess)
      endOperation()
    }

    do {
      switch operation {
      case .unlock(let target, let password, let keyFileURL):
        let state = try await BackgroundWork.run {
          try target.unlock(
            runtime: runtime,
            password: password,
            keyFilePath: keyFileURL?.path,
            kdfConfirmed: true
          )
        }
        try await finishUnlock(state, runtime: runtime)
      case .unlockBlob:
        let result = try await BackgroundWork.run {
          try runtime.unlockWithBlob(kdfConfirmed: true)
        }
        try await handleBlobResult(result, runtime: runtime)
      case .enroll(let password, let keyFileURL):
        let state = try await BackgroundWork.run {
          try runtime.enroll(
            password: password,
            keyFilePath: keyFileURL?.path,
            kdfConfirmed: true
          )
        }
        apply(state)
        quickUnlockKnownEnrolled = true
        noticeMessage = "Touch ID quick unlock is enabled."
      }
      errorMessage = nil
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func cancelKDF() {
    guard let operation = pendingKDF else { return }
    pendingKDF = nil
    kdfPrompt = nil
    operation.close(using: scopedAccess)
  }

  func prepareOneDriveBrowser() async {
    guard let runtime, !hasSelectedVault, beginOperation() else { return }
    oneDriveBrowserState = .checking
    defer { endOperation() }
    do {
      let items = try await BackgroundWork.run {
        try runtime.listOneDriveChildren(parentItemID: nil)
      }
      oneDriveFolders = [.root]
      oneDriveItems = Self.selectableOneDriveItems(items)
      oneDriveBrowserState = .browsing(accountLabel: nil)
    } catch {
      oneDriveItems = []
      oneDriveFolders = [.root]
      oneDriveBrowserState = .needsAuthorization
    }
  }

  func beginOneDriveLogin() async -> URL? {
    guard let runtime, !hasSelectedVault, beginOperation() else { return nil }
    oneDriveAuthorizationURL = nil
    oneDriveBrowserState = .authorizing
    defer { endOperation() }
    do {
      let session = try await BackgroundWork.run { try runtime.beginOneDriveLogin() }
      guard
        let url = URL(string: session.authUrl),
        url.scheme == "https",
        url.host == "login.microsoftonline.com"
      else {
        throw OneDrivePresentationError.invalidAuthorizationURL
      }
      oneDriveAuthorizationURL = url
      return url
    } catch {
      oneDriveAuthorizationURL = nil
      let message = Self.describe(error)
      oneDriveBrowserState = .failed(message: message)
      return nil
    }
  }

  func completeOneDriveLogin() async {
    guard let runtime, !hasSelectedVault, beginOperation() else { return }
    oneDriveBrowserState = .authorizing
    defer { endOperation() }
    do {
      let status = try await BackgroundWork.run {
        try runtime.completePendingOneDriveLogin()
      }
      oneDriveAuthorizationURL = nil
      oneDriveBrowserState = .browsing(accountLabel: status.accountLabel)
      let items = try await BackgroundWork.run {
        try runtime.listOneDriveChildren(parentItemID: nil)
      }
      oneDriveFolders = [.root]
      oneDriveItems = Self.selectableOneDriveItems(items)
      errorMessage = nil
    } catch {
      oneDriveAuthorizationURL = nil
      let message = Self.describe(error)
      oneDriveBrowserState = .failed(message: message)
    }
  }

  func oneDriveAuthorizationBrowserDidOpen() {
    guard oneDriveAuthorizationURL != nil else { return }
    oneDriveBrowserState = .awaitingCallback
  }

  func oneDriveAuthorizationBrowserDidNotOpen() {
    guard oneDriveAuthorizationURL != nil else { return }
    oneDriveBrowserState = .awaitingCallback
  }

  func enterOneDriveFolder(_ item: OneDriveItemDto) async {
    guard item.folder, let runtime, beginOperation() else { return }
    defer { endOperation() }
    do {
      let items = try await BackgroundWork.run {
        try runtime.listOneDriveChildren(parentItemID: item.itemId)
      }
      oneDriveFolders.append(
        OneDriveFolderLevel(id: item.itemId, name: item.name, itemID: item.itemId)
      )
      oneDriveItems = Self.selectableOneDriveItems(items)
      errorMessage = nil
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func leaveOneDriveFolder() async {
    guard oneDriveFolders.count > 1, let runtime, beginOperation() else { return }
    let parent = oneDriveFolders[oneDriveFolders.count - 2]
    defer { endOperation() }
    do {
      let items = try await BackgroundWork.run {
        try runtime.listOneDriveChildren(parentItemID: parent.itemID)
      }
      oneDriveFolders.removeLast()
      oneDriveItems = Self.selectableOneDriveItems(items)
      errorMessage = nil
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func selectOneDriveVault(_ item: OneDriveItemDto) async -> Bool {
    guard
      !item.folder,
      item.name.lowercased().hasSuffix(".kdbx"),
      let runtime,
      !hasSelectedVault,
      beginOperation()
    else { return false }
    defer { endOperation() }
    do {
      let reference = try await BackgroundWork.run {
        try runtime.addOneDriveVault(
          driveID: item.driveId,
          itemID: item.itemId
        )
      }
      clearDraft()
      entries = []
      selectedEntryID = nil
      currentVault = nil
      selectedRemoteVault = reference
      loadedVaultID = nil
      vaultURL = nil
      isUnlocked = false
      if let state = try? await BackgroundWork.run({ try runtime.sessionState() }) {
        apply(state)
      } else {
        sourceStatus = try? await BackgroundWork.run { try runtime.syncStatus() }
      }
      quickUnlockKnownEnrolled = reference.supportsQuickUnlock
      oneDriveItems = []
      oneDriveFolders = [.root]
      oneDriveAuthorizationURL = nil
      oneDriveBrowserState = .idle
      noticeMessage = nil
      errorMessage = nil
      return true
    } catch {
      errorMessage = Self.describe(error)
      return false
    }
  }

  func resetOneDriveBrowser() {
    guard
      oneDriveBrowserState != .authorizing,
      oneDriveBrowserState != .awaitingCallback
    else { return }
    oneDriveItems = []
    oneDriveFolders = [.root]
    oneDriveAuthorizationURL = nil
    oneDriveBrowserState = .idle
  }

  func selectEntry(_ entryID: String) async {
    guard let runtime, let vaultID = activeVaultID, beginOperation() else { return }
    defer { endOperation() }
    guard saveProgress == .clean else {
      errorMessage = "Save or discard the current draft first."
      return
    }
    if selectedEntryID == entryID, draft != nil { return }

    clearDraft()
    selectedEntryID = entryID
    do {
      let loaded = try await BackgroundWork.run {
        try runtime.readEntry(vaultID: vaultID, entryID: entryID)
      }
      draft = loaded
      errorMessage = nil
    } catch {
      selectedEntryID = nil
      errorMessage = Self.describe(error)
    }
  }

  func refreshEntries() async {
    guard let runtime, let vaultID = activeVaultID, beginOperation() else { return }
    defer { endOperation() }
    guard !saveProgress.hasUncommittedChanges else {
      errorMessage = "Save the current entry before refreshing."
      return
    }
    do {
      entries = try await BackgroundWork.run { try runtime.listEntries(vaultID: vaultID) }
      if let selectedEntryID {
        let loaded = try await BackgroundWork.run {
          try runtime.readEntry(vaultID: vaultID, entryID: selectedEntryID)
        }
        replaceDraft(with: loaded)
      }
      errorMessage = nil
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func syncCurrentVault() async {
    guard
      let runtime,
      isRemoteVault,
      let vaultID = activeVaultID,
      !saveProgress.hasUncommittedChanges,
      beginOperation()
    else { return }
    defer { endOperation() }
    let selectedEntryID = selectedEntryID
    do {
      sourceStatus = try await BackgroundWork.run {
        try runtime.sync(vaultID: vaultID)
      }
    } catch {
      errorMessage = Self.describe(error)
      return
    }

    do {
      let snapshot = try await BackgroundWork.run {
        let entries = try runtime.listEntries(vaultID: vaultID)
        let draft = try selectedEntryID.map {
          try runtime.readEntry(vaultID: vaultID, entryID: $0)
        }
        return SyncedVaultSnapshot(entries: entries, draft: draft)
      }
      entries = snapshot.entries
      if let draft = snapshot.draft {
        replaceDraft(with: draft)
      }
      noticeMessage = "OneDrive sync finished."
      errorMessage = nil
    } catch {
      errorMessage =
        "OneDrive sync finished, but refreshing the view failed: \(Self.describe(error))"
    }
  }

  func updateDraft<Value>(_ keyPath: WritableKeyPath<EntryDraft, Value>, value: Value) {
    guard !isBusy, saveProgress != .staged, draft != nil else { return }
    draft?[keyPath: keyPath] = value
    saveProgress.markDraftChanged()
  }

  func updateCustomField(_ field: EntryCustomFieldDraft) {
    guard !isBusy, saveProgress != .staged, var draft else { return }
    guard let index = draft.customFields.firstIndex(where: { $0.id == field.id }) else { return }
    draft.customFields[index] = field
    self.draft = draft
    saveProgress.markDraftChanged()
  }

  func addCustomField() {
    guard !isBusy, saveProgress != .staged, var draft else { return }
    draft.customFields.append(
      EntryCustomFieldDraft(key: "", value: "", isProtected: false)
    )
    self.draft = draft
    saveProgress.markDraftChanged()
  }

  func removeCustomField(id: UUID) {
    guard !isBusy, saveProgress != .staged, var draft else { return }
    guard let index = draft.customFields.firstIndex(where: { $0.id == id }) else { return }
    draft.customFields[index].key.removeAll(keepingCapacity: false)
    draft.customFields[index].value.removeAll(keepingCapacity: false)
    draft.customFields.remove(at: index)
    self.draft = draft
    saveProgress.markDraftChanged()
  }

  func saveDraft() async {
    guard let runtime, let vaultID = activeVaultID, let draft, beginOperation() else { return }
    defer { endOperation() }

    if saveProgress.shouldApplyDraft {
      let ownedFields = OwnedEntryFields(draft: draft)
      do {
        let stagedDraft = try await BackgroundWork.run {
          defer { ownedFields.close() }
          return try runtime.editEntry(
            vaultID: vaultID,
            entryID: draft.id,
            fields: ownedFields
          )
        }
        replaceDraft(with: stagedDraft)
        saveProgress.markEditApplied()
      } catch {
        ownedFields.close()
        errorMessage = Self.describe(error)
        return
      }
    }

    guard saveProgress == .staged else { return }
    do {
      let result = try await BackgroundWork.run { try runtime.save(vaultID: vaultID) }
      saveProgress.markSaveSucceeded()
      noticeMessage = Self.describe(result)
      errorMessage = nil
    } catch {
      // The runtime mutation is already staged. Retain that state so retrying
      // invokes save only and never applies the same edit twice.
      errorMessage = Self.describe(error)
      return
    }

    do {
      try await reloadAfterCommittedSave(runtime: runtime, vaultID: vaultID)
      sourceStatus = try await BackgroundWork.run { try runtime.syncStatus() }
    } catch {
      errorMessage = "The save committed, but refreshing the view failed: \(Self.describe(error))"
    }
  }

  func discardDraft() async {
    guard saveProgress == .dirty, let entryID = selectedEntryID else { return }
    saveProgress.discardDraft()
    clearDraft()
    await selectEntry(entryID)
  }

  func lockVault() async {
    guard let runtime, beginOperation() else { return }
    defer { endOperation() }
    guard !saveProgress.hasUncommittedChanges else {
      errorMessage = "Save the current entry before locking the vault."
      return
    }
    do {
      let state = try await BackgroundWork.run { try runtime.lockSession() }
      apply(state)
      entries.removeAll(keepingCapacity: false)
      selectedEntryID = nil
      clearDraft()
      noticeMessage = nil
      errorMessage = nil
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func closeVault() async {
    guard let runtime, hasSelectedVault, !isRemoteVault, beginOperation() else { return }
    defer { endOperation() }
    guard !saveProgress.hasUncommittedChanges else {
      errorMessage = "Save the current entry before closing the vault."
      return
    }
    do {
      let state: SessionStateDto
      if let loadedVaultID {
        state = try await BackgroundWork.run {
          try runtime.closeVault(vaultID: loadedVaultID)
        }
      } else {
        state = try await BackgroundWork.run { try runtime.sessionState() }
      }
      clearDraft()
      entries.removeAll(keepingCapacity: false)
      selectedEntryID = nil
      currentVault = nil
      selectedRemoteVault = nil
      self.loadedVaultID = nil
      apply(state)
      sourceStatus = nil
      quickUnlockKnownEnrolled = nil
      if let vaultURL {
        scopedAccess.release(vaultURL)
      }
      self.vaultURL = nil
      noticeMessage = nil
      errorMessage = nil
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  private var activeVaultID: String? {
    guard isUnlocked else { return nil }
    return loadedVaultID
  }

  private var unlockTarget: UnlockTarget? {
    if selectedRemoteVault != nil {
      return .currentReference
    }
    return currentVault.map { .vault($0.vaultId) }
  }

  private func beginOperation(allowPendingKDF: Bool = false) -> Bool {
    guard !isBusy, allowPendingKDF || pendingKDF == nil else { return false }
    isBusy = true
    return true
  }

  private func endOperation() {
    isBusy = false
  }

  private func finishUnlock(
    _ state: SessionStateDto,
    runtime: any VaultRuntimeClient
  ) async throws {
    apply(state)
    guard state.unlocked, let vaultID = state.activeVaultId else {
      throw VaultKernError.StateUnavailable
    }
    entries = try await BackgroundWork.run { try runtime.listEntries(vaultID: vaultID) }
    noticeMessage = nil
    errorMessage = nil
  }

  private func handleBlobResult(
    _ result: UnlockBlobResultDto,
    runtime: any VaultRuntimeClient
  ) async throws {
    apply(result.state)
    switch result.status {
    case .unlocked:
      quickUnlockKnownEnrolled = true
      try await finishUnlock(result.state, runtime: runtime)
    case .notEnrolled:
      quickUnlockKnownEnrolled = false
      noticeMessage = "Touch ID quick unlock is not enrolled."
    case .cancelled:
      noticeMessage = nil
    case .openAppRequired:
      errorMessage = "Quick unlock needs one password unlock to refresh its cached key."
    case .credentialRequired:
      errorMessage = "The stored credential is stale. Unlock with the current master credential."
    case .unsupported:
      errorMessage = "Touch ID quick unlock is unavailable on this Mac."
    }
  }

  private func apply(_ state: SessionStateDto) {
    isUnlocked = state.unlocked
    supportsBiometricUnlock = state.supportsBiometricUnlock
    sourceStatus = state.sourceStatus
    if let activeVaultID = state.activeVaultId {
      loadedVaultID = activeVaultID
    }
  }

  private func captureKDFConfirmation(
    _ error: VaultKernError,
    operation: PendingKDFOperation
  ) -> Bool {
    guard
      case .KdfConfirmationRequired(let algorithm, let resource, let observed, let limit) = error
    else { return false }
    pendingKDF = operation
    kdfPrompt = KDFConfirmationPrompt(
      message:
        "This vault requests \(algorithm) \(resource) = \(observed), above the desktop confirmation limit \(limit). Continue?"
    )
    return true
  }

  private func reloadAfterCommittedSave(
    runtime: any VaultRuntimeClient,
    vaultID: String
  ) async throws {
    entries = try await BackgroundWork.run { try runtime.listEntries(vaultID: vaultID) }
    guard let selectedEntryID else { return }
    let loaded = try await BackgroundWork.run {
      try runtime.readEntry(vaultID: vaultID, entryID: selectedEntryID)
    }
    replaceDraft(with: loaded)
  }

  private func replaceDraft(with replacement: EntryDraft) {
    clearDraft()
    draft = replacement
  }

  private func clearDraft() {
    draft?.clear()
    draft = nil
  }

  private static func describe(_ result: SaveVaultResultDto) -> String {
    switch result.status {
    case .saved:
      "Saved to the vault."
    case .merged:
      "Saved after rebasing concurrent changes."
    case .savedToCache:
      "Saved locally; remote sync is pending."
    case .conflictCopy:
      result.conflictCopyPath.map { "Saved a conflict copy at \($0)." }
        ?? "Saved a conflict copy."
    }
  }

  private static func selectableOneDriveItems(
    _ items: [OneDriveItemDto]
  ) -> [OneDriveItemDto] {
    items
      .filter { $0.folder || $0.name.lowercased().hasSuffix(".kdbx") }
      .sorted {
        if $0.folder != $1.folder {
          return $0.folder
        }
        return $0.name.localizedStandardCompare($1.name) == .orderedAscending
      }
  }

  private static func describe(_ error: Error) -> String {
    if let error = error as? LocalizedError, let description = error.errorDescription {
      return description
    }
    return "The operation failed."
  }
}

private enum PendingKDFOperation {
  case unlock(
    target: UnlockTarget,
    password: VaultKernSensitiveString?,
    keyFileURL: URL?
  )
  case unlockBlob
  case enroll(password: VaultKernSensitiveString?, keyFileURL: URL?)

  @MainActor
  func close(using scopedAccess: SecurityScopedAccess) {
    switch self {
    case .unlock(_, let password, let keyFileURL),
      .enroll(let password, let keyFileURL):
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
    case .unlockBlob:
      break
    }
  }
}

private enum UnlockTarget: Sendable {
  case currentReference
  case vault(String)

  func unlock(
    runtime: any VaultRuntimeClient,
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto {
    switch self {
    case .currentReference:
      try runtime.unlockCurrent(
        password: password,
        keyFilePath: keyFilePath,
        kdfConfirmed: kdfConfirmed
      )
    case .vault(let vaultID):
      try runtime.unlockVault(
        vaultID: vaultID,
        password: password,
        keyFilePath: keyFilePath,
        kdfConfirmed: kdfConfirmed
      )
    }
  }
}

private struct OpenedVault: Sendable {
  let handle: VaultHandleDto
  let state: SessionStateDto
}

private struct SyncedVaultSnapshot: Sendable {
  let entries: [EntrySummaryDto]
  let draft: EntryDraft?
}

private enum OneDrivePresentationError: LocalizedError {
  case invalidAuthorizationURL

  var errorDescription: String? {
    "OneDrive returned an invalid authorization URL."
  }
}
