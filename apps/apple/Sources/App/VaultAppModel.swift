import Combine
import Foundation

struct KDFConfirmationPrompt: Identifiable, Equatable {
  let id = UUID()
  let message: String
}

@MainActor
final class VaultAppModel: ObservableObject {
  @Published private(set) var bootError: String?
  @Published private(set) var currentVault: VaultHandleDto?
  @Published private(set) var entries: [EntrySummaryDto] = []
  @Published private(set) var selectedEntryID: String?
  @Published private(set) var draft: EntryDraft?
  @Published private(set) var saveProgress: SaveProgress = .clean
  @Published private(set) var isBusy = false
  @Published private(set) var isUnlocked = false
  @Published private(set) var supportsBiometricUnlock = false
  @Published private(set) var quickUnlockKnownEnrolled: Bool?
  @Published var errorMessage: String?
  @Published var noticeMessage: String?
  @Published var kdfPrompt: KDFConfirmationPrompt?

  private let runtime: (any VaultRuntimeClient)?
  private let scopedAccess = SecurityScopedAccess()
  private var vaultURL: URL?
  private var pendingKDF: PendingKDFOperation?

  init() {
    do {
      runtime = try LiveVaultRuntimeClient(configuration: AppConfiguration.live())
      bootError = nil
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

  var canChangeVault: Bool {
    !isBusy && !saveProgress.hasUncommittedChanges && pendingKDF == nil
  }

  func openVault(_ url: URL) async {
    guard let runtime, beginOperation() else { return }
    defer { endOperation() }
    guard currentVault == nil else {
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
    guard let runtime, let vault = currentVault, beginOperation() else {
      password?.close()
      return
    }
    defer { endOperation() }
    if let keyFileURL {
      scopedAccess.retain(keyFileURL)
    }

    do {
      let state = try await BackgroundWork.run {
        try runtime.unlockVault(
          vaultID: vault.vaultId,
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
        operation: .unlock(password: password, keyFileURL: keyFileURL)
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
    guard let runtime, currentVault != nil, beginOperation() else { return }
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
      case .unlock(let password, let keyFileURL):
        guard let vault = currentVault else { return }
        let state = try await BackgroundWork.run {
          try runtime.unlockVault(
            vaultID: vault.vaultId,
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
    guard let runtime, let vault = currentVault, beginOperation() else { return }
    defer { endOperation() }
    guard !saveProgress.hasUncommittedChanges else {
      errorMessage = "Save the current entry before closing the vault."
      return
    }
    do {
      let state = try await BackgroundWork.run { try runtime.closeVault(vaultID: vault.vaultId) }
      clearDraft()
      entries.removeAll(keepingCapacity: false)
      selectedEntryID = nil
      currentVault = nil
      apply(state)
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
    return currentVault?.vaultId
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

  private static func describe(_ error: Error) -> String {
    if let error = error as? LocalizedError, let description = error.errorDescription {
      return description
    }
    return "The operation failed."
  }
}

private enum PendingKDFOperation {
  case unlock(password: VaultKernSensitiveString?, keyFileURL: URL?)
  case unlockBlob
  case enroll(password: VaultKernSensitiveString?, keyFileURL: URL?)

  @MainActor
  func close(using scopedAccess: SecurityScopedAccess) {
    switch self {
    case .unlock(let password, let keyFileURL), .enroll(let password, let keyFileURL):
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
    case .unlockBlob:
      break
    }
  }
}

private struct OpenedVault: Sendable {
  let handle: VaultHandleDto
  let state: SessionStateDto
}
