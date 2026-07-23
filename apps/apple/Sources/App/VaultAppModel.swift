import Combine
import Foundation

struct KDFConfirmationPrompt: Identifiable, Equatable {
  let id = UUID()
  let message: String
}

enum VaultTerminationRisk: Equatable {
  case operationInProgress
  case kdfConfirmation
  case dirtyDraft
  case stagedSave
}

@MainActor
protocol QuickUnlockSettingsStoring: AnyObject {
  var isEnabled: Bool { get }
  func setEnabled(_ enabled: Bool)
}

@MainActor
final class UserDefaultsQuickUnlockSettingsStore: QuickUnlockSettingsStoring {
  private let defaults: UserDefaults
  private let key: String

  init(
    defaults: UserDefaults = .standard,
    key: String = "io.vaultkern.quick-unlock.enabled"
  ) {
    self.defaults = defaults
    self.key = key
  }

  var isEnabled: Bool { defaults.bool(forKey: key) }

  func setEnabled(_ enabled: Bool) {
    defaults.set(enabled, forKey: key)
  }
}

@MainActor
final class VolatileQuickUnlockSettingsStore: QuickUnlockSettingsStoring {
  private(set) var isEnabled: Bool

  init(isEnabled: Bool = false) {
    self.isEnabled = isEnabled
  }

  func setEnabled(_ enabled: Bool) {
    isEnabled = enabled
  }
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
  @Published private(set) var hasPendingCredentialSubmission = false
  @Published private(set) var isUnlocked = false
  @Published private(set) var supportsBiometricUnlock = false
  @Published private(set) var quickUnlockKnownEnrolled: Bool?
  @Published private(set) var quickUnlockDesiredEnabled: Bool
  @Published var errorMessage: String?
  @Published var noticeMessage: String?
  @Published var kdfPrompt: KDFConfirmationPrompt?

  private let runtime: (any VaultRuntimeClient)?
  private let scopedAccess: any SecurityScopedAccessing
  private let quickUnlockSettings: any QuickUnlockSettingsStoring
  private var vaultAccessURLs: [URL] = []
  private var pendingKDF: PendingKDFOperation?

  init() {
    scopedAccess = SecurityScopedAccess()
    let quickUnlockSettings = UserDefaultsQuickUnlockSettingsStore()
    self.quickUnlockSettings = quickUnlockSettings
    quickUnlockDesiredEnabled = quickUnlockSettings.isEnabled
    do {
      runtime = try LiveVaultRuntimeClient(configuration: AppConfiguration.live())
      bootError = nil
    } catch {
      runtime = nil
      bootError = Self.describe(error)
    }
  }

  init(
    runtime: any VaultRuntimeClient,
    scopedAccess: any SecurityScopedAccessing = SecurityScopedAccess(),
    quickUnlockSettings: any QuickUnlockSettingsStoring =
      VolatileQuickUnlockSettingsStore()
  ) {
    self.runtime = runtime
    self.scopedAccess = scopedAccess
    self.quickUnlockSettings = quickUnlockSettings
    quickUnlockDesiredEnabled = quickUnlockSettings.isEnabled
    bootError = nil
  }

  var hasUncommittedChanges: Bool { saveProgress.hasUncommittedChanges }

  var canChangeVault: Bool {
    !isBusy && !hasPendingCredentialSubmission
      && !saveProgress.hasUncommittedChanges && pendingKDF == nil
  }

  var terminationRisk: VaultTerminationRisk? {
    if isBusy || hasPendingCredentialSubmission { return .operationInProgress }
    if pendingKDF != nil { return .kdfConfirmation }
    switch saveProgress {
    case .clean:
      return nil
    case .dirty:
      return .dirtyDraft
    case .staged:
      return .stagedSave
    }
  }

  func registerCredentialSubmission() -> Bool {
    guard
      !isBusy,
      !hasPendingCredentialSubmission,
      pendingKDF == nil
    else { return false }
    hasPendingCredentialSubmission = true
    return true
  }

  func reconcileStartupSettings() async {
    guard
      !quickUnlockDesiredEnabled,
      currentVault == nil,
      let runtime,
      beginOperation()
    else { return }
    defer { endOperation() }
    do {
      try await reconcileDesiredQuickUnlock(
        runtime: runtime,
        password: nil,
        keyFileURL: nil,
        kdfConfirmed: false
      )
      errorMessage = nil
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func openVault(_ url: URL, authorizedDirectoryURL: URL) async {
    let accessURLs = [url, authorizedDirectoryURL]
    for accessURL in accessURLs {
      scopedAccess.retain(accessURL)
    }
    guard let runtime, beginOperation() else {
      release(accessURLs)
      return
    }
    defer { endOperation() }
    guard currentVault == nil else {
      release(accessURLs)
      errorMessage = "Close the current vault before opening another one."
      return
    }
    guard
      let selection = AuthorizedVaultSelection(
        vaultURL: url,
        directoryURL: authorizedDirectoryURL
      )
    else {
      release(accessURLs)
      errorMessage = "Choose the folder that directly contains the vault."
      return
    }

    do {
      let opened = try await BackgroundWork.run {
        let handle = try runtime.openVault(path: selection.vaultURL.path)
        do {
          return OpenedVault(handle: handle, state: try runtime.sessionState())
        } catch {
          _ = try? runtime.closeVault(vaultID: handle.vaultId)
          throw error
        }
      }
      vaultAccessURLs = accessURLs
      currentVault = opened.handle
      apply(opened.state)
      quickUnlockKnownEnrolled = nil
      noticeMessage = nil
      errorMessage = nil
    } catch {
      release(accessURLs)
      errorMessage = Self.describe(error)
    }
  }

  func unlockWithPassword(
    _ password: VaultKernSensitiveString?,
    keyFileURL: URL?
  ) async {
    consumeCredentialSubmissionReservation()
    if let keyFileURL {
      scopedAccess.retain(keyFileURL)
    }
    guard let runtime, let vault = currentVault, beginOperation() else {
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
      return
    }
    var retainedForKDFConfirmation = false
    defer {
      if !retainedForKDFConfirmation {
        closeCredential(password: password, keyFileURL: keyFileURL)
      }
      endOperation()
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
      let reconciliationError = try await reconcileThenFinishUnlock(
        state,
        runtime: runtime,
        password: password,
        keyFileURL: keyFileURL,
        kdfConfirmed: false
      )
      if let error = reconciliationError as? VaultKernError {
        if captureKDFConfirmation(
          error,
          operation: .reconcile(password: password, keyFileURL: keyFileURL)
        ) {
          retainedForKDFConfirmation = true
          return
        }
        errorMessage =
          "The vault unlocked, but Quick Unlock reconciliation failed: \(Self.describe(error))"
      } else if let reconciliationError {
        errorMessage =
          "The vault unlocked, but Quick Unlock reconciliation failed: \(Self.describe(reconciliationError))"
      }
    } catch let error as VaultKernError {
      if captureKDFConfirmation(
        error,
        operation: .unlock(password: password, keyFileURL: keyFileURL)
      ) {
        retainedForKDFConfirmation = true
        return
      }
      errorMessage = Self.describe(error)
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func unlockWithBiometrics() async {
    consumeCredentialSubmissionReservation()
    guard let runtime, currentVault != nil, beginOperation() else { return }
    defer { endOperation() }
    do {
      let result = try await BackgroundWork.run {
        try runtime.unlockWithBlob(kdfConfirmed: false)
      }
      try await handleBlobResult(result, runtime: runtime, kdfConfirmed: false)
    } catch let error as VaultKernError {
      if captureKDFConfirmation(error, operation: .unlockBlob) {
        return
      }
      errorMessage = Self.describe(error)
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func enableQuickUnlock(
    password: VaultKernSensitiveString?,
    keyFileURL: URL?
  ) async {
    consumeCredentialSubmissionReservation()
    setQuickUnlockDesiredEnabled(true)
    if let keyFileURL {
      scopedAccess.retain(keyFileURL)
    }
    guard let runtime, isUnlocked, beginOperation() else {
      password?.close()
      if let keyFileURL {
        scopedAccess.release(keyFileURL)
      }
      return
    }
    var retainedForKDFConfirmation = false
    defer {
      if !retainedForKDFConfirmation {
        closeCredential(password: password, keyFileURL: keyFileURL)
      }
      endOperation()
    }
    do {
      try await reconcileDesiredQuickUnlock(
        runtime: runtime,
        password: password,
        keyFileURL: keyFileURL,
        kdfConfirmed: false
      )
      noticeMessage = "Touch ID quick unlock is enabled."
      errorMessage = nil
    } catch let error as VaultKernError {
      if captureKDFConfirmation(
        error,
        operation: .reconcile(password: password, keyFileURL: keyFileURL)
      ) {
        retainedForKDFConfirmation = true
        return
      }
      errorMessage = Self.describe(error)
    } catch {
      errorMessage = Self.describe(error)
    }
  }

  func disableQuickUnlock() async {
    setQuickUnlockDesiredEnabled(false)
    guard let runtime, beginOperation() else { return }
    defer { endOperation() }
    do {
      try await reconcileDesiredQuickUnlock(
        runtime: runtime,
        password: nil,
        keyFileURL: nil,
        kdfConfirmed: false
      )
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
        let reconciliationError = try await reconcileThenFinishUnlock(
          state,
          runtime: runtime,
          password: password,
          keyFileURL: keyFileURL,
          kdfConfirmed: true
        )
        if let reconciliationError {
          throw reconciliationError
        }
      case .unlockBlob:
        let result = try await BackgroundWork.run {
          try runtime.unlockWithBlob(kdfConfirmed: true)
        }
        try await handleBlobResult(result, runtime: runtime, kdfConfirmed: true)
      case .reconcile(let password, let keyFileURL):
        try await reconcileDesiredQuickUnlock(
          runtime: runtime,
          password: password,
          keyFileURL: keyFileURL,
          kdfConfirmed: true
        )
        noticeMessage =
          quickUnlockDesiredEnabled
          ? "Touch ID quick unlock is enabled."
          : "Touch ID quick unlock is disabled."
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

  func updateDraft(
    _ keyPath: KeyPath<EntryDraft, VaultKernSensitiveString>,
    value: String
  ) {
    guard !isBusy, saveProgress != .staged, let draft else { return }
    draft[keyPath: keyPath].replace(with: value)
    self.draft = draft
    saveProgress.markDraftChanged()
  }

  func updateCustomField(
    id: UUID,
    _ keyPath: KeyPath<EntryCustomFieldDraft, VaultKernSensitiveString>,
    value: String
  ) {
    guard !isBusy, saveProgress != .staged, let draft else { return }
    guard let index = draft.customFields.firstIndex(where: { $0.id == id }) else { return }
    draft.customFields[index][keyPath: keyPath].replace(with: value)
    self.draft = draft
    saveProgress.markDraftChanged()
  }

  func updateCustomFieldProtection(id: UUID, isProtected: Bool) {
    guard !isBusy, saveProgress != .staged, let draft else { return }
    guard let index = draft.customFields.firstIndex(where: { $0.id == id }) else { return }
    draft.customFields[index].isProtected = isProtected
    self.draft = draft
    saveProgress.markDraftChanged()
  }

  func addCustomField() {
    guard !isBusy, saveProgress != .staged, let draft else { return }
    draft.customFields.append(
      EntryCustomFieldDraft(key: "", value: "", isProtected: false)
    )
    self.draft = draft
    saveProgress.markDraftChanged()
  }

  func removeCustomField(id: UUID) {
    guard !isBusy, saveProgress != .staged, let draft else { return }
    guard let index = draft.customFields.firstIndex(where: { $0.id == id }) else { return }
    draft.customFields[index].close()
    draft.customFields.remove(at: index)
    self.draft = draft
    saveProgress.markDraftChanged()
  }

  func saveDraft() async {
    guard let runtime, let vaultID = activeVaultID, let draft else { return }
    guard beginOperation() else { return }
    defer { endOperation() }

    if saveProgress.shouldApplyDraft {
      let ownedFields = OwnedEntryFields(draft: draft)
      do {
        let stagedDraft = try await BackgroundWork.run {
          defer { ownedFields.close() }
          return try runtime.editEntry(
            vaultID: vaultID,
            entryID: draft.id.reveal(),
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
      release(vaultAccessURLs)
      vaultAccessURLs.removeAll(keepingCapacity: false)
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
    guard
      !isBusy,
      !hasPendingCredentialSubmission,
      allowPendingKDF || pendingKDF == nil
    else { return false }
    isBusy = true
    return true
  }

  private func endOperation() {
    isBusy = false
  }

  private func consumeCredentialSubmissionReservation() {
    hasPendingCredentialSubmission = false
  }

  private func release(_ accessURLs: [URL]) {
    for accessURL in accessURLs.reversed() {
      scopedAccess.release(accessURL)
    }
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

  private func reconcileDesiredQuickUnlock(
    runtime: any VaultRuntimeClient,
    password: VaultKernSensitiveString?,
    keyFileURL: URL?,
    kdfConfirmed: Bool
  ) async throws {
    let enabled = quickUnlockDesiredEnabled
    let state = try await BackgroundWork.run {
      try runtime.reconcileQuickUnlock(
        enabled: enabled,
        password: password,
        keyFilePath: keyFileURL?.path,
        kdfConfirmed: kdfConfirmed
      )
    }
    apply(state)
    quickUnlockKnownEnrolled =
      enabled && state.supportsBiometricUnlock ? true : (enabled ? nil : false)
  }

  private func reconcileThenFinishUnlock(
    _ state: SessionStateDto,
    runtime: any VaultRuntimeClient,
    password: VaultKernSensitiveString?,
    keyFileURL: URL?,
    kdfConfirmed: Bool
  ) async throws -> Error? {
    let reconciliationError: Error?
    do {
      try await reconcileDesiredQuickUnlock(
        runtime: runtime,
        password: password,
        keyFileURL: keyFileURL,
        kdfConfirmed: kdfConfirmed
      )
      reconciliationError = nil
    } catch {
      reconciliationError = error
    }
    try await finishUnlock(state, runtime: runtime)
    return reconciliationError
  }

  private func handleBlobResult(
    _ result: UnlockBlobResultDto,
    runtime: any VaultRuntimeClient,
    kdfConfirmed: Bool
  ) async throws {
    apply(result.state)
    switch result.status {
    case .unlocked:
      quickUnlockKnownEnrolled = true
      let reconciliationError = try await reconcileThenFinishUnlock(
        result.state,
        runtime: runtime,
        password: nil,
        keyFileURL: nil,
        kdfConfirmed: kdfConfirmed
      )
      if let reconciliationError {
        throw reconciliationError
      }
    case .notEnrolled:
      quickUnlockKnownEnrolled = false
      noticeMessage = "Touch ID quick unlock is not enrolled."
    case .cancelled:
      noticeMessage = nil
    case .openAppRequired:
      quickUnlockKnownEnrolled = true
      errorMessage = "Quick unlock needs one password unlock to refresh its cached key."
    case .credentialRequired:
      quickUnlockKnownEnrolled = false
      errorMessage = "The stored credential is stale. Unlock with the current master credential."
    case .unsupported:
      quickUnlockKnownEnrolled = nil
      errorMessage = "Touch ID quick unlock is unavailable on this Mac."
    }
  }

  private func apply(_ state: SessionStateDto) {
    isUnlocked = state.unlocked
    supportsBiometricUnlock = state.supportsBiometricUnlock
  }

  private func setQuickUnlockDesiredEnabled(_ enabled: Bool) {
    quickUnlockSettings.setEnabled(enabled)
    quickUnlockDesiredEnabled = enabled
  }

  private func closeCredential(
    password: VaultKernSensitiveString?,
    keyFileURL: URL?
  ) {
    password?.close()
    if let keyFileURL {
      scopedAccess.release(keyFileURL)
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
    draft?.close()
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
  case reconcile(password: VaultKernSensitiveString?, keyFileURL: URL?)

  @MainActor
  func close(using scopedAccess: any SecurityScopedAccessing) {
    switch self {
    case .unlock(let password, let keyFileURL), .reconcile(let password, let keyFileURL):
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
