import Foundation

protocol VaultRuntimeClient: Sendable {
  func openVault(path: String) throws -> VaultHandleDto
  func sessionState() throws -> SessionStateDto
  func unlockVault(
    vaultID: String,
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto
  func unlockCurrent(
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto
  func unlockWithBlob(kdfConfirmed: Bool) throws -> UnlockBlobResultDto
  func enroll(
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto
  func revoke() throws -> SessionStateDto
  func lockSession() throws -> SessionStateDto
  func closeVault(vaultID: String) throws -> SessionStateDto
  func listEntries(vaultID: String) throws -> [EntrySummaryDto]
  func readEntry(vaultID: String, entryID: String) throws -> EntryDraft
  func editEntry(vaultID: String, entryID: String, fields: OwnedEntryFields) throws -> EntryDraft
  func save(vaultID: String) throws -> SaveVaultResultDto
  func currentVaultReference() throws -> VaultReferenceDto?
  func beginOneDriveLogin() throws -> OneDriveAuthSessionDto
  func completePendingOneDriveLogin() throws -> OneDriveAuthStatusDto
  func listOneDriveChildren(parentItemID: String?) throws -> [OneDriveItemDto]
  func addOneDriveVault(driveID: String, itemID: String) throws -> VaultReferenceDto
  func sync(vaultID: String) throws -> VaultSourceStatusDto
  func syncStatus() throws -> VaultSourceStatusDto?
}

final class LiveVaultRuntimeClient: VaultRuntimeClient, @unchecked Sendable {
  private let session: VaultSession
  private let unlock: VaultUnlock
  private let sources: VaultSources
  private let syncClient: VaultSync

  init(configuration: AppConfiguration) throws {
    let unlockAdapter = try VaultKernMacOSUnlockBlobAdapter(
      accessGroup: configuration.keychainAccessGroup
    )
    let oneDriveTokenAdapter = try VaultKernMacOSOneDriveTokenAdapter(
      accessGroup: configuration.keychainAccessGroup
    )
    session = try VaultSession(
      config: VaultSessionConfig(
        platform: .macos,
        stateDirectory: configuration.stateDirectory.path,
        temporaryDirectory: configuration.temporaryDirectory.path
      ),
      unlockBlobAdapter: unlockAdapter,
      oneDriveTokenAdapter: oneDriveTokenAdapter
    )
    unlock = session.unlock()
    sources = session.sources()
    syncClient = session.sync()
  }

  func openVault(path: String) throws -> VaultHandleDto {
    try session.openVault(path: path)
  }

  func sessionState() throws -> SessionStateDto {
    try session.sessionState()
  }

  func unlockVault(
    vaultID: String,
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto {
    try unlock.unlockVault(
      vaultId: vaultID,
      password: password,
      keyFilePath: keyFilePath,
      kdfConfirmed: kdfConfirmed
    )
  }

  func unlockWithBlob(kdfConfirmed: Bool) throws -> UnlockBlobResultDto {
    try unlock.unlockWithBlob(kdfConfirmed: kdfConfirmed)
  }

  func unlockCurrent(
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto {
    try unlock.unlockCurrent(
      password: password,
      keyFilePath: keyFilePath,
      kdfConfirmed: kdfConfirmed
    )
  }

  func enroll(
    password: VaultKernSensitiveString?,
    keyFilePath: String?,
    kdfConfirmed: Bool
  ) throws -> SessionStateDto {
    try unlock.enroll(
      password: password,
      keyFilePath: keyFilePath,
      kdfConfirmed: kdfConfirmed
    )
  }

  func revoke() throws -> SessionStateDto {
    try unlock.revoke()
  }

  func lockSession() throws -> SessionStateDto {
    try session.lockSession()
  }

  func closeVault(vaultID: String) throws -> SessionStateDto {
    try session.closeVault(vaultId: vaultID)
  }

  func listEntries(vaultID: String) throws -> [EntrySummaryDto] {
    try session.listEntries(vaultId: vaultID)
  }

  func readEntry(vaultID: String, entryID: String) throws -> EntryDraft {
    try session.readEntry(vaultId: vaultID, entryId: entryID).consumeAsDraft()
  }

  func editEntry(vaultID: String, entryID: String, fields: OwnedEntryFields) throws -> EntryDraft {
    defer { fields.close() }
    return try session.editEntry(
      vaultId: vaultID,
      entryId: entryID,
      fields: fields.value
    ).consumeAsDraft()
  }

  func save(vaultID: String) throws -> SaveVaultResultDto {
    try session.save(vaultId: vaultID)
  }

  func currentVaultReference() throws -> VaultReferenceDto? {
    try sources.listRecent().vaults.first(where: \.isCurrent)
  }

  func beginOneDriveLogin() throws -> OneDriveAuthSessionDto {
    try sources.beginOneDriveLogin()
  }

  func completePendingOneDriveLogin() throws -> OneDriveAuthStatusDto {
    try sources.completePendingOneDriveLogin()
  }

  func listOneDriveChildren(parentItemID: String?) throws -> [OneDriveItemDto] {
    try sources.listOneDriveChildren(parentItemId: parentItemID).items
  }

  func addOneDriveVault(driveID: String, itemID: String) throws -> VaultReferenceDto {
    try sources.addOneDriveVault(driveId: driveID, itemId: itemID)
  }

  func sync(vaultID: String) throws -> VaultSourceStatusDto {
    try syncClient.trigger(vaultId: vaultID)
  }

  func syncStatus() throws -> VaultSourceStatusDto? {
    try syncClient.status()
  }

  func makeProtocolSession() -> VaultProtocolSession {
    session.protocolSession()
  }
}

enum BackgroundWork {
  static func run<T: Sendable>(_ operation: @escaping @Sendable () throws -> T) async throws -> T {
    try await Task.detached(priority: .userInitiated, operation: operation).value
  }
}
