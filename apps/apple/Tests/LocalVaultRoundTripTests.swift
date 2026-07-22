import Foundation
import XCTest

@testable import VaultKern

final class LocalVaultRoundTripTests: XCTestCase {
  func testLiveClientEditsSavesAndReopensKDBX41() throws {
    let fixture = repositoryRoot.appending(
      path: "crates/vaultkern-kdbx/tests/fixtures/keepassxc-2.7.6-kdbx4.1.kdbx")
    let privateTemporary = URL(
      fileURLWithPath: "/private\(FileManager.default.temporaryDirectory.path)",
      isDirectory: true
    )
    let root = privateTemporary.appending(
      path: "vaultkern-macos-roundtrip-\(UUID().uuidString)", directoryHint: .isDirectory)
    let vault = root.appending(path: "roundtrip.kdbx")
    let state = root.appending(path: "state", directoryHint: .isDirectory)
    let temporary = root.appending(path: "temporary", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.copyItem(at: fixture, to: vault)

    let configuration = AppConfiguration(
      stateDirectory: state,
      temporaryDirectory: temporary,
      keychainAccessGroup: "4HBAZ2M969.com.vaultkern.shared"
    )
    let firstClient = try LiveVaultRuntimeClient(configuration: configuration)
    let firstHandle = try firstClient.openVault(path: vault.path)
    let firstPassword = VaultKernSensitiveString("vaultkern-external-fixture")
    defer { firstPassword.close() }
    let unlocked = try firstClient.unlockVault(
      vaultID: firstHandle.vaultId,
      password: firstPassword,
      keyFilePath: nil,
      kdfConfirmed: false
    )
    XCTAssertTrue(unlocked.unlocked)

    let summaries = try firstClient.listEntries(vaultID: firstHandle.vaultId)
    let summary = try XCTUnwrap(summaries.first)
    var draft = try firstClient.readEntry(vaultID: firstHandle.vaultId, entryID: summary.id)
    let marker = "macOS M2 \(UUID().uuidString)"
    draft.notes = marker
    _ = try firstClient.editEntry(
      vaultID: firstHandle.vaultId,
      entryID: summary.id,
      fields: OwnedEntryFields(draft: draft)
    )
    let saved = try firstClient.save(vaultID: firstHandle.vaultId)
    XCTAssertEqual(saved.status, .saved)
    _ = try firstClient.closeVault(vaultID: firstHandle.vaultId)
    draft.clear()

    let secondClient = try LiveVaultRuntimeClient(configuration: configuration)
    let secondHandle = try secondClient.openVault(path: vault.path)
    let secondPassword = VaultKernSensitiveString("vaultkern-external-fixture")
    defer { secondPassword.close() }
    _ = try secondClient.unlockVault(
      vaultID: secondHandle.vaultId,
      password: secondPassword,
      keyFilePath: nil,
      kdfConfirmed: false
    )
    var reopened = try secondClient.readEntry(vaultID: secondHandle.vaultId, entryID: summary.id)
    XCTAssertEqual(reopened.notes, marker)
    reopened.clear()
    _ = try secondClient.closeVault(vaultID: secondHandle.vaultId)
  }

  private var repositoryRoot: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }
}
