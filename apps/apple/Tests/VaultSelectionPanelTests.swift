import Foundation
import XCTest

@testable import VaultKern

final class VaultSelectionPanelTests: XCTestCase {
  func testAcceptsOnlyTheVaultsContainingDirectory() throws {
    let rootURL = FileManager.default.temporaryDirectory
      .appendingPathComponent("vaultkern-selection-\(UUID().uuidString)", isDirectory: true)
    let directoryURL = rootURL.appendingPathComponent("vaults", isDirectory: true)
    let vaultURL = directoryURL.appendingPathComponent("example.kdbx")
    try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
    try Data().write(to: vaultURL)
    defer { try? FileManager.default.removeItem(at: rootURL) }

    XCTAssertNotNil(
      AuthorizedVaultSelection(
        vaultURL: vaultURL,
        directoryURL: directoryURL
      )
    )
    XCTAssertNil(
      AuthorizedVaultSelection(
        vaultURL: vaultURL,
        directoryURL: rootURL
      )
    )
  }

  func testSymlinkedVaultRequiresTheResolvedTargetDirectory() throws {
    let rootURL = FileManager.default.temporaryDirectory
      .appendingPathComponent("vaultkern-selection-\(UUID().uuidString)", isDirectory: true)
    let visibleDirectoryURL = rootURL.appendingPathComponent("visible", isDirectory: true)
    let targetDirectoryURL = rootURL.appendingPathComponent("target", isDirectory: true)
    let targetVaultURL = targetDirectoryURL.appendingPathComponent("example.kdbx")
    let symlinkVaultURL = visibleDirectoryURL.appendingPathComponent("example.kdbx")
    try FileManager.default.createDirectory(
      at: visibleDirectoryURL,
      withIntermediateDirectories: true
    )
    try FileManager.default.createDirectory(
      at: targetDirectoryURL,
      withIntermediateDirectories: true
    )
    try Data().write(to: targetVaultURL)
    try FileManager.default.createSymbolicLink(
      at: symlinkVaultURL,
      withDestinationURL: targetVaultURL
    )
    defer { try? FileManager.default.removeItem(at: rootURL) }

    XCTAssertNotNil(
      AuthorizedVaultSelection(
        vaultURL: symlinkVaultURL,
        directoryURL: targetDirectoryURL
      )
    )
    XCTAssertNil(
      AuthorizedVaultSelection(
        vaultURL: symlinkVaultURL,
        directoryURL: visibleDirectoryURL
      )
    )
  }
}
