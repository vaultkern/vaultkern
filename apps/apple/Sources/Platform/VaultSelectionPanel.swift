import AppKit
import Foundation
import UniformTypeIdentifiers

struct AuthorizedVaultSelection: Sendable {
  let vaultURL: URL
  let directoryURL: URL

  init?(vaultURL: URL, directoryURL: URL) {
    let resolvedVaultDirectoryURL =
      vaultURL.standardizedFileURL
      .resolvingSymlinksInPath()
      .deletingLastPathComponent()
    let resolvedDirectoryURL = directoryURL.standardizedFileURL.resolvingSymlinksInPath()
    guard resolvedVaultDirectoryURL.path == resolvedDirectoryURL.path else {
      return nil
    }
    self.vaultURL = vaultURL
    self.directoryURL = directoryURL
  }
}

@MainActor
enum VaultSelectionPanel {
  static func chooseVault() -> AuthorizedVaultSelection? {
    let vaultPanel = NSOpenPanel()
    vaultPanel.allowedContentTypes = [UTType(filenameExtension: "kdbx") ?? .data]
    vaultPanel.allowsMultipleSelection = false
    vaultPanel.canChooseDirectories = false
    vaultPanel.canChooseFiles = true
    vaultPanel.prompt = "Open"

    guard vaultPanel.runModal() == .OK, let vaultURL = vaultPanel.url else { return nil }
    let parentURL =
      vaultURL.standardizedFileURL
      .resolvingSymlinksInPath()
      .deletingLastPathComponent()

    let directoryPanel = NSOpenPanel()
    directoryPanel.allowsMultipleSelection = false
    directoryPanel.canChooseDirectories = true
    directoryPanel.canChooseFiles = false
    directoryPanel.canCreateDirectories = false
    directoryPanel.directoryURL = parentURL
    directoryPanel.message =
      "Authorize the folder containing \(vaultURL.lastPathComponent) for atomic saves."
    directoryPanel.prompt = "Authorize Folder"

    while directoryPanel.runModal() == .OK {
      guard let directoryURL = directoryPanel.url else { continue }
      if let selection = AuthorizedVaultSelection(
        vaultURL: vaultURL,
        directoryURL: directoryURL
      ) {
        return selection
      }

      directoryURL.stopAccessingSecurityScopedResource()
      let alert = NSAlert()
      alert.alertStyle = .warning
      alert.messageText = "Choose the vault's containing folder"
      alert.informativeText =
        "VaultKern needs that exact folder to create the temporary files required for atomic saves."
      alert.runModal()
      directoryPanel.directoryURL = parentURL
    }
    vaultURL.stopAccessingSecurityScopedResource()
    return nil
  }
}
