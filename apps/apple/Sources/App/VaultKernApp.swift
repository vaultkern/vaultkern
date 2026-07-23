import AppKit
import SwiftUI

@MainActor
final class VaultKernAppDelegate: NSObject, NSApplicationDelegate {
  weak var model: VaultAppModel?
  var confirmsTermination: (VaultTerminationRisk) -> Bool = {
    VaultKernAppDelegate.presentTerminationConfirmation(for: $0)
  }

  func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    terminationReply(for: model)
  }

  func terminationReply(for model: VaultAppModel?) -> NSApplication.TerminateReply {
    guard let risk = model?.terminationRisk else { return .terminateNow }
    return confirmsTermination(risk) ? .terminateNow : .terminateCancel
  }

  private static func presentTerminationConfirmation(for risk: VaultTerminationRisk) -> Bool {
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = "Quit VaultKern?"
    alert.informativeText =
      switch risk {
      case .operationInProgress:
        "An operation is still running. Quitting now may leave its outcome unknown."
      case .kdfConfirmation:
        "A credential operation is waiting for confirmation."
      case .dirtyDraft:
        "The current entry has edits that have not been applied."
      case .stagedSave:
        "The current entry was changed in memory but has not been saved to the vault."
      }
    alert.addButton(withTitle: "Keep Working")
    alert.addButton(withTitle: "Quit Without Saving")
    return alert.runModal() == .alertSecondButtonReturn
  }
}

@main
struct VaultKernApp: App {
  @NSApplicationDelegateAdaptor(VaultKernAppDelegate.self) private var appDelegate
  @StateObject private var model = VaultAppModel()

  var body: some Scene {
    WindowGroup {
      ContentView(model: model)
        .frame(minWidth: 920, minHeight: 620)
        .onAppear { appDelegate.model = model }
    }
    .defaultSize(width: 1120, height: 760)
    .commands {
      CommandGroup(replacing: .newItem) {
        Button("Open Vault...") {
          NotificationCenter.default.post(name: .openVaultPicker, object: nil)
        }
        .keyboardShortcut("o")
        .disabled(!model.canChangeVault || model.currentVault != nil)
      }
    }
  }
}

extension Notification.Name {
  static let openVaultPicker = Notification.Name("VaultKern.openVaultPicker")
}
