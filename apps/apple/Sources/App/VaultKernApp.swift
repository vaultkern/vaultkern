import SwiftUI

@main
struct VaultKernApp: App {
  @StateObject private var model = VaultAppModel()

  var body: some Scene {
    WindowGroup {
      ContentView(model: model)
        .frame(minWidth: 920, minHeight: 620)
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
