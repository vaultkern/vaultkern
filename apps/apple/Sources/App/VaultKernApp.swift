import Darwin
import SwiftUI

@main
struct VaultKernApp: App {
  @StateObject private var model: VaultAppModel

  init() {
    if CommandLine.arguments.dropFirst() == ["--unregister-native-messaging"] {
      do {
        let status = try ResidentIPCController.unregisterService()
        print("native messaging service status: \(status.rawValue)")
        exit(0)
      } catch {
        fputs("native messaging service unregister failed: \(error.localizedDescription)\n", stderr)
        exit(1)
      }
    }
    _model = StateObject(wrappedValue: VaultAppModel())
  }

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
        .disabled(!model.canChangeVault || model.hasSelectedVault)
      }
    }
  }
}

extension Notification.Name {
  static let openVaultPicker = Notification.Name("VaultKern.openVaultPicker")
}
