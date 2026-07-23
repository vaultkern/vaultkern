import SwiftUI

struct ContentView: View {
  @ObservedObject var model: VaultAppModel

  var body: some View {
    Group {
      if let bootError = model.bootError {
        ContentUnavailableView(
          "VaultKern could not start",
          systemImage: "exclamationmark.lock",
          description: Text(bootError)
        )
      } else {
        vaultWorkspace
      }
    }
    .onReceive(NotificationCenter.default.publisher(for: .openVaultPicker)) { _ in
      guard model.canChangeVault, model.currentVault == nil else { return }
      openVault()
    }
    .alert(
      "VaultKern",
      isPresented: Binding(
        get: { model.errorMessage != nil },
        set: { if !$0 { model.errorMessage = nil } }
      )
    ) {
      Button("OK") { model.errorMessage = nil }
    } message: {
      Text(model.errorMessage ?? "")
    }
    .alert(item: $model.kdfPrompt) { prompt in
      Alert(
        title: Text("Confirm expensive KDF"),
        message: Text(prompt.message),
        primaryButton: .default(Text("Continue")) {
          Task { await model.confirmKDF() }
        },
        secondaryButton: .cancel {
          model.cancelKDF()
        }
      )
    }
  }

  private var vaultWorkspace: some View {
    NavigationSplitView {
      sidebar
        .navigationSplitViewColumnWidth(min: 230, ideal: 280, max: 360)
    } detail: {
      detail
    }
    .toolbar { toolbar }
    .overlay(alignment: .bottom) {
      if let notice = model.noticeMessage {
        Text(notice)
          .font(.callout)
          .padding(.horizontal, 14)
          .padding(.vertical, 8)
          .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 6))
          .padding(12)
      }
    }
  }

  private var sidebar: some View {
    List(selection: selectedEntryBinding) {
      if let vault = model.currentVault {
        Section("Vault") {
          Label(vault.name, systemImage: model.isUnlocked ? "lock.open" : "lock")
            .lineLimit(2)
        }
      }

      if model.isUnlocked {
        Section("Entries") {
          ForEach(model.entries, id: \.id) { entry in
            VStack(alignment: .leading, spacing: 3) {
              Text(entry.title.isEmpty ? "Untitled" : entry.title)
                .font(.body.weight(.medium))
                .lineLimit(1)
              if !entry.username.isEmpty || !entry.url.isEmpty {
                Text(entry.username.isEmpty ? entry.url : entry.username)
                  .font(.caption)
                  .foregroundStyle(.secondary)
                  .lineLimit(1)
              }
            }
            .tag(entry.id)
          }
        }
      }
    }
    .disabled(model.isBusy || model.hasUncommittedChanges)
    .safeAreaInset(edge: .bottom) {
      if model.isBusy {
        ProgressView()
          .controlSize(.small)
          .padding(10)
          .frame(maxWidth: .infinity)
          .background(.bar)
      }
    }
  }

  @ViewBuilder
  private var detail: some View {
    if model.currentVault == nil {
      ContentUnavailableView {
        Label("Open a KDBX vault", systemImage: "folder.badge.plus")
      } actions: {
        Button("Open Vault", systemImage: "folder") {
          openVault()
        }
        .buttonStyle(.borderedProminent)
        .disabled(!model.canChangeVault)
      }
    } else if !model.isUnlocked {
      UnlockView(model: model)
    } else if model.draft != nil {
      EntryEditorView(model: model)
    } else {
      ContentUnavailableView(
        "Select an entry",
        systemImage: "list.bullet.rectangle",
        description: Text("Choose an entry from the sidebar.")
      )
    }
  }

  @ToolbarContentBuilder
  private var toolbar: some ToolbarContent {
    ToolbarItemGroup(placement: .primaryAction) {
      if model.currentVault == nil {
        Button {
          openVault()
        } label: {
          Label("Open Vault", systemImage: "folder")
        }
        .help("Open Vault")
        .disabled(!model.canChangeVault)
      } else {
        if model.isUnlocked {
          Button {
            Task { await model.refreshEntries() }
          } label: {
            Label("Refresh", systemImage: "arrow.clockwise")
          }
          .help("Refresh Entries")
          .disabled(!model.canChangeVault)
          Button {
            Task { await model.lockVault() }
          } label: {
            Label("Lock", systemImage: "lock")
          }
          .help("Lock Vault")
          .disabled(!model.canChangeVault)
        }
        Button {
          Task { await model.closeVault() }
        } label: {
          Label("Close", systemImage: "xmark.circle")
        }
        .help("Close Vault")
        .disabled(!model.canChangeVault)
      }
    }
  }

  private var selectedEntryBinding: Binding<String?> {
    Binding(
      get: { model.selectedEntryID },
      set: { entryID in
        guard let entryID else { return }
        Task { await model.selectEntry(entryID) }
      }
    )
  }

  private func openVault() {
    guard let selection = VaultSelectionPanel.chooseVault() else { return }
    Task {
      await model.openVault(
        selection.vaultURL,
        authorizedDirectoryURL: selection.directoryURL
      )
    }
  }
}

private struct UnlockView: View {
  @ObservedObject var model: VaultAppModel
  @State private var password = ""
  @State private var keyFileURL: URL?
  @State private var presentsKeyFileImporter = false

  var body: some View {
    Form {
      Section("Unlock") {
        SecureField("Master password", text: $password)
          .textContentType(.password)
          .onSubmit(unlock)

        HStack {
          Text(keyFileURL?.lastPathComponent ?? "No key file")
            .foregroundStyle(keyFileURL == nil ? .secondary : .primary)
            .lineLimit(1)
          Spacer()
          Button {
            presentsKeyFileImporter = true
          } label: {
            Label("Choose Key File", systemImage: "doc.badge.key")
          }
          if keyFileURL != nil {
            Button {
              clearKeyFileURL()
            } label: {
              Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.plain)
            .help("Remove Key File")
          }
        }

        HStack {
          Button("Unlock", systemImage: "lock.open") { unlock() }
            .buttonStyle(.borderedProminent)
            .disabled(model.isBusy || (password.isEmpty && keyFileURL == nil))
          if model.supportsBiometricUnlock {
            Button("Touch ID", systemImage: "touchid") {
              Task { await model.unlockWithBiometrics() }
            }
            .disabled(model.isBusy)
          }
        }
      }
    }
    .formStyle(.grouped)
    .frame(maxWidth: 560)
    .fileImporter(
      isPresented: $presentsKeyFileImporter,
      allowedContentTypes: [.data],
      allowsMultipleSelection: false
    ) { result in
      guard
        case .success(let urls) = result,
        let url = urls.first,
        url.startAccessingSecurityScopedResource()
      else {
        model.errorMessage = "VaultKern could not access the selected key file."
        return
      }
      clearKeyFileURL()
      keyFileURL = url
    }
    .onDisappear {
      password.removeAll(keepingCapacity: false)
      clearKeyFileURL()
    }
  }

  private func unlock() {
    guard !password.isEmpty || keyFileURL != nil else { return }
    let selectedKeyFileURL = keyFileURL
    keyFileURL = nil
    let owner = password.isEmpty ? nil : VaultKernSensitiveString(password)
    password.removeAll(keepingCapacity: false)
    Task { await model.unlockWithPassword(owner, keyFileURL: selectedKeyFileURL) }
  }

  private func clearKeyFileURL() {
    keyFileURL?.stopAccessingSecurityScopedResource()
    keyFileURL = nil
  }
}

private struct EntryEditorView: View {
  @ObservedObject var model: VaultAppModel
  @State private var revealsPassword = false
  @State private var revealsTOTP = false
  @State private var presentsEnrollment = false

  var body: some View {
    Form {
      Section("Entry") {
        TextField("Title", text: draftBinding(\.title))
        TextField("Username", text: draftBinding(\.username))
        HStack {
          Group {
            if revealsPassword {
              TextField("Password", text: draftBinding(\.password))
            } else {
              SecureField("Password", text: draftBinding(\.password))
            }
          }
          Button {
            revealsPassword.toggle()
          } label: {
            Image(systemName: revealsPassword ? "eye.slash" : "eye")
          }
          .buttonStyle(.plain)
          .help(revealsPassword ? "Hide Password" : "Show Password")
        }
        TextField("URL", text: draftBinding(\.url))
        HStack {
          Group {
            if revealsTOTP {
              TextField("TOTP URI", text: draftBinding(\.totpURI))
            } else {
              SecureField("TOTP URI", text: draftBinding(\.totpURI))
            }
          }
          Button {
            revealsTOTP.toggle()
          } label: {
            Image(systemName: revealsTOTP ? "eye.slash" : "eye")
          }
          .buttonStyle(.plain)
          .help(revealsTOTP ? "Hide TOTP URI" : "Show TOTP URI")
        }
        TextEditor(text: draftBinding(\.notes))
          .frame(minHeight: 100)
      }

      if let draft = model.draft {
        Section("Custom Fields") {
          ForEach(draft.customFields) { field in
            CustomFieldRow(field: field, model: model)
          }
          Button("Add Field", systemImage: "plus") { model.addCustomField() }
            .disabled(model.isBusy || model.saveProgress == .staged)
        }

        if !draft.attachments.isEmpty {
          Section("Attachments") {
            ForEach(draft.attachments) { attachment in
              LabeledContent(
                attachment.name,
                value: ByteCountFormatter.string(
                  fromByteCount: Int64(attachment.size),
                  countStyle: .file
                ))
            }
          }
        }

        if let relyingParty = draft.passkeyRelyingParty {
          Section("Passkey") {
            LabeledContent("Relying party", value: relyingParty)
          }
        }
      }

      Section("Quick Unlock") {
        HStack {
          Button("Enable Touch ID", systemImage: "touchid") {
            presentsEnrollment = true
          }
          .disabled(model.isBusy || !model.supportsBiometricUnlock)
          Button("Disable", systemImage: "trash", role: .destructive) {
            Task { await model.revokeQuickUnlock() }
          }
          .disabled(model.isBusy)
        }
      }
    }
    .formStyle(.grouped)
    .safeAreaInset(edge: .bottom) {
      HStack {
        if model.saveProgress == .dirty {
          Button("Discard") { Task { await model.discardDraft() } }
            .disabled(model.isBusy)
        }
        Spacer()
        Button(
          model.saveProgress == .staged ? "Retry Save" : "Save",
          systemImage: "square.and.arrow.down"
        ) {
          Task { await model.saveDraft() }
        }
        .buttonStyle(.borderedProminent)
        .disabled(model.isBusy || model.saveProgress == .clean)
      }
      .padding(12)
      .background(.bar)
    }
    .sheet(isPresented: $presentsEnrollment) {
      QuickUnlockEnrollmentView(model: model, isPresented: $presentsEnrollment)
        .frame(width: 460)
    }
    .onChange(of: model.selectedEntryID) {
      revealsPassword = false
      revealsTOTP = false
    }
  }

  private func draftBinding(_ keyPath: WritableKeyPath<EntryDraft, String>) -> Binding<String> {
    Binding(
      get: { model.draft?[keyPath: keyPath] ?? "" },
      set: { model.updateDraft(keyPath, value: $0) }
    )
  }
}

private struct CustomFieldRow: View {
  let field: EntryCustomFieldDraft
  @ObservedObject var model: VaultAppModel
  @State private var revealsProtectedValue = false

  var body: some View {
    HStack {
      TextField("Name", text: fieldBinding(\.key))
      Group {
        if field.isProtected && !revealsProtectedValue {
          SecureField("Value", text: fieldBinding(\.value))
        } else {
          TextField("Value", text: fieldBinding(\.value))
        }
      }
      if field.isProtected {
        Button {
          revealsProtectedValue.toggle()
        } label: {
          Image(systemName: revealsProtectedValue ? "eye.slash" : "eye")
        }
        .buttonStyle(.plain)
        .help(revealsProtectedValue ? "Hide Protected Value" : "Show Protected Value")
      }
      Toggle("Protected", isOn: fieldBinding(\.isProtected))
        .labelsHidden()
        .help("Protected Field")
      Button(role: .destructive) {
        model.removeCustomField(id: field.id)
      } label: {
        Image(systemName: "minus.circle")
      }
      .buttonStyle(.plain)
      .help("Remove Field")
    }
    .onChange(of: field.isProtected) {
      revealsProtectedValue = false
    }
  }

  private func fieldBinding<Value>(
    _ keyPath: WritableKeyPath<EntryCustomFieldDraft, Value>
  ) -> Binding<Value> {
    Binding(
      get: { field[keyPath: keyPath] },
      set: { value in
        var updated = field
        updated[keyPath: keyPath] = value
        model.updateCustomField(updated)
      }
    )
  }
}

private struct QuickUnlockEnrollmentView: View {
  @ObservedObject var model: VaultAppModel
  @Binding var isPresented: Bool
  @State private var password = ""
  @State private var keyFileURL: URL?
  @State private var presentsKeyFileImporter = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Enable Touch ID")
        .font(.title2.weight(.semibold))
      SecureField("Current master password", text: $password)
        .textContentType(.password)
      HStack {
        Text(keyFileURL?.lastPathComponent ?? "No key file")
          .foregroundStyle(keyFileURL == nil ? .secondary : .primary)
          .lineLimit(1)
        Spacer()
        Button("Choose", systemImage: "doc.badge.key") {
          presentsKeyFileImporter = true
        }
      }
      HStack {
        Spacer()
        Button("Cancel") {
          password.removeAll(keepingCapacity: false)
          clearKeyFileURL()
          isPresented = false
        }
        Button("Enable", systemImage: "touchid") {
          let selectedKeyFileURL = keyFileURL
          keyFileURL = nil
          let owner = password.isEmpty ? nil : VaultKernSensitiveString(password)
          password.removeAll(keepingCapacity: false)
          isPresented = false
          Task {
            await model.enrollQuickUnlock(password: owner, keyFileURL: selectedKeyFileURL)
          }
        }
        .buttonStyle(.borderedProminent)
        .disabled(model.isBusy || (password.isEmpty && keyFileURL == nil))
      }
    }
    .padding(24)
    .fileImporter(
      isPresented: $presentsKeyFileImporter,
      allowedContentTypes: [.data],
      allowsMultipleSelection: false
    ) { result in
      guard
        case .success(let urls) = result,
        let url = urls.first,
        url.startAccessingSecurityScopedResource()
      else {
        model.errorMessage = "VaultKern could not access the selected key file."
        return
      }
      clearKeyFileURL()
      keyFileURL = url
    }
    .interactiveDismissDisabled(model.isBusy)
    .onDisappear {
      password.removeAll(keepingCapacity: false)
      clearKeyFileURL()
    }
  }

  private func clearKeyFileURL() {
    keyFileURL?.stopAccessingSecurityScopedResource()
    keyFileURL = nil
  }
}
