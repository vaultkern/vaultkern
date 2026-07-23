import SwiftUI

enum CredentialSubmission {
  static func password(
    taking owner: VaultKernSensitiveString,
    hasKeyFile: Bool,
    includesEmptyPassword: Bool
  ) -> VaultKernSensitiveString? {
    guard !owner.isEmpty || !hasKeyFile || includesEmptyPassword else {
      owner.close()
      return nil
    }
    return owner
  }
}

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
    .task { await model.reconcileStartupSettings() }
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
  @State private var password = VaultKernSensitiveString("")
  @State private var keyFileURL: URL?
  @State private var includesEmptyPassword = false
  @State private var presentsKeyFileImporter = false
  @State private var isSubmitting = false

  var body: some View {
    Form {
      Section("Unlock") {
        SecureField("Master password", text: passwordBinding)
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

        if keyFileURL != nil && password.isEmpty {
          Toggle("Use empty password with key file", isOn: $includesEmptyPassword)
        }

        HStack {
          Button("Unlock", systemImage: "lock.open") { unlock() }
            .buttonStyle(.borderedProminent)
            .disabled(model.isBusy || isSubmitting)
          if model.supportsBiometricUnlock {
            Button("Touch ID", systemImage: "touchid") {
              submitBiometricUnlock()
            }
            .disabled(model.isBusy || isSubmitting)
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
      includesEmptyPassword = false
    }
    .onDisappear {
      password.close()
      clearKeyFileURL()
    }
  }

  private func unlock() {
    guard !isSubmitting, model.registerCredentialSubmission() else { return }
    isSubmitting = true
    let selectedKeyFileURL = keyFileURL
    keyFileURL = nil
    let owner = takePassword(keyFileURL: selectedKeyFileURL)
    includesEmptyPassword = false
    Task {
      await model.unlockWithPassword(owner, keyFileURL: selectedKeyFileURL)
      isSubmitting = false
    }
  }

  private func submitBiometricUnlock() {
    guard !isSubmitting, model.registerCredentialSubmission() else { return }
    isSubmitting = true
    Task {
      await model.unlockWithBiometrics()
      isSubmitting = false
    }
  }

  private var passwordBinding: Binding<String> {
    Binding(
      get: { password.reveal() },
      set: { value in
        let replacement = VaultKernSensitiveString(value)
        password.close()
        password = replacement
      }
    )
  }

  private func takePassword(keyFileURL: URL?) -> VaultKernSensitiveString? {
    let owner = password
    password = VaultKernSensitiveString("")
    return CredentialSubmission.password(
      taking: owner,
      hasKeyFile: keyFileURL != nil,
      includesEmptyPassword: includesEmptyPassword
    )
  }

  private func clearKeyFileURL() {
    keyFileURL?.stopAccessingSecurityScopedResource()
    keyFileURL = nil
    includesEmptyPassword = false
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
                attachment.name.reveal(),
                value: ByteCountFormatter.string(
                  fromByteCount: Int64(attachment.size),
                  countStyle: .file
                ))
            }
          }
        }

        if let relyingParty = draft.passkeyRelyingParty {
          Section("Passkey") {
            LabeledContent("Relying party", value: relyingParty.reveal())
          }
        }
      }

      Section("Quick Unlock") {
        HStack {
          Button("Enable Touch ID", systemImage: "touchid") {
            presentsEnrollment = true
          }
          .disabled(
            model.isBusy || !model.supportsBiometricUnlock
              || (model.quickUnlockDesiredEnabled && model.quickUnlockKnownEnrolled == true)
          )
          Button("Disable", systemImage: "trash", role: .destructive) {
            Task { await model.disableQuickUnlock() }
          }
          .disabled(model.isBusy || !model.quickUnlockDesiredEnabled)
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

  private func draftBinding(
    _ keyPath: KeyPath<EntryDraft, VaultKernSensitiveString>
  ) -> Binding<String> {
    Binding(
      get: { model.draft?[keyPath: keyPath].reveal() ?? "" },
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
      TextField("Name", text: sensitiveFieldBinding(\.key))
      Group {
        if field.isProtected && !revealsProtectedValue {
          SecureField("Value", text: sensitiveFieldBinding(\.value))
        } else {
          TextField("Value", text: sensitiveFieldBinding(\.value))
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
      Toggle("Protected", isOn: protectionBinding)
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

  private func sensitiveFieldBinding(
    _ keyPath: KeyPath<EntryCustomFieldDraft, VaultKernSensitiveString>
  ) -> Binding<String> {
    Binding(
      get: { field[keyPath: keyPath].reveal() },
      set: { model.updateCustomField(id: field.id, keyPath, value: $0) }
    )
  }

  private var protectionBinding: Binding<Bool> {
    Binding(
      get: { field.isProtected },
      set: { model.updateCustomFieldProtection(id: field.id, isProtected: $0) }
    )
  }
}

private struct QuickUnlockEnrollmentView: View {
  @ObservedObject var model: VaultAppModel
  @Binding var isPresented: Bool
  @State private var password = VaultKernSensitiveString("")
  @State private var keyFileURL: URL?
  @State private var includesEmptyPassword = false
  @State private var presentsKeyFileImporter = false
  @State private var isSubmitting = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Enable Touch ID")
        .font(.title2.weight(.semibold))
      SecureField("Current master password", text: passwordBinding)
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
      if keyFileURL != nil && password.isEmpty {
        Toggle("Use empty password with key file", isOn: $includesEmptyPassword)
      }
      HStack {
        Spacer()
        Button("Cancel") {
          password.close()
          clearKeyFileURL()
          isPresented = false
        }
        Button("Enable", systemImage: "touchid") {
          guard !isSubmitting, model.registerCredentialSubmission() else { return }
          isSubmitting = true
          let selectedKeyFileURL = keyFileURL
          keyFileURL = nil
          let owner = takePassword(keyFileURL: selectedKeyFileURL)
          includesEmptyPassword = false
          isPresented = false
          Task {
            await model.enableQuickUnlock(password: owner, keyFileURL: selectedKeyFileURL)
            isSubmitting = false
          }
        }
        .buttonStyle(.borderedProminent)
        .disabled(model.isBusy || isSubmitting)
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
      includesEmptyPassword = false
    }
    .interactiveDismissDisabled(model.isBusy)
    .onDisappear {
      password.close()
      clearKeyFileURL()
    }
  }

  private var passwordBinding: Binding<String> {
    Binding(
      get: { password.reveal() },
      set: { value in
        let replacement = VaultKernSensitiveString(value)
        password.close()
        password = replacement
      }
    )
  }

  private func takePassword(keyFileURL: URL?) -> VaultKernSensitiveString? {
    let owner = password
    password = VaultKernSensitiveString("")
    return CredentialSubmission.password(
      taking: owner,
      hasKeyFile: keyFileURL != nil,
      includesEmptyPassword: includesEmptyPassword
    )
  }

  private func clearKeyFileURL() {
    keyFileURL?.stopAccessingSecurityScopedResource()
    keyFileURL = nil
    includesEmptyPassword = false
  }
}
