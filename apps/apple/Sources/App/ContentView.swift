import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
  @ObservedObject var model: VaultAppModel
  @State private var presentsVaultImporter = false
  @State private var presentsOneDrive = false

  private let kdbxType = UTType(filenameExtension: "kdbx") ?? .data

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
    .fileImporter(
      isPresented: $presentsVaultImporter,
      allowedContentTypes: [kdbxType],
      allowsMultipleSelection: false
    ) { result in
      guard case .success(let urls) = result, let url = urls.first else { return }
      Task { await model.openVault(url) }
    }
    .onReceive(NotificationCenter.default.publisher(for: .openVaultPicker)) { _ in
      guard model.canChangeVault, !model.hasSelectedVault else { return }
      presentsVaultImporter = true
    }
    .sheet(
      isPresented: $presentsOneDrive,
      onDismiss: model.resetOneDriveBrowser
    ) {
      OneDriveSourceView(model: model, isPresented: $presentsOneDrive)
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
      if let vaultName = model.selectedVaultName {
        Section("Vault") {
          Label(
            vaultName,
            systemImage: model.isRemoteVault
              ? "externaldrive.badge.icloud"
              : (model.isUnlocked ? "lock.open" : "lock")
          )
          .lineLimit(2)
        }
      }

      if model.isRemoteVault, let status = model.sourceStatus {
        Section("OneDrive") {
          Label(status.remoteState.capitalized, systemImage: "arrow.triangle.2.circlepath")
          if let error = status.lastError {
            Label(error, systemImage: "exclamationmark.triangle")
              .foregroundStyle(.red)
              .lineLimit(2)
          }
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
    if !model.hasSelectedVault {
      ContentUnavailableView {
        Label("Open a KDBX vault", systemImage: "folder.badge.plus")
      } actions: {
        Button("Open Vault", systemImage: "folder") {
          presentsVaultImporter = true
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
      if !model.hasSelectedVault {
        Button {
          presentsVaultImporter = true
        } label: {
          Label("Open Vault", systemImage: "folder")
        }
        .help("Open Vault")
        .disabled(!model.canChangeVault)
        Button {
          presentsOneDrive = true
        } label: {
          Label("OneDrive", systemImage: "externaldrive.badge.icloud")
        }
        .help("Open from OneDrive")
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
          if model.isRemoteVault {
            Button {
              Task { await model.syncCurrentVault() }
            } label: {
              Label("Sync", systemImage: "arrow.triangle.2.circlepath")
            }
            .help("Sync OneDrive Vault")
            .disabled(!model.canChangeVault)
          }
          Button {
            Task { await model.lockVault() }
          } label: {
            Label("Lock", systemImage: "lock")
          }
          .help("Lock Vault")
          .disabled(!model.canChangeVault)
        }
        if !model.isRemoteVault {
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
              keyFileURL = nil
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
      guard case .success(let urls) = result else { return }
      keyFileURL = urls.first
    }
    .onDisappear {
      password.removeAll(keepingCapacity: false)
      keyFileURL = nil
    }
  }

  private func unlock() {
    guard !password.isEmpty || keyFileURL != nil else { return }
    let owner = password.isEmpty ? nil : VaultKernSensitiveString(password)
    password.removeAll(keepingCapacity: false)
    Task { await model.unlockWithPassword(owner, keyFileURL: keyFileURL) }
  }
}

private struct EntryEditorView: View {
  @ObservedObject var model: VaultAppModel
  @State private var revealsPassword = false
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
        TextField("TOTP URI", text: draftBinding(\.totpURI))
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

  var body: some View {
    HStack {
      TextField("Name", text: fieldBinding(\.key))
      TextField("Value", text: fieldBinding(\.value))
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
          isPresented = false
        }
        Button("Enable", systemImage: "touchid") {
          let owner = password.isEmpty ? nil : VaultKernSensitiveString(password)
          password.removeAll(keepingCapacity: false)
          isPresented = false
          Task { await model.enrollQuickUnlock(password: owner, keyFileURL: keyFileURL) }
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
      guard case .success(let urls) = result else { return }
      keyFileURL = urls.first
    }
    .interactiveDismissDisabled(model.isBusy)
    .onDisappear {
      password.removeAll(keepingCapacity: false)
      keyFileURL = nil
    }
  }
}

private struct OneDriveSourceView: View {
  @ObservedObject var model: VaultAppModel
  @Binding var isPresented: Bool

  var body: some View {
    NavigationStack {
      Group {
        switch model.oneDriveBrowserState {
        case .idle, .checking:
          ProgressView()
            .controlSize(.large)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .needsAuthorization:
          ContentUnavailableView {
            Label("Connect OneDrive", systemImage: "person.crop.circle.badge.plus")
          } actions: {
            Button("Connect", systemImage: "arrow.up.right.square", action: connect)
              .buttonStyle(.borderedProminent)
          }
        case .authorizing:
          ProgressView("Waiting for OneDrive")
            .controlSize(.large)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .awaitingCallback:
          ContentUnavailableView {
            Label("OneDrive sign-in", systemImage: "person.crop.circle.badge.clock")
          } actions: {
            Button("Open Sign-In", systemImage: "arrow.up.right.square") {
              openAuthorizationPage()
            }
            Button("Finish", systemImage: "checkmark") {
              Task { await model.completeOneDriveLogin() }
            }
            .buttonStyle(.borderedProminent)
          }
        case .browsing(let accountLabel):
          browser(accountLabel: accountLabel)
        case .failed(let message):
          ContentUnavailableView {
            Label("OneDrive unavailable", systemImage: "exclamationmark.icloud")
          } description: {
            Text(message)
          } actions: {
            Button("Reconnect", systemImage: "arrow.clockwise", action: connect)
          }
        }
      }
      .navigationTitle(model.oneDriveFolders.last?.name ?? "OneDrive")
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button {
            isPresented = false
          } label: {
            Image(systemName: "xmark")
          }
          .help("Close")
          .disabled(locksAuthorizationPresentation)
        }
        if model.oneDriveFolders.count > 1,
          case .browsing = model.oneDriveBrowserState
        {
          ToolbarItem(placement: .navigation) {
            Button {
              Task { await model.leaveOneDriveFolder() }
            } label: {
              Image(systemName: "chevron.left")
            }
            .help("Parent Folder")
            .disabled(model.isBusy)
          }
        }
      }
    }
    .frame(minWidth: 620, minHeight: 480)
    .interactiveDismissDisabled(locksAuthorizationPresentation)
    .task {
      guard model.oneDriveBrowserState == .idle else { return }
      await model.prepareOneDriveBrowser()
    }
  }

  @ViewBuilder
  private func browser(accountLabel: String?) -> some View {
    if model.oneDriveItems.isEmpty {
      ContentUnavailableView(
        "No KDBX vaults",
        systemImage: "externaldrive.badge.xmark",
        description: accountLabel.map(Text.init)
      )
    } else {
      List(model.oneDriveItems, id: \.itemId) { item in
        Button {
          if item.folder {
            Task { await model.enterOneDriveFolder(item) }
          } else {
            Task {
              if await model.selectOneDriveVault(item) {
                isPresented = false
              }
            }
          }
        } label: {
          HStack(spacing: 12) {
            Image(systemName: item.folder ? "folder" : "lock.doc")
              .foregroundStyle(item.folder ? .blue : .primary)
              .frame(width: 20)
            Text(item.name)
              .lineLimit(1)
            Spacer()
            if let size = item.size, !item.folder {
              Text(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
                .foregroundStyle(.secondary)
                .monospacedDigit()
            }
            if item.folder {
              Image(systemName: "chevron.right")
                .foregroundStyle(.tertiary)
            }
          }
          .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(model.isBusy)
      }
    }
  }

  private func connect() {
    Task {
      guard let url = await model.beginOneDriveLogin() else { return }
      if NSWorkspace.shared.open(url) {
        model.oneDriveAuthorizationBrowserDidOpen()
      } else {
        model.oneDriveAuthorizationBrowserDidNotOpen()
      }
    }
  }

  private func openAuthorizationPage() {
    guard let url = model.oneDriveAuthorizationURL else { return }
    if NSWorkspace.shared.open(url) {
      model.oneDriveAuthorizationBrowserDidOpen()
    } else {
      model.oneDriveAuthorizationBrowserDidNotOpen()
    }
  }

  private var locksAuthorizationPresentation: Bool {
    model.oneDriveBrowserState == .authorizing
      || model.oneDriveBrowserState == .awaitingCallback
  }
}
