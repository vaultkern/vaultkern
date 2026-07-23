import Foundation

struct EntryCustomFieldDraft: Identifiable, @unchecked Sendable,
  CustomStringConvertible, CustomDebugStringConvertible
{
  let id: UUID
  let key: VaultKernSensitiveString
  let value: VaultKernSensitiveString
  var isProtected: Bool

  init(
    id: UUID = UUID(),
    key: VaultKernSensitiveString,
    value: VaultKernSensitiveString,
    isProtected: Bool
  ) {
    self.id = id
    self.key = key
    self.value = value
    self.isProtected = isProtected
  }

  init(id: UUID = UUID(), key: String, value: String, isProtected: Bool) {
    self.init(
      id: id,
      key: VaultKernSensitiveString(key),
      value: VaultKernSensitiveString(value),
      isProtected: isProtected
    )
  }

  func close() {
    key.close()
    value.close()
  }

  var description: String { "EntryCustomFieldDraft([REDACTED])" }
  var debugDescription: String { description }
}

struct EntryAttachmentSummary: Identifiable, @unchecked Sendable,
  CustomStringConvertible, CustomDebugStringConvertible
{
  let id: UUID
  let name: VaultKernSensitiveString
  let size: UInt64

  init(id: UUID = UUID(), name: VaultKernSensitiveString, size: UInt64) {
    self.id = id
    self.name = name
    self.size = size
  }

  init(id: UUID = UUID(), name: String, size: UInt64) {
    self.init(id: id, name: VaultKernSensitiveString(name), size: size)
  }

  func close() {
    name.close()
  }

  var description: String { "EntryAttachmentSummary([REDACTED])" }
  var debugDescription: String { description }
}

final class EntryDraft: @unchecked Sendable,
  CustomStringConvertible, CustomDebugStringConvertible
{
  let id: VaultKernSensitiveString
  let title: VaultKernSensitiveString
  let username: VaultKernSensitiveString
  let password: VaultKernSensitiveString
  let url: VaultKernSensitiveString
  let notes: VaultKernSensitiveString
  let totpURI: VaultKernSensitiveString
  var customFields: [EntryCustomFieldDraft]
  var attachments: [EntryAttachmentSummary]
  let passkeyRelyingParty: VaultKernSensitiveString?

  private let closeLock = NSLock()
  private var isClosed = false

  init(
    id: VaultKernSensitiveString,
    title: VaultKernSensitiveString,
    username: VaultKernSensitiveString,
    password: VaultKernSensitiveString,
    url: VaultKernSensitiveString,
    notes: VaultKernSensitiveString,
    totpURI: VaultKernSensitiveString,
    customFields: [EntryCustomFieldDraft],
    attachments: [EntryAttachmentSummary],
    passkeyRelyingParty: VaultKernSensitiveString?
  ) {
    self.id = id
    self.title = title
    self.username = username
    self.password = password
    self.url = url
    self.notes = notes
    self.totpURI = totpURI
    self.customFields = customFields
    self.attachments = attachments
    self.passkeyRelyingParty = passkeyRelyingParty
  }

  convenience init(
    id: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    totpURI: String,
    customFields: [EntryCustomFieldDraft],
    attachments: [EntryAttachmentSummary],
    passkeyRelyingParty: String?
  ) {
    self.init(
      id: VaultKernSensitiveString(id),
      title: VaultKernSensitiveString(title),
      username: VaultKernSensitiveString(username),
      password: VaultKernSensitiveString(password),
      url: VaultKernSensitiveString(url),
      notes: VaultKernSensitiveString(notes),
      totpURI: VaultKernSensitiveString(totpURI),
      customFields: customFields,
      attachments: attachments,
      passkeyRelyingParty: passkeyRelyingParty.map { VaultKernSensitiveString($0) }
    )
  }

  func close() {
    closeLock.lock()
    guard !isClosed else {
      closeLock.unlock()
      return
    }
    isClosed = true
    closeLock.unlock()

    id.close()
    title.close()
    username.close()
    password.close()
    url.close()
    notes.close()
    totpURI.close()
    for field in customFields {
      field.close()
    }
    customFields.removeAll(keepingCapacity: false)
    for attachment in attachments {
      attachment.close()
    }
    attachments.removeAll(keepingCapacity: false)
    passkeyRelyingParty?.close()
  }

  deinit { close() }

  var description: String { "EntryDraft([REDACTED])" }
  var debugDescription: String { description }
}

extension EntryDetailDto {
  func consumeAsDraft() -> EntryDraft {
    totp?.close()
    let retainedRelyingParty = passkey?.relyingParty
    if let passkey {
      passkey.username.close()
      passkey.credentialId.close()
      passkey.generatedUserId?.close()
      passkey.userHandle?.close()
    }

    return EntryDraft(
      id: id,
      title: title,
      username: username,
      password: password,
      url: url,
      notes: notes,
      totpURI: totpUri ?? VaultKernSensitiveString(""),
      customFields: customFields.map {
        EntryCustomFieldDraft(
          key: $0.key,
          value: $0.value,
          isProtected: $0.protected
        )
      },
      attachments: attachments.map {
        EntryAttachmentSummary(name: $0.name, size: $0.size)
      },
      passkeyRelyingParty: retainedRelyingParty
    )
  }
}

final class OwnedEntryFields: @unchecked Sendable {
  let value: EntryFieldsDto

  private let owners: [VaultKernSensitiveString]
  private let lock = NSLock()
  private var isClosed = false

  init(draft: EntryDraft) {
    let title = draft.title.copyForTransfer()
    let username = draft.username.copyForTransfer()
    let password = draft.password.copyForTransfer()
    let url = draft.url.copyForTransfer()
    let notes = draft.notes.copyForTransfer()
    let totpURI = draft.totpURI.isEmpty ? nil : draft.totpURI.copyForTransfer()
    var owners = [title, username, password, url, notes]
    if let totpURI {
      owners.append(totpURI)
    }
    let customFields = draft.customFields.map { field in
      let key = field.key.copyForTransfer()
      let value = field.value.copyForTransfer()
      owners.append(contentsOf: [key, value])
      return EntryCustomFieldDto(key: key, value: value, protected: field.isProtected)
    }
    self.owners = owners
    value = EntryFieldsDto(
      title: title,
      username: username,
      password: password,
      url: url,
      notes: notes,
      totpUri: totpURI,
      customFields: customFields
    )
  }

  func close() {
    lock.lock()
    guard !isClosed else {
      lock.unlock()
      return
    }
    isClosed = true
    lock.unlock()
    for owner in owners {
      owner.close()
    }
  }

  deinit { close() }
}
