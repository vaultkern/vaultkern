import Foundation

struct EntryCustomFieldDraft: Identifiable, Sendable,
  CustomStringConvertible, CustomDebugStringConvertible
{
  let id: UUID
  var key: String
  var value: String
  var isProtected: Bool

  init(id: UUID = UUID(), key: String, value: String, isProtected: Bool) {
    self.id = id
    self.key = key
    self.value = value
    self.isProtected = isProtected
  }

  var description: String { "EntryCustomFieldDraft([REDACTED])" }
  var debugDescription: String { description }
}

struct EntryAttachmentSummary: Identifiable, Sendable,
  CustomStringConvertible, CustomDebugStringConvertible
{
  let id: UUID
  var name: String
  let size: UInt64

  init(id: UUID = UUID(), name: String, size: UInt64) {
    self.id = id
    self.name = name
    self.size = size
  }

  var description: String { "EntryAttachmentSummary([REDACTED])" }
  var debugDescription: String { description }
}

struct EntryDraft: Identifiable, Sendable,
  CustomStringConvertible, CustomDebugStringConvertible
{
  var id: String
  var title: String
  var username: String
  var password: String
  var url: String
  var notes: String
  var totpURI: String
  var customFields: [EntryCustomFieldDraft]
  var attachments: [EntryAttachmentSummary]
  var passkeyRelyingParty: String?

  mutating func clear() {
    id.removeAll(keepingCapacity: false)
    title.removeAll(keepingCapacity: false)
    username.removeAll(keepingCapacity: false)
    password.removeAll(keepingCapacity: false)
    url.removeAll(keepingCapacity: false)
    notes.removeAll(keepingCapacity: false)
    totpURI.removeAll(keepingCapacity: false)
    for index in customFields.indices {
      customFields[index].key.removeAll(keepingCapacity: false)
      customFields[index].value.removeAll(keepingCapacity: false)
    }
    customFields.removeAll(keepingCapacity: false)
    for index in attachments.indices {
      attachments[index].name.removeAll(keepingCapacity: false)
    }
    attachments.removeAll(keepingCapacity: false)
    passkeyRelyingParty?.removeAll(keepingCapacity: false)
    passkeyRelyingParty = nil
  }

  var description: String { "EntryDraft([REDACTED])" }
  var debugDescription: String { description }
}

extension EntryDetailDto {
  func consumeAsDraft() -> EntryDraft {
    defer { closeSensitiveValues() }
    return EntryDraft(
      id: id.reveal(),
      title: title.reveal(),
      username: username.reveal(),
      password: password.reveal(),
      url: url.reveal(),
      notes: notes.reveal(),
      totpURI: totpUri?.reveal() ?? "",
      customFields: customFields.map {
        EntryCustomFieldDraft(
          key: $0.key.reveal(),
          value: $0.value.reveal(),
          isProtected: $0.protected
        )
      },
      attachments: attachments.map {
        EntryAttachmentSummary(name: $0.name.reveal(), size: $0.size)
      },
      passkeyRelyingParty: passkey?.relyingParty.reveal()
    )
  }

  func closeSensitiveValues() {
    id.close()
    title.close()
    username.close()
    password.close()
    url.close()
    notes.close()
    totp?.close()
    totpUri?.close()
    for field in customFields {
      field.key.close()
      field.value.close()
    }
    for attachment in attachments {
      attachment.name.close()
    }
    if let passkey {
      passkey.username.close()
      passkey.credentialId.close()
      passkey.generatedUserId?.close()
      passkey.relyingParty.close()
      passkey.userHandle?.close()
    }
  }
}

final class OwnedEntryFields: @unchecked Sendable {
  let value: EntryFieldsDto

  private let owners: [VaultKernSensitiveString]
  private let lock = NSLock()
  private var isClosed = false

  init(draft: EntryDraft) {
    let title = VaultKernSensitiveString(draft.title)
    let username = VaultKernSensitiveString(draft.username)
    let password = VaultKernSensitiveString(draft.password)
    let url = VaultKernSensitiveString(draft.url)
    let notes = VaultKernSensitiveString(draft.notes)
    let totpURI = draft.totpURI.isEmpty ? nil : VaultKernSensitiveString(draft.totpURI)
    var owners = [title, username, password, url, notes]
    if let totpURI {
      owners.append(totpURI)
    }
    let customFields = draft.customFields.map { field in
      let key = VaultKernSensitiveString(field.key)
      let value = VaultKernSensitiveString(field.value)
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
