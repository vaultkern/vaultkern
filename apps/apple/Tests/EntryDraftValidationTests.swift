import XCTest

@testable import VaultKern

final class EntryDraftValidationTests: XCTestCase {
  func testOwnedEntryFieldsHaveAnIndependentTransferLifetime() {
    let draft = testDraft()
    let fields = OwnedEntryFields(draft: draft)

    draft.notes.replace(with: "changed after transfer")
    draft.close()

    XCTAssertEqual(fields.value.notes.reveal(), "")
    XCTAssertEqual(fields.value.password.reveal(), "secret")
    fields.close()
    XCTAssertEqual(fields.value.password.reveal(), "")
  }

  func testDraftCloseClearsNestedSensitiveOwners() {
    let draft = testDraft()
    let customKey = draft.customFields[0].key
    let customValue = draft.customFields[0].value
    let attachmentName = draft.attachments[0].name

    draft.close()

    XCTAssertEqual(customKey.reveal(), "")
    XCTAssertEqual(customValue.reveal(), "")
    XCTAssertEqual(attachmentName.reveal(), "")
  }

  private func testDraft() -> EntryDraft {
    EntryDraft(
      id: "entry",
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: "",
      totpURI: "",
      customFields: [
        EntryCustomFieldDraft(key: "API Token", value: "value", isProtected: true)
      ],
      attachments: [EntryAttachmentSummary(name: "secret.pdf", size: 42)],
      passkeyRelyingParty: nil
    )
  }
}
