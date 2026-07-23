import XCTest

@testable import VaultKern

final class EntryDraftValidationTests: XCTestCase {
  func testRejectsReservedCustomFieldFamilies() {
    for key in ["Password", "otp", "TimeOtp-Period", "HmacOtp-Counter", "KPEX_PASSKEY_PRIVATE_KEY"]
    {
      var draft = testDraft()
      draft.customFields = [
        EntryCustomFieldDraft(key: key, value: "value", isProtected: true)
      ]

      XCTAssertThrowsError(try draft.validateForSave(), "reserved key: \(key)") { error in
        XCTAssertEqual(
          error as? EntryDraftValidationError,
          .reservedCustomFieldKey
        )
      }
    }
  }

  func testRejectsDuplicateCustomFieldNames() {
    var draft = testDraft()
    draft.customFields = [
      EntryCustomFieldDraft(key: "API Token", value: "one", isProtected: true),
      EntryCustomFieldDraft(key: "API Token", value: "two", isProtected: true),
    ]

    XCTAssertThrowsError(try draft.validateForSave()) { error in
      XCTAssertEqual(
        error as? EntryDraftValidationError,
        .duplicateCustomFieldKey
      )
    }
  }

  func testRejectsUnnamedCustomFieldWithValue() {
    var draft = testDraft()
    draft.customFields = [
      EntryCustomFieldDraft(key: "  ", value: "must not be dropped", isProtected: true)
    ]

    XCTAssertThrowsError(try draft.validateForSave()) { error in
      XCTAssertEqual(
        error as? EntryDraftValidationError,
        .missingCustomFieldKey
      )
    }
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
      customFields: [],
      attachments: [],
      passkeyRelyingParty: nil
    )
  }
}
