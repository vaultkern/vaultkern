import XCTest

@testable import VaultKern

final class SensitiveOwnershipTests: XCTestCase {
  func testEntryDetailConsumptionTransfersOwnersAndCloseClearsThem() {
    let id = VaultKernSensitiveString("entry-id")
    let title = VaultKernSensitiveString("Example")
    let username = VaultKernSensitiveString("alice")
    let password = VaultKernSensitiveString("secret")
    let url = VaultKernSensitiveString("https://example.com")
    let notes = VaultKernSensitiveString("notes")
    let totp = VaultKernSensitiveString("123456")
    let totpURI = VaultKernSensitiveString("otpauth://totp/example")
    let customKey = VaultKernSensitiveString("account")
    let customValue = VaultKernSensitiveString("primary")
    let attachmentName = VaultKernSensitiveString("receipt.pdf")
    let detail = EntryDetailDto(
      id: id,
      title: title,
      username: username,
      password: password,
      url: url,
      notes: notes,
      modifiedAt: 1,
      totp: totp,
      totpUri: totpURI,
      passkey: nil,
      fieldProtection: EntryFieldProtectionDto(
        protectTitle: false,
        protectUsername: false,
        protectPassword: true,
        protectUrl: false,
        protectNotes: false
      ),
      customFields: [
        EntryCustomFieldDto(key: customKey, value: customValue, protected: true)
      ],
      attachments: [
        EntryAttachmentDto(name: attachmentName, size: 42, protectInMemory: true)
      ]
    )

    let draft = detail.consumeAsDraft()

    XCTAssertTrue(draft.password === password)
    XCTAssertEqual(draft.password.reveal(), "secret")
    XCTAssertEqual(totp.reveal(), "")
    for owner in [
      id, title, username, password, url, notes, totpURI, customKey, customValue,
      attachmentName,
    ] {
      XCTAssertFalse(owner.reveal().isEmpty)
    }

    draft.close()

    for owner in [
      id, title, username, password, url, notes, totp, totpURI, customKey, customValue,
      attachmentName,
    ] {
      XCTAssertEqual(owner.reveal(), "")
    }
  }

  func testSensitiveStringTransferCopyHasIndependentLifetime() {
    let source = VaultKernSensitiveString("secret")
    let transfer = source.copyForTransfer()

    source.replace(with: "updated")
    XCTAssertEqual(source.reveal(), "updated")
    XCTAssertEqual(transfer.reveal(), "secret")

    transfer.close()
    XCTAssertEqual(transfer.reveal(), "")
    XCTAssertEqual(source.reveal(), "updated")
    source.close()
  }

  func testEmptyPasswordRemainsARealCredentialWithoutAKeyFile() {
    let owner = VaultKernSensitiveString("")

    let submitted = CredentialSubmission.password(
      taking: owner,
      hasKeyFile: false,
      includesEmptyPassword: false
    )

    XCTAssertTrue(submitted === owner)
    submitted?.close()
  }

  func testKeyFileOnlySubmissionOmitsEmptyPasswordUnlessExplicitlyIncluded() {
    let omittedOwner = VaultKernSensitiveString("")
    XCTAssertNil(
      CredentialSubmission.password(
        taking: omittedOwner,
        hasKeyFile: true,
        includesEmptyPassword: false
      )
    )
    XCTAssertEqual(omittedOwner.reveal(), "")

    let includedOwner = VaultKernSensitiveString("")
    let included = CredentialSubmission.password(
      taking: includedOwner,
      hasKeyFile: true,
      includesEmptyPassword: true
    )
    XCTAssertTrue(included === includedOwner)
    included?.close()
  }

  func testUnavailableOneDriveAdapterClosesRejectedToken() {
    let token = VaultKernSensitiveString("refresh-token")
    let adapter = UnavailableOneDriveTokenAdapter()

    XCTAssertThrowsError(try adapter.storeRefreshToken(token: token))
    XCTAssertEqual(token.reveal(), "")
  }

  func testSwiftUIDraftsRedactDescriptions() {
    let customField = EntryCustomFieldDraft(
      key: "account",
      value: "hidden-value",
      isProtected: true
    )
    let attachment = EntryAttachmentSummary(name: "secret.pdf", size: 42)
    let draft = EntryDraft(
      id: "entry-id",
      title: "Example",
      username: "alice",
      password: "master-secret",
      url: "https://example.com",
      notes: "private note",
      totpURI: "otpauth://totp/example",
      customFields: [customField],
      attachments: [attachment],
      passkeyRelyingParty: "example.com"
    )

    XCTAssertEqual(String(describing: customField), "EntryCustomFieldDraft([REDACTED])")
    XCTAssertEqual(String(reflecting: customField), "EntryCustomFieldDraft([REDACTED])")
    XCTAssertEqual(String(describing: attachment), "EntryAttachmentSummary([REDACTED])")
    XCTAssertEqual(String(reflecting: attachment), "EntryAttachmentSummary([REDACTED])")
    XCTAssertEqual(String(describing: draft), "EntryDraft([REDACTED])")
    XCTAssertEqual(String(reflecting: draft), "EntryDraft([REDACTED])")
    draft.close()
  }
}
