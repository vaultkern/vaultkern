import XCTest

@testable import VaultKern

final class SaveProgressTests: XCTestCase {
  func testFailedSaveRetainsStagedStateAndSkipsSecondEdit() {
    var progress = SaveProgress.clean
    progress.markDraftChanged()
    XCTAssertTrue(progress.shouldApplyDraft)

    progress.markEditApplied()

    XCTAssertEqual(progress, .staged)
    XCTAssertFalse(progress.shouldApplyDraft)
    XCTAssertTrue(progress.hasUncommittedChanges)
  }

  func testCommittedSaveReturnsToClean() {
    var progress = SaveProgress.dirty
    progress.markEditApplied()
    progress.markSaveSucceeded()

    XCTAssertEqual(progress, .clean)
    XCTAssertFalse(progress.hasUncommittedChanges)
  }

  func testDraftCanBeDiscardedBeforeRuntimeMutation() {
    var progress = SaveProgress.dirty
    progress.discardDraft()

    XCTAssertEqual(progress, .clean)
  }
}
