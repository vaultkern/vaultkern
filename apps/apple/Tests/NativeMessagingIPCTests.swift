import Foundation
import XCTest

@testable import VaultKern

final class NativeMessagingIPCTests: XCTestCase {
  func testContractPinsMutualPersonalTeamRequirements() {
    XCTAssertEqual(
      VaultKernIPCContract.residentRequirement,
      "anchor apple generic and identifier \"com.vaultkern.macos\" and certificate leaf[subject.OU] = \"4HBAZ2M969\""
    )
    XCTAssertEqual(
      VaultKernIPCContract.shimRequirement,
      "anchor apple generic and identifier \"com.vaultkern.macos.native-messaging-shim\" and certificate leaf[subject.OU] = \"4HBAZ2M969\""
    )
    XCTAssertNotEqual(
      VaultKernIPCContract.residentMachService,
      VaultKernIPCContract.browserMachService
    )
  }

  func testBrowserOriginValidationIsExact() {
    XCTAssertTrue(
      VaultKernIPCContract.isSupportedBrowserOrigin(
        "chrome-extension://akgcahfkhhffgcafpbbeihpmniekohik/"
      )
    )
    XCTAssertFalse(
      VaultKernIPCContract.isSupportedBrowserOrigin(
        "chrome-extension://akgcahfkhhffgcafpbbeihpmniekohik/manager.html"
      )
    )
    XCTAssertFalse(
      VaultKernIPCContract.isSupportedBrowserOrigin(
        "https://akgcahfkhhffgcafpbbeihpmniekohik/"
      )
    )
  }

  func testResidentHandlerOwnsOneCancelableSessionPerChannel() throws {
    let fake = FakeBrowserProtocolSession()
    let handler = ResidentMessageHandler { fake }
    let channelID = UUID().uuidString
    var opened = false
    handler.openChannel(
      channelID,
      origin: "chrome-extension://akgcahfkhhffgcafpbbeihpmniekohik/"
    ) { accepted, message in
      XCTAssertNil(message)
      opened = accepted
    }
    XCTAssertTrue(opened)

    let request = Data(#"{"version":1,"requestId":"swift","command":{"type":"get_session_state"}}"#.utf8)
    var response: NSData?
    handler.handleMessage(channelID, payload: request as NSData) { payload, code, message in
      XCTAssertNil(code)
      XCTAssertNil(message)
      response = payload
    }
    XCTAssertEqual(response as Data?, request)
    XCTAssertEqual(fake.messageCount, 1)

    handler.closeChannel(channelID)
    XCTAssertTrue(fake.canceled)
    var closedCode: NSString?
    handler.handleMessage(channelID, payload: request as NSData) { _, code, _ in
      closedCode = code
    }
    XCTAssertEqual(closedCode, "channel_closed")
    XCTAssertEqual(fake.messageCount, 1)
  }
}

private final class FakeBrowserProtocolSession: BrowserProtocolSession, @unchecked Sendable {
  private let lock = NSLock()
  private(set) var canceled = false
  private(set) var messageCount = 0

  func handleMessage(message: VaultKernSensitiveBytes) throws -> VaultKernSensitiveBytes {
    lock.lock()
    messageCount += 1
    lock.unlock()
    let data = message.copyData()
    message.close()
    return VaultKernSensitiveBytes(data)
  }

  func cancel() {
    lock.lock()
    canceled = true
    lock.unlock()
  }
}
