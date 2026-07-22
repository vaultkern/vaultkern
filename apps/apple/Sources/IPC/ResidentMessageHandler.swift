import Foundation

protocol BrowserProtocolSession: AnyObject, Sendable {
  func handleMessage(message: VaultKernSensitiveBytes) throws -> VaultKernSensitiveBytes
  func cancel()
}

extension VaultProtocolSession: BrowserProtocolSession {}

final class ResidentMessageHandler: NSObject, VaultKernResidentEndpoint, @unchecked Sendable {
  typealias SessionFactory = @Sendable () -> any BrowserProtocolSession

  private let lock = NSLock()
  private let sessionFactory: SessionFactory
  private var sessions: [String: any BrowserProtocolSession] = [:]

  init(sessionFactory: @escaping SessionFactory) {
    self.sessionFactory = sessionFactory
  }

  func openChannel(
    _ channelID: String,
    origin: String,
    withReply reply: @escaping (Bool, NSString?) -> Void
  ) {
    guard !channelID.isEmpty, VaultKernIPCContract.isSupportedBrowserOrigin(origin) else {
      reply(false, "invalid native messaging channel" as NSString)
      return
    }

    lock.lock()
    defer { lock.unlock() }
    guard sessions[channelID] == nil else {
      reply(false, "native messaging channel is already open" as NSString)
      return
    }
    sessions[channelID] = sessionFactory()
    reply(true, nil)
  }

  func handleMessage(
    _ channelID: String,
    payload: NSData,
    withReply reply: @escaping (NSData?, NSString?, NSString?) -> Void
  ) {
    guard payload.length <= VaultKernIPCContract.maximumMessageBytes else {
      reply(nil, "invalid_request" as NSString, "message exceeds the hard size limit" as NSString)
      return
    }

    lock.lock()
    let session = sessions[channelID]
    lock.unlock()
    guard let session else {
      reply(nil, "channel_closed" as NSString, "native messaging channel is not open" as NSString)
      return
    }

    var request = Data.vaultKernDeepCopy(payload)
    let owner = VaultKernSensitiveBytes(request)
    request.vaultKernWipe()
    do {
      let responseOwner = try session.handleMessage(message: owner)
      owner.close()
      var response = responseOwner.copyData()
      responseOwner.close()
      let xpcResponse = response.vaultKernImmutableCopy()
      response.vaultKernWipe()
      reply(xpcResponse, nil, nil)
    } catch {
      owner.close()
      reply(nil, "resident_failure" as NSString, "resident runtime rejected the request" as NSString)
    }
  }

  func closeChannel(_ channelID: String) {
    lock.lock()
    let session = sessions.removeValue(forKey: channelID)
    lock.unlock()
    session?.cancel()
  }

  deinit {
    lock.lock()
    let active = Array(sessions.values)
    sessions.removeAll()
    lock.unlock()
    active.forEach { $0.cancel() }
  }
}
