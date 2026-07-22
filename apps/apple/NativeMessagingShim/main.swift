import Darwin
import Foundation

private struct NativeHostTransportError: Encodable {
  let type = "error"
  let code: String
  let message: String
  let requestId: String?
}

private struct RequestIDProbe: Decodable {
  let requestId: String?
}

private final class BrokerState: @unchecked Sendable {
  private let lock = NSLock()
  private var residentConnection: NSXPCConnection?

  func register(_ connection: NSXPCConnection) {
    lock.lock()
    let previous = residentConnection
    residentConnection = connection
    lock.unlock()
    if previous !== connection {
      previous?.invalidate()
    }
  }

  func clear(_ connection: NSXPCConnection) {
    lock.lock()
    if residentConnection === connection {
      residentConnection = nil
    }
    lock.unlock()
  }

  func residentProxy(
    errorHandler: @escaping @Sendable (Error) -> Void
  ) -> VaultKernResidentEndpoint? {
    lock.lock()
    let connection = residentConnection
    lock.unlock()
    return connection?.remoteObjectProxyWithErrorHandler(errorHandler)
      as? VaultKernResidentEndpoint
  }
}

private final class ResidentRegistrationService: NSObject, VaultKernResidentBroker,
  @unchecked Sendable
{
  private let state: BrokerState
  private weak var connection: NSXPCConnection?

  init(state: BrokerState, connection: NSXPCConnection) {
    self.state = state
    self.connection = connection
  }

  func registerResident(withReply reply: @escaping (Bool, NSString?) -> Void) {
    guard let connection else {
      reply(false, "resident connection is unavailable" as NSString)
      return
    }
    state.register(connection)
    reply(true, nil)
  }
}

private final class BrowserForwardingService: NSObject, VaultKernBrowserBroker,
  @unchecked Sendable
{
  private let lock = NSLock()
  private let state: BrokerState
  private var channelID: String?

  init(state: BrokerState) {
    self.state = state
  }

  func openChannel(
    _ channelID: String,
    origin: String,
    withReply reply: @escaping (Bool, NSString?) -> Void
  ) {
    let completion = OpenChannelReply(reply)
    guard !channelID.isEmpty, VaultKernIPCContract.isSupportedBrowserOrigin(origin) else {
      completion.finish(false, "invalid native messaging channel" as NSString)
      return
    }
    lock.lock()
    guard self.channelID == nil else {
      lock.unlock()
      completion.finish(false, "native messaging channel is already open" as NSString)
      return
    }
    self.channelID = channelID
    lock.unlock()

    guard let resident = state.residentProxy(errorHandler: { [weak self] _ in
      self?.clearChannel(channelID)
      completion.finish(false, "resident endpoint disconnected" as NSString)
    }) else {
      clearChannel(channelID)
      completion.finish(false, "resident endpoint is unavailable" as NSString)
      return
    }
    resident.openChannel(channelID, origin: origin) { [weak self] accepted, message in
      if !accepted { self?.clearChannel(channelID) }
      completion.finish(accepted, message)
    }
  }

  func forwardMessage(
    _ channelID: String,
    payload: NSData,
    withReply reply: @escaping (NSData?, NSString?, NSString?) -> Void
  ) {
    let completion = PayloadReply(reply)
    guard payload.length <= VaultKernIPCContract.maximumMessageBytes else {
      completion.finish(
        nil,
        "invalid_request" as NSString,
        "message exceeds the hard size limit" as NSString
      )
      return
    }
    lock.lock()
    let matches = self.channelID == channelID
    lock.unlock()
    guard matches else {
      completion.finish(
        nil,
        "channel_closed" as NSString,
        "native messaging channel is not open" as NSString
      )
      return
    }
    guard let resident = state.residentProxy(errorHandler: { _ in
      completion.finish(
        nil,
        "resident_unavailable" as NSString,
        "resident endpoint disconnected" as NSString
      )
    }) else {
      completion.finish(
        nil,
        "resident_unavailable" as NSString,
        "resident endpoint is unavailable" as NSString
      )
      return
    }
    resident.handleMessage(channelID, payload: payload) { response, code, message in
      completion.finish(response, code, message)
    }
  }

  func closeChannel(_ channelID: String) {
    guard clearChannel(channelID) else { return }
    state.residentProxy(errorHandler: { _ in })?.closeChannel(channelID)
  }

  @discardableResult
  private func clearChannel(_ channelID: String) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard self.channelID == channelID else { return false }
    self.channelID = nil
    return true
  }

  deinit {
    lock.lock()
    let channelID = channelID
    self.channelID = nil
    lock.unlock()
    if let channelID {
      state.residentProxy(errorHandler: { _ in })?.closeChannel(channelID)
    }
  }
}

private final class OpenChannelReply: @unchecked Sendable {
  private let lock = NSLock()
  private var reply: ((Bool, NSString?) -> Void)?

  init(_ reply: @escaping (Bool, NSString?) -> Void) {
    self.reply = reply
  }

  func finish(_ accepted: Bool, _ message: NSString?) {
    lock.lock()
    let reply = reply
    self.reply = nil
    lock.unlock()
    reply?(accepted, message)
  }
}

private final class PayloadReply: @unchecked Sendable {
  private let lock = NSLock()
  private var reply: ((NSData?, NSString?, NSString?) -> Void)?

  init(_ reply: @escaping (NSData?, NSString?, NSString?) -> Void) {
    self.reply = reply
  }

  func finish(_ response: NSData?, _ code: NSString?, _ message: NSString?) {
    lock.lock()
    let reply = reply
    self.reply = nil
    lock.unlock()
    reply?(response, code, message)
  }
}

private final class ResidentListenerDelegate: NSObject, NSXPCListenerDelegate,
  @unchecked Sendable
{
  let state: BrokerState

  init(state: BrokerState) {
    self.state = state
  }

  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    connection.remoteObjectInterface = NSXPCInterface(with: VaultKernResidentEndpoint.self)
    connection.exportedInterface = NSXPCInterface(with: VaultKernResidentBroker.self)
    connection.exportedObject = ResidentRegistrationService(state: state, connection: connection)
    connection.invalidationHandler = { [state, weak connection] in
      if let connection { state.clear(connection) }
    }
    connection.activate()
    return true
  }
}

private final class BrowserListenerDelegate: NSObject, NSXPCListenerDelegate,
  @unchecked Sendable
{
  let state: BrokerState

  init(state: BrokerState) {
    self.state = state
  }

  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    connection.exportedInterface = NSXPCInterface(with: VaultKernBrowserBroker.self)
    connection.exportedObject = BrowserForwardingService(state: state)
    connection.activate()
    return true
  }
}

private final class NativeHostClient: @unchecked Sendable {
  private let connection: NSXPCConnection
  private let closeLock = NSLock()
  private let channelID = UUID().uuidString
  private let origin: String
  private var closed = false

  init(origin: String) throws {
    self.origin = origin
    connection = NSXPCConnection(
      machServiceName: VaultKernIPCContract.browserMachService,
      options: []
    )
    connection.remoteObjectInterface = NSXPCInterface(with: VaultKernBrowserBroker.self)
    connection.setCodeSigningRequirement(VaultKernIPCContract.shimRequirement)
    connection.activate()
  }

  func open() throws {
    let result = OneShotResult()
    guard
      let broker = connection.remoteObjectProxyWithErrorHandler({ error in
        result.finish(accepted: false, message: (error as NSError).description)
      }) as? VaultKernBrowserBroker
    else {
      throw NativeHostFailure("broker proxy has the wrong interface")
    }
    broker.openChannel(channelID, origin: origin) { accepted, message in
      result.finish(accepted: accepted, message: message as String?)
    }
    guard result.wait(timeout: 10) else {
      throw NativeHostFailure("timed out opening the resident channel")
    }
    guard result.accepted else {
      throw NativeHostFailure(result.message ?? "resident channel was refused")
    }
  }

  func send(_ payload: NSData) -> (NSData?, String?, String?) {
    let result = OneShotPayload()
    guard
      let broker = connection.remoteObjectProxyWithErrorHandler({ error in
        result.finish(
          response: nil,
          code: "resident_unavailable",
          message: (error as NSError).description
        )
      }) as? VaultKernBrowserBroker
    else {
      return (nil, "resident_unavailable", "broker proxy has the wrong interface")
    }
    broker.forwardMessage(channelID, payload: payload) { response, code, message in
      result.finish(response: response, code: code as String?, message: message as String?)
    }
    guard result.wait(timeout: VaultKernIPCContract.requestTimeout) else {
      close()
      return (
        nil,
        "request_outcome_unknown",
        "resident IPC request timed out; its outcome is unknown and must not be retried"
      )
    }
    return (result.response, result.code, result.message)
  }

  func close() {
    closeLock.lock()
    guard !closed else {
      closeLock.unlock()
      return
    }
    closed = true
    closeLock.unlock()
    (connection.remoteObjectProxyWithErrorHandler({ _ in }) as? VaultKernBrowserBroker)?
      .closeChannel(channelID)
    connection.invalidate()
  }

  deinit { connection.invalidate() }
}

private struct NativeHostFailure: Error {
  let message: String
  init(_ message: String) { self.message = message }
}

private class OneShotBase: @unchecked Sendable {
  let lock = NSLock()
  let semaphore = DispatchSemaphore(value: 0)
  var finished = false

  func claim() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard !finished else { return false }
    finished = true
    return true
  }

  func wait(timeout: TimeInterval) -> Bool {
    semaphore.wait(timeout: .now() + timeout) == .success
  }
}

private final class OneShotResult: OneShotBase, @unchecked Sendable {
  private(set) var accepted = false
  private(set) var message: String?

  func finish(accepted: Bool, message: String?) {
    guard claim() else { return }
    self.accepted = accepted
    self.message = message
    semaphore.signal()
  }
}

private final class OneShotPayload: OneShotBase, @unchecked Sendable {
  private(set) var response: NSData?
  private(set) var code: String?
  private(set) var message: String?

  func finish(response: NSData?, code: String?, message: String?) {
    guard claim() else { return }
    self.response = response
    self.code = code
    self.message = message
    semaphore.signal()
  }
}

private func runBroker() -> Never {
  let state = BrokerState()
  let residentListener = NSXPCListener(
    machServiceName: VaultKernIPCContract.residentMachService
  )
  let residentDelegate = ResidentListenerDelegate(state: state)
  residentListener.delegate = residentDelegate
  residentListener.setConnectionCodeSigningRequirement(VaultKernIPCContract.residentRequirement)

  let browserListener = NSXPCListener(
    machServiceName: VaultKernIPCContract.browserMachService
  )
  let browserDelegate = BrowserListenerDelegate(state: state)
  browserListener.delegate = browserDelegate
  browserListener.setConnectionCodeSigningRequirement(VaultKernIPCContract.shimRequirement)

  residentListener.activate()
  browserListener.activate()
  withExtendedLifetime((residentDelegate, browserDelegate)) {
    dispatchMain()
  }
}

private func runNativeHost(origin: String) -> Int32 {
  signal(SIGPIPE, SIG_IGN)
  let client: NativeHostClient
  do {
    client = try NativeHostClient(origin: origin)
    try client.open()
  } catch let error as NativeHostFailure {
    writeFrame(transportError(code: "resident_unavailable", message: error.message, requestID: nil))
    return 1
  } catch {
    writeFrame(transportError(code: "resident_unavailable", message: "resident IPC failed", requestID: nil))
    return 1
  }
  defer { client.close() }

  while true {
    var request: Data
    do {
      guard let next = try readFrame() else { return 0 }
      request = next
    } catch let error as NativeHostFailure {
      writeFrame(transportError(code: "invalid_request", message: error.message, requestID: nil))
      return 1
    } catch {
      return 1
    }

    let requestID = requestID(from: request)
    let xpcRequest = request.vaultKernImmutableCopy()
    request.vaultKernWipe()
    let (response, code, message) = client.send(xpcRequest)
    guard let response else {
      writeFrame(
        transportError(
          code: code ?? "resident_failure",
          message: message ?? "resident runtime rejected the request",
          requestID: requestID
        )
      )
      if code == "request_outcome_unknown" { return 1 }
      continue
    }
    guard response.length <= VaultKernIPCContract.maximumMessageBytes else {
      writeFrame(
        transportError(
          code: "response_too_large",
          message: "resident response exceeds the hard size limit",
          requestID: requestID
        )
      )
      continue
    }
    var responseData = Data.vaultKernDeepCopy(response)
    writeFrame(responseData)
    responseData.vaultKernWipe()
  }
}

private func readFrame() throws -> Data? {
  guard let lengthBytes = try readExactly(4) else { return nil }
  let length = lengthBytes.withUnsafeBytes { bytes in
    bytes.loadUnaligned(as: UInt32.self).littleEndian
  }
  guard length <= VaultKernIPCContract.maximumMessageBytes else {
    throw NativeHostFailure("native message exceeds the hard size limit")
  }
  return try readExactly(Int(length)) ?? {
    throw NativeHostFailure("native message ended before its payload")
  }()
}

private func readExactly(_ count: Int) throws -> Data? {
  var result = Data()
  result.reserveCapacity(count)
  while result.count < count {
    guard var chunk = try FileHandle.standardInput.read(upToCount: count - result.count),
      !chunk.isEmpty
    else {
      if result.isEmpty { return nil }
      throw NativeHostFailure("native message ended before its frame was complete")
    }
    result.append(chunk)
    chunk.vaultKernWipe()
  }
  return result
}

private func writeFrame(_ payload: Data) {
  guard payload.count <= VaultKernIPCContract.maximumMessageBytes,
    let length = UInt32(exactly: payload.count)
  else { return }
  var littleEndian = length.littleEndian
  FileHandle.standardOutput.write(Data(bytes: &littleEndian, count: 4))
  FileHandle.standardOutput.write(payload)
}

private func requestID(from payload: Data) -> String? {
  guard let requestID = try? JSONDecoder().decode(RequestIDProbe.self, from: payload).requestId,
    requestID.utf8.count <= 256
  else { return nil }
  return requestID
}

private func transportError(code: String, message: String, requestID: String?) -> Data {
  (try? JSONEncoder().encode(
    NativeHostTransportError(code: code, message: message, requestId: requestID)
  )) ?? Data()
}

let arguments = Array(CommandLine.arguments.dropFirst())
if arguments.isEmpty {
  runBroker()
}
guard let origin = arguments.first,
  VaultKernIPCContract.isSupportedBrowserOrigin(origin),
  arguments.dropFirst().allSatisfy({ $0.hasPrefix("--parent-window=") })
else {
  fputs("usage: VaultKernNativeMessagingShim [chrome-extension://<id>/ [--parent-window=<id>]]\n", stderr)
  exit(64)
}
exit(runNativeHost(origin: origin))
