import Foundation
import ServiceManagement

enum ResidentIPCError: LocalizedError {
  case registrationFailed(String)
  case serviceNotEnabled(SMAppService.Status)
  case connectionFailed(String)

  var errorDescription: String? {
    switch self {
    case .registrationFailed(let message):
      "Native messaging helper registration failed: \(message)"
    case .serviceNotEnabled(let status):
      "Native messaging helper is not enabled (status \(status.rawValue))."
    case .connectionFailed(let message):
      "Native messaging helper connection failed: \(message)"
    }
  }
}

final class ResidentIPCController: @unchecked Sendable {
  private let handler: ResidentMessageHandler
  private let service = ResidentIPCController.service
  private var connection: NSXPCConnection?

  private static var service: SMAppService {
    SMAppService.agent(plistName: VaultKernIPCContract.agentPlist)
  }

  init(sessionFactory: @escaping ResidentMessageHandler.SessionFactory) {
    handler = ResidentMessageHandler(sessionFactory: sessionFactory)
  }

  func start() throws {
    if service.status != .enabled {
      do {
        try service.register()
      } catch {
        throw ResidentIPCError.registrationFailed((error as NSError).description)
      }
    }
    guard service.status == .enabled else {
      throw ResidentIPCError.serviceNotEnabled(service.status)
    }

    let connection = NSXPCConnection(
      machServiceName: VaultKernIPCContract.residentMachService,
      options: []
    )
    connection.remoteObjectInterface = NSXPCInterface(with: VaultKernResidentBroker.self)
    connection.exportedInterface = NSXPCInterface(with: VaultKernResidentEndpoint.self)
    connection.exportedObject = handler
    connection.setCodeSigningRequirement(VaultKernIPCContract.shimRequirement)
    connection.activate()

    let completion = OneShotRegistration()
    let proxy = connection.remoteObjectProxyWithErrorHandler { error in
      completion.finish(false, (error as NSError).description)
    }
    guard let broker = proxy as? VaultKernResidentBroker else {
      connection.invalidate()
      throw ResidentIPCError.connectionFailed("broker proxy has the wrong interface")
    }
    broker.registerResident { accepted, message in
      completion.finish(accepted, message as String?)
    }
    guard completion.wait(timeout: 10) else {
      connection.invalidate()
      throw ResidentIPCError.connectionFailed("timed out registering the resident endpoint")
    }
    guard completion.accepted else {
      connection.invalidate()
      throw ResidentIPCError.connectionFailed(completion.message ?? "registration was refused")
    }
    self.connection = connection
  }

  deinit {
    connection?.invalidate()
  }

  static func unregisterService() throws -> SMAppService.Status {
    let service = Self.service
    if service.status != .notRegistered {
      try service.unregister()
    }
    return service.status
  }
}

private final class OneShotRegistration: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var finished = false
  private(set) var accepted = false
  private(set) var message: String?

  func finish(_ accepted: Bool, _ message: String?) {
    lock.lock()
    defer { lock.unlock() }
    guard !finished else { return }
    finished = true
    self.accepted = accepted
    self.message = message
    semaphore.signal()
  }

  func wait(timeout: TimeInterval) -> Bool {
    semaphore.wait(timeout: .now() + timeout) == .success
  }
}
