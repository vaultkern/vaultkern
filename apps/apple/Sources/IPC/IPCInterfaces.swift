import Foundation

@objc protocol VaultKernResidentEndpoint {
  func openChannel(
    _ channelID: String,
    origin: String,
    withReply reply: @escaping (Bool, NSString?) -> Void
  )

  func handleMessage(
    _ channelID: String,
    payload: NSData,
    withReply reply: @escaping (NSData?, NSString?, NSString?) -> Void
  )

  func closeChannel(_ channelID: String)
}

@objc protocol VaultKernResidentBroker {
  func registerResident(withReply reply: @escaping (Bool, NSString?) -> Void)
}

@objc protocol VaultKernBrowserBroker {
  func openChannel(
    _ channelID: String,
    origin: String,
    withReply reply: @escaping (Bool, NSString?) -> Void
  )

  func forwardMessage(
    _ channelID: String,
    payload: NSData,
    withReply reply: @escaping (NSData?, NSString?, NSString?) -> Void
  )

  func closeChannel(_ channelID: String)
}
