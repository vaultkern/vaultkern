import Foundation

enum VaultKernIPCContract {
  static let teamID = "4HBAZ2M969"
  static let residentIdentifier = "com.vaultkern.macos"
  static let shimIdentifier = "com.vaultkern.macos.native-messaging-shim"
  static let residentMachService = "com.vaultkern.macos.native-messaging-shim.resident"
  static let browserMachService = "com.vaultkern.macos.native-messaging-shim.browser"
  static let agentPlist = "com.vaultkern.macos.native-messaging-shim.agent.plist"
  static let nativeHostName = "com.vaultkern.runtime"
  static let maximumMessageBytes = 8 * 1024 * 1024
  static let requestTimeout: TimeInterval = 5 * 60

  static let residentRequirement =
    "anchor apple generic and identifier \"\(residentIdentifier)\" and certificate leaf[subject.OU] = \"\(teamID)\""
  static let shimRequirement =
    "anchor apple generic and identifier \"\(shimIdentifier)\" and certificate leaf[subject.OU] = \"\(teamID)\""

  static func isSupportedBrowserOrigin(_ origin: String) -> Bool {
    let range = NSRange(origin.startIndex..<origin.endIndex, in: origin)
    return browserOriginExpression.firstMatch(in: origin, range: range)?.range == range
  }

  private static let browserOriginExpression = try! NSRegularExpression(
    pattern: #"\Achrome-extension://[a-p]{32}/\z"#
  )
}

extension Data {
  mutating func vaultKernWipe() {
    resetBytes(in: startIndex..<endIndex)
    removeAll(keepingCapacity: false)
  }

  static func vaultKernDeepCopy(_ source: NSData) -> Data {
    var copy = Data(count: source.length)
    copy.withUnsafeMutableBytes { destination in
      guard let destinationAddress = destination.baseAddress, source.length > 0 else { return }
      destinationAddress.copyMemory(from: source.bytes, byteCount: source.length)
    }
    return copy
  }

  func vaultKernImmutableCopy() -> NSData {
    withUnsafeBytes { source in
      guard let address = source.baseAddress, !isEmpty else { return NSData() }
      return NSData(bytes: address, length: count)
    }
  }
}
