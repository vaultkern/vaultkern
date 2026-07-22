#if os(macOS)
  import Foundation
  import Security

  /// Device-bound data-protection Keychain storage for the OneDrive refresh token.
  public final class VaultKernMacOSOneDriveTokenAdapter: OneDriveTokenAdapter,
    @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible
  {
    public static let defaultService = "com.vaultkern.onedrive-refresh-token.v1"
    public static let defaultAccount = "primary"

    private let accessGroup: String
    private let service: String
    private let account: String
    private let lock = NSLock()

    public init(
      accessGroup: String,
      service: String = VaultKernMacOSOneDriveTokenAdapter.defaultService,
      account: String = VaultKernMacOSOneDriveTokenAdapter.defaultAccount
    ) throws {
      guard !accessGroup.isEmpty else {
        throw PlatformAdapterError.Failure(details: "OneDrive token access group is empty")
      }
      guard !service.isEmpty else {
        throw PlatformAdapterError.Failure(details: "OneDrive token service is empty")
      }
      guard !account.isEmpty else {
        throw PlatformAdapterError.Failure(details: "OneDrive token account is empty")
      }
      self.accessGroup = accessGroup
      self.service = service
      self.account = account
    }

    public var description: String { "VaultKernMacOSOneDriveTokenAdapter([REDACTED])" }
    public var debugDescription: String { description }

    public func loadRefreshToken() throws -> VaultKernSensitiveString? {
      try withLock {
        var query = baseQuery()
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
          guard var bytes = result as? Data else {
            throw PlatformAdapterError.Unexpected
          }
          defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
          guard !bytes.isEmpty else {
            throw PlatformAdapterError.Failure(details: "stored OneDrive token is empty")
          }
          return VaultKernSensitiveString(utf8Data: bytes)
        case errSecItemNotFound:
          return nil
        default:
          throw Self.statusError(status, operation: "SecItemCopyMatching(OneDrive token)")
        }
      }
    }

    public func storeRefreshToken(token: VaultKernSensitiveString) throws {
      var bytes = token.copyUTF8Data()
      token.close()
      defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
      guard !bytes.isEmpty else {
        throw PlatformAdapterError.Failure(details: "OneDrive refresh token is empty")
      }

      try withLock {
        let query = baseQuery()
        let updateStatus = SecItemUpdate(
          query as CFDictionary,
          [kSecValueData: bytes] as CFDictionary
        )
        if updateStatus == errSecSuccess {
          return
        }
        guard updateStatus == errSecItemNotFound else {
          throw Self.statusError(updateStatus, operation: "SecItemUpdate(OneDrive token)")
        }

        var add = query
        add[kSecValueData] = bytes
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        if addStatus == errSecDuplicateItem {
          let retryStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData: bytes] as CFDictionary
          )
          guard retryStatus == errSecSuccess else {
            throw Self.statusError(retryStatus, operation: "SecItemUpdate(OneDrive token retry)")
          }
          return
        }
        guard addStatus == errSecSuccess else {
          throw Self.statusError(addStatus, operation: "SecItemAdd(OneDrive token)")
        }
      }
    }

    public func deleteRefreshToken() throws {
      try withLock {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
          throw Self.statusError(status, operation: "SecItemDelete(OneDrive token)")
        }
      }
    }

    private func baseQuery() -> [CFString: Any] {
      [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecAttrAccessGroup: accessGroup,
        kSecAttrSynchronizable: false,
        kSecUseDataProtectionKeychain: true,
      ]
    }

    private func withLock<T>(_ body: () throws -> T) rethrows -> T {
      lock.lock()
      defer { lock.unlock() }
      return try body()
    }

    private static func statusError(
      _ status: OSStatus,
      operation: String
    ) -> PlatformAdapterError {
      let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
      return .Failure(details: "\(operation): OSStatus \(status) (\(message))")
    }
  }
#endif
