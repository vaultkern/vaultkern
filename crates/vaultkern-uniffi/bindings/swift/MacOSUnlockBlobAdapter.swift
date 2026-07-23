#if os(macOS)
  import CryptoKit
  import Foundation
  import LocalAuthentication
  import Security

  /// Data-protection Keychain storage for the macOS 002 unlock blob.
  ///
  /// Each logical blob has a Secure Enclave P-256 key protected by
  /// `biometryCurrentSet`. The Keychain stores only the ECIES ciphertext and the
  /// non-exportable private key. Callers must provision `accessGroup` in the
  /// application's signed entitlements.
  public final class VaultKernMacOSUnlockBlobAdapter: UnlockBlobAdapter, @unchecked Sendable {
    public static let defaultService = "com.vaultkern.unlock-blob.v1"

    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM

    private let accessGroup: String
    private let service: String
    private let lock = NSLock()

    public init(
      accessGroup: String,
      service: String = VaultKernMacOSUnlockBlobAdapter.defaultService
    ) throws {
      guard !accessGroup.isEmpty else {
        throw PlatformAdapterError.Failure(details: "unlock blob access group is empty")
      }
      guard !service.isEmpty else {
        throw PlatformAdapterError.Failure(details: "unlock blob service is empty")
      }
      self.accessGroup = accessGroup
      self.service = service
    }

    public func supportsUnlockBlob() throws -> Bool {
      let context = LAContext()
      defer { context.invalidate() }
      var error: NSError?
      return context.canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        error: &error
      )
    }

    public func authorize(reason: String) throws {
      let context = LAContext()
      context.touchIDAuthenticationAllowableReuseDuration = 0
      defer { context.invalidate() }
      var availabilityError: NSError?
      guard
        context.canEvaluatePolicy(
          .deviceOwnerAuthenticationWithBiometrics,
          error: &availabilityError
        )
      else {
        throw Self.authorizationError(
          availabilityError,
          operation: "LAContext.canEvaluatePolicy"
        )
      }

      let evaluation = AuthenticationEvaluation()
      context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: reason.isEmpty ? "Authenticate with Touch ID" : reason
      ) { success, error in
        evaluation.finish(success: success, error: error)
      }
      let result = evaluation.wait()
      guard result.success else {
        throw Self.authorizationError(
          result.error,
          operation: "LAContext.evaluatePolicy"
        )
      }
    }

    public func storeRequiresUserPresence() throws -> Bool { false }

    // Loading decrypts with the ACL-protected private key, which presents the
    // one Touch ID prompt for the unlock operation.
    public func loadRequiresUserPresence() throws -> Bool { true }

    public func authorizeStoreUserPresence() throws {
      try authorize(reason: "Enable quick unlock for this vault")
    }

    public func storeBlob(key: String, value: VaultKernSensitiveBytes) throws {
      var plaintext = value.copyData()
      value.close()
      defer { plaintext.resetBytes(in: plaintext.startIndex..<plaintext.endIndex) }

      try withLock {
        let identifier = try itemIdentifier(for: key)
        let existing = copyPrivateKey(identifier: identifier, context: nil)
        let privateKey: SecKey
        let createdKey: Bool
        switch existing.status {
        case errSecSuccess:
          guard let key = existing.key else {
            throw PlatformAdapterError.Unexpected
          }
          privateKey = key
          createdKey = false
        case errSecItemNotFound:
          privateKey = try createPrivateKey(identifier: identifier)
          createdKey = true
        default:
          throw Self.statusError(
            existing.status,
            operation: "SecItemCopyMatching(unlock key)"
          )
        }

        do {
          guard let publicKey = SecKeyCopyPublicKey(privateKey),
            SecKeyIsAlgorithmSupported(publicKey, .encrypt, Self.algorithm)
          else {
            throw PlatformAdapterError.Failure(
              details: "Secure Enclave key does not support ECIES AES-GCM encryption"
            )
          }
          var encryptionError: Unmanaged<CFError>?
          guard
            let ciphertext = SecKeyCreateEncryptedData(
              publicKey,
              Self.algorithm,
              plaintext as CFData,
              &encryptionError
            ) as Data?
          else {
            throw Self.cfError(
              encryptionError?.takeRetainedValue(),
              operation: "SecKeyCreateEncryptedData"
            )
          }
          try replaceCiphertext(ciphertext, identifier: identifier)
        } catch {
          if createdKey {
            _ = SecItemDelete(keyQuery(identifier: identifier) as CFDictionary)
          }
          throw error
        }
      }
    }

    public func loadBlob(key: String) throws -> VaultKernSensitiveBytes? {
      try withLock {
        let identifier = try itemIdentifier(for: key)
        guard let ciphertext = try copyCiphertext(identifier: identifier) else {
          return nil
        }

        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = "Unlock this VaultKern vault"
        context.interactionNotAllowed = false
        defer { context.invalidate() }
        let privateKeyResult = copyPrivateKey(identifier: identifier, context: context)
        switch privateKeyResult.status {
        case errSecSuccess:
          break
        case errSecItemNotFound:
          throw PlatformAdapterError.Invalidated
        case errSecUserCanceled:
          throw PlatformAdapterError.Cancelled
        default:
          throw Self.statusError(
            privateKeyResult.status,
            operation: "SecItemCopyMatching(unlock key)"
          )
        }
        guard let privateKey = privateKeyResult.key,
          SecKeyIsAlgorithmSupported(privateKey, .decrypt, Self.algorithm)
        else {
          throw PlatformAdapterError.Invalidated
        }

        var decryptionError: Unmanaged<CFError>?
        guard
          var plaintext = SecKeyCreateDecryptedData(
            privateKey,
            Self.algorithm,
            ciphertext as CFData,
            &decryptionError
          ) as Data?
        else {
          throw Self.decryptionError(decryptionError?.takeRetainedValue())
        }
        defer { plaintext.resetBytes(in: plaintext.startIndex..<plaintext.endIndex) }
        return VaultKernSensitiveBytes(plaintext)
      }
    }

    public func containsBlob(key: String) throws -> Bool {
      try withLock {
        let identifier = try itemIdentifier(for: key)
        let status = SecItemCopyMatching(blobQuery(identifier: identifier) as CFDictionary, nil)
        switch status {
        case errSecSuccess:
          return true
        case errSecItemNotFound:
          return false
        default:
          throw Self.statusError(status, operation: "SecItemCopyMatching(unlock blob)")
        }
      }
    }

    public func deleteBlob(key: String) throws {
      try withLock {
        let identifier = try itemIdentifier(for: key)
        try deleteRecord(identifier: identifier)
      }
    }

    public func purgeQuickUnlockRecords() throws -> UInt64 {
      try withLock {
        let identifiers = try copyBlobIdentifiers()
        for identifier in identifiers {
          try deleteRecord(identifier: identifier)
        }
        return UInt64(identifiers.count)
      }
    }

    private func withLock<T>(_ body: () throws -> T) rethrows -> T {
      lock.lock()
      defer { lock.unlock() }
      return try body()
    }

    private func itemIdentifier(for key: String) throws -> String {
      guard !key.isEmpty else {
        throw PlatformAdapterError.Failure(details: "unlock blob key is empty")
      }
      return SHA256.hash(data: Data(key.utf8))
        .map { String(format: "%02x", $0) }
        .joined()
    }

    private func blobQuery(identifier: String) -> [CFString: Any] {
      var query = blobCollectionQuery()
      query[kSecAttrAccount] = identifier
      return query
    }

    private func blobCollectionQuery() -> [CFString: Any] {
      [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccessGroup: accessGroup,
        kSecUseDataProtectionKeychain: true,
      ]
    }

    private func keyQuery(identifier: String) -> [CFString: Any] {
      [
        kSecClass: kSecClassKey,
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        kSecAttrApplicationTag: keyTag(identifier: identifier),
        kSecAttrAccessGroup: accessGroup,
        kSecUseDataProtectionKeychain: true,
      ]
    }

    private func keyTag(identifier: String) -> Data {
      Data("\(service).key.\(identifier)".utf8)
    }

    private func createPrivateKey(identifier: String) throws -> SecKey {
      var accessError: Unmanaged<CFError>?
      guard
        let access = SecAccessControlCreateWithFlags(
          nil,
          kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
          [.privateKeyUsage, .biometryCurrentSet],
          &accessError
        )
      else {
        throw Self.cfError(
          accessError?.takeRetainedValue(),
          operation: "SecAccessControlCreateWithFlags"
        )
      }

      let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        kSecUseDataProtectionKeychain: true,
        kSecPrivateKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: keyTag(identifier: identifier),
          kSecAttrAccessGroup: accessGroup,
          kSecAttrAccessControl: access,
        ],
      ]
      var creationError: Unmanaged<CFError>?
      guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &creationError) else {
        throw Self.cfError(
          creationError?.takeRetainedValue(),
          operation: "SecKeyCreateRandomKey"
        )
      }
      let returnedToken =
        (SecKeyCopyAttributes(key) as? [CFString: Any])?[kSecAttrTokenID]
        as? String
      guard returnedToken == (kSecAttrTokenIDSecureEnclave as String) else {
        _ = SecItemDelete(keyQuery(identifier: identifier) as CFDictionary)
        throw PlatformAdapterError.Failure(
          details: "created unlock key is not backed by the Secure Enclave"
        )
      }
      return key
    }

    private func copyPrivateKey(
      identifier: String,
      context: LAContext?
    ) -> (status: OSStatus, key: SecKey?) {
      var query = keyQuery(identifier: identifier)
      query[kSecReturnRef] = true
      query[kSecMatchLimit] = kSecMatchLimitOne
      let authenticationContext: LAContext
      if let context {
        authenticationContext = context
      } else {
        authenticationContext = LAContext()
        authenticationContext.interactionNotAllowed = true
      }
      query[kSecUseAuthenticationContext] = authenticationContext
      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      guard status == errSecSuccess, let result else {
        return (status, nil)
      }
      return (status, unsafeDowncast(result, to: SecKey.self))
    }

    private func replaceCiphertext(_ ciphertext: Data, identifier: String) throws {
      let query = blobQuery(identifier: identifier)
      let updateStatus = SecItemUpdate(
        query as CFDictionary,
        [kSecValueData: ciphertext] as CFDictionary
      )
      if updateStatus == errSecSuccess {
        return
      }
      guard updateStatus == errSecItemNotFound else {
        throw Self.statusError(updateStatus, operation: "SecItemUpdate(unlock blob)")
      }

      var add = query
      add[kSecValueData] = ciphertext
      add[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      let addStatus = SecItemAdd(add as CFDictionary, nil)
      guard addStatus == errSecSuccess else {
        throw Self.statusError(addStatus, operation: "SecItemAdd(unlock blob)")
      }
    }

    private func copyCiphertext(identifier: String) throws -> Data? {
      var query = blobQuery(identifier: identifier)
      query[kSecReturnData] = true
      query[kSecMatchLimit] = kSecMatchLimitOne
      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      switch status {
      case errSecSuccess:
        guard let ciphertext = result as? Data else {
          throw PlatformAdapterError.Unexpected
        }
        return ciphertext
      case errSecItemNotFound:
        return nil
      default:
        throw Self.statusError(status, operation: "SecItemCopyMatching(unlock blob)")
      }
    }

    private func copyBlobIdentifiers() throws -> [String] {
      var query = blobCollectionQuery()
      query[kSecReturnAttributes] = true
      query[kSecMatchLimit] = kSecMatchLimitAll
      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      switch status {
      case errSecSuccess:
        guard let items = result as? [NSDictionary] else {
          throw PlatformAdapterError.Unexpected
        }
        return try items.map { item in
          guard let identifier = item[kSecAttrAccount] as? String else {
            throw PlatformAdapterError.Unexpected
          }
          return identifier
        }
      case errSecItemNotFound:
        return []
      default:
        throw Self.statusError(status, operation: "SecItemCopyMatching(all unlock blobs)")
      }
    }

    private func deleteRecord(identifier: String) throws {
      let keyStatus = SecItemDelete(keyQuery(identifier: identifier) as CFDictionary)
      guard keyStatus == errSecSuccess || keyStatus == errSecItemNotFound else {
        throw Self.statusError(keyStatus, operation: "SecItemDelete(unlock key)")
      }
      let blobStatus = SecItemDelete(blobQuery(identifier: identifier) as CFDictionary)
      guard blobStatus == errSecSuccess || blobStatus == errSecItemNotFound else {
        throw Self.statusError(blobStatus, operation: "SecItemDelete(unlock blob)")
      }
    }

    private static func authorizationError(
      _ error: Error?,
      operation: String
    ) -> PlatformAdapterError {
      guard let error else { return .Unexpected }
      let nsError = error as NSError
      if isCancellation(nsError) {
        return .Cancelled
      }
      return .Failure(
        details: "\(operation): \(nsError.domain) \(nsError.code): \(nsError.localizedDescription)"
      )
    }

    private static func decryptionError(_ error: CFError?) -> PlatformAdapterError {
      guard let error else { return .Invalidated }
      let nsError = error as NSError
      if isCancellation(nsError) {
        return .Cancelled
      }
      if shouldPreserveEnrollment(nsError) {
        return .Failure(
          details:
            "SecKeyCreateDecryptedData: \(nsError.domain) \(nsError.code): \(nsError.localizedDescription)"
        )
      }
      return .Invalidated
    }

    private static func isCancellation(_ error: NSError) -> Bool {
      if error.domain == LAError.errorDomain {
        return [
          LAError.Code.userCancel.rawValue,
          LAError.Code.userFallback.rawValue,
          LAError.Code.appCancel.rawValue,
          LAError.Code.systemCancel.rawValue,
        ].contains(error.code)
      }
      return error.domain == NSOSStatusErrorDomain && error.code == Int(errSecUserCanceled)
    }

    private static func shouldPreserveEnrollment(_ error: NSError) -> Bool {
      if error.domain == LAError.errorDomain {
        return [
          LAError.Code.authenticationFailed.rawValue,
          LAError.Code.biometryLockout.rawValue,
          LAError.Code.biometryNotAvailable.rawValue,
          LAError.Code.invalidContext.rawValue,
          LAError.Code.notInteractive.rawValue,
        ].contains(error.code)
      }
      return error.domain == NSOSStatusErrorDomain
        && [Int(errSecAuthFailed), Int(errSecInteractionNotAllowed)].contains(error.code)
    }

    private static func statusError(
      _ status: OSStatus,
      operation: String
    ) -> PlatformAdapterError {
      let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
      return .Failure(details: "\(operation): OSStatus \(status) (\(message))")
    }

    private static func cfError(
      _ error: CFError?,
      operation: String
    ) -> PlatformAdapterError {
      guard let error else { return .Unexpected }
      let nsError = error as NSError
      return .Failure(
        details: "\(operation): \(nsError.domain) \(nsError.code): \(nsError.localizedDescription)"
      )
    }
  }

  private final class AuthenticationEvaluation: @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var success = false
    private var error: Error?

    func finish(success: Bool, error: Error?) {
      lock.lock()
      self.success = success
      self.error = error
      lock.unlock()
      semaphore.signal()
    }

    func wait() -> (success: Bool, error: Error?) {
      semaphore.wait()
      lock.lock()
      defer { lock.unlock() }
      return (success, error)
    }
  }
#endif
