import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

private let statusOK: Int32 = 0
private let statusMissingItem: Int32 = 1
private let statusAuthenticationFailed: Int32 = 2
private let statusKeyInvalidated: Int32 = 3
private let statusInteractionUnavailable: Int32 = 4
private let statusPlatformFailure: Int32 = 5

private struct BridgeInputError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

private func copiedData(
    _ pointer: UnsafePointer<UInt8>?,
    length: Int,
    label: String
) throws -> Data {
    guard length >= 0 else {
        throw BridgeInputError(message: "\(label) length was negative")
    }
    guard length > 0 else { return Data() }
    guard let pointer else {
        throw BridgeInputError(message: "\(label) pointer was null for \(length) bytes")
    }
    return Data(bytes: pointer, count: length)
}

private func wipeData(_ data: inout Data) {
    data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
        guard let baseAddress = buffer.baseAddress, !buffer.isEmpty else { return }
        _ = memset_s(baseAddress, buffer.count, 0, buffer.count)
    }
}

private func copiedString(
    _ pointer: UnsafePointer<UInt8>?,
    length: Int,
    label: String
) throws -> String {
    let data = try copiedData(pointer, length: length, label: label)
    guard let value = String(data: data, encoding: .utf8) else {
        throw BridgeInputError(message: "\(label) was not valid UTF-8")
    }
    return value
}

private func allocateBuffer<Bytes: ContiguousBytes>(_ bytes: Bytes) -> (UnsafeMutableRawPointer, Int) {
    bytes.withUnsafeBytes { source in
        let byteCount = source.count
        let allocationCount = max(byteCount, 1)
        let allocation = UnsafeMutableRawPointer.allocate(
            byteCount: allocationCount,
            alignment: MemoryLayout<UInt8>.alignment
        )
        allocation.initializeMemory(as: UInt8.self, repeating: 0, count: allocationCount)
        if byteCount > 0, let baseAddress = source.baseAddress {
            allocation.copyMemory(from: baseAddress, byteCount: byteCount)
        }
        return (allocation, byteCount)
    }
}

private func publish<Bytes: ContiguousBytes>(
    _ bytes: Bytes,
    pointerOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>,
    lengthOut: UnsafeMutablePointer<Int>
) {
    let (pointer, length) = allocateBuffer(bytes)
    pointerOut.pointee = pointer
    lengthOut.pointee = length
}

private func resetOutput(
    _ pointerOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ lengthOut: UnsafeMutablePointer<Int>?
) throws -> (
    UnsafeMutablePointer<UnsafeMutableRawPointer?>,
    UnsafeMutablePointer<Int>
) {
    guard let pointerOut, let lengthOut else {
        throw BridgeInputError(message: "required output pointer was null")
    }
    pointerOut.pointee = nil
    lengthOut.pointee = 0
    return (pointerOut, lengthOut)
}

private func errorChain(_ error: Error) -> [NSError] {
    var errors: [NSError] = []
    var pending: [(NSError, Int)] = [(error as NSError, 0)]
    var visited = Set<ObjectIdentifier>()
    while !pending.isEmpty && errors.count < 32 {
        let (value, depth) = pending.removeFirst()
        guard depth <= 8, visited.insert(ObjectIdentifier(value)).inserted else {
            continue
        }
        errors.append(value)
        pending.append(contentsOf: value.underlyingErrors.map { ($0 as NSError, depth + 1) })
    }
    return errors
}

private func containsSecurityStatus(_ status: OSStatus, in errors: [NSError]) -> Bool {
    errors.contains { error in
        error.domain == NSOSStatusErrorDomain && error.code == Int(status)
    }
}

private func localAuthenticationCodes(in errors: [NSError]) -> [LAError.Code] {
    errors.compactMap { error in
        guard error.domain == LAError.errorDomain else { return nil }
        return LAError.Code(rawValue: error.code)
    }
}

private func classify(_ error: Error, invalidationEligible: Bool) -> Int32 {
    let errors = errorChain(error)
    let localAuthentication = localAuthenticationCodes(in: errors)

    if containsSecurityStatus(errSecInteractionNotAllowed, in: errors)
        || containsSecurityStatus(errSecInteractionRequired, in: errors)
        || localAuthentication.contains(.notInteractive)
        || localAuthentication.contains(.biometryNotAvailable)
    {
        return statusInteractionUnavailable
    }
    if invalidationEligible
        && (containsSecurityStatus(errSecItemNotFound, in: errors)
            || containsSecurityStatus(errSecDecode, in: errors)
            || localAuthentication.contains(.biometryNotEnrolled))
    {
        return statusKeyInvalidated
    }
    if containsSecurityStatus(errSecItemNotFound, in: errors) {
        return statusMissingItem
    }
    if containsSecurityStatus(errSecAuthFailed, in: errors)
        || containsSecurityStatus(errSecUserCanceled, in: errors)
        || localAuthentication.contains(.authenticationFailed)
        || localAuthentication.contains(.userCancel)
        || localAuthentication.contains(.userFallback)
        || localAuthentication.contains(.systemCancel)
        || localAuthentication.contains(.appCancel)
        || localAuthentication.contains(.biometryLockout)
    {
        return statusAuthenticationFailed
    }
    return statusPlatformFailure
}

private func diagnostic(for error: Error) -> String {
    errorChain(error)
        .map { "\($0.domain) \($0.code): \($0.localizedDescription)" }
        .joined(separator: " | ")
}

private func publishError(
    _ error: Error,
    invalidationEligible: Bool,
    errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    errorLengthOut: UnsafeMutablePointer<Int>?
) -> Int32 {
    if let errorOut, let errorLengthOut {
        let bytes = Array(diagnostic(for: error).utf8)
        publish(bytes, pointerOut: errorOut, lengthOut: errorLengthOut)
    }
    return classify(error, invalidationEligible: invalidationEligible)
}

private func accessControl() throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let value = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        &error
    ) else {
        if let error {
            throw error.takeRetainedValue()
        }
        throw BridgeInputError(message: "SecAccessControlCreateWithFlags returned no error")
    }
    return value
}

private func derivedKEK(
    privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey,
    peerPublicKey: P256.KeyAgreement.PublicKey,
    salt: Data,
    sharedInfo: Data
) throws -> SymmetricKey {
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
    return sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: salt,
        sharedInfo: sharedInfo,
        outputByteCount: 32
    )
}

// MARK: - Executable-bound Quick Unlock Keychain

private let quickUnlockService = "com.vaultkern.runtime.quick-unlock"
private let quickUnlockLabel = "VaultKern Quick Unlock"
private let securityInteractionLock = NSRecursiveLock()

private func securityError(_ status: OSStatus, operation: String) -> NSError {
    let detail = SecCopyErrorMessageString(status, nil) as String?
        ?? "Security framework status \(status)"
    return NSError(
        domain: NSOSStatusErrorDomain,
        code: Int(status),
        userInfo: [NSLocalizedDescriptionKey: "\(operation): \(detail)"]
    )
}

private func combinedSecurityError(primary: Error, secondary: Error) -> NSError {
    let primaryError = primary as NSError
    let secondaryError = secondary as NSError
    return NSError(
        domain: "com.vaultkern.runtime.security-bridge",
        code: 1,
        userInfo: [
            NSLocalizedDescriptionKey:
                "\(diagnostic(for: primary)) | \(diagnostic(for: secondary))",
            NSUnderlyingErrorKey: primaryError,
            NSMultipleUnderlyingErrorsKey: [primaryError, secondaryError],
        ]
    )
}

private func checkSecurityStatus(_ status: OSStatus, operation: String) throws {
    guard status == errSecSuccess else {
        throw securityError(status, operation: operation)
    }
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func withKeychainUserInteractionDisabled<T>(_ body: () throws -> T) throws -> T {
    securityInteractionLock.lock()
    defer { securityInteractionLock.unlock() }

    var wasAllowed = DarwinBoolean(false)
    try checkSecurityStatus(
        SecKeychainGetUserInteractionAllowed(&wasAllowed),
        operation: "read Keychain user-interaction state"
    )
    let disableStatus = SecKeychainSetUserInteractionAllowed(false)
    if disableStatus != errSecSuccess {
        let disableError = securityError(
            disableStatus,
            operation: "disable Keychain user interaction"
        )
        let restoreStatus = SecKeychainSetUserInteractionAllowed(wasAllowed.boolValue)
        if restoreStatus != errSecSuccess {
            let restoreError = securityError(
                restoreStatus,
                operation: "restore Keychain user-interaction state after disable failure"
            )
            throw combinedSecurityError(primary: disableError, secondary: restoreError)
        }
        throw disableError
    }

    let bodyResult: Result<T, Error>
    do {
        bodyResult = .success(try body())
    } catch {
        bodyResult = .failure(error)
    }

    let restoreStatus = SecKeychainSetUserInteractionAllowed(wasAllowed.boolValue)
    if restoreStatus != errSecSuccess {
        let restoreError = securityError(
            restoreStatus,
            operation: "restore Keychain user-interaction state"
        )
        if case let .failure(primaryError) = bodyResult {
            throw combinedSecurityError(primary: primaryError, secondary: restoreError)
        }
        throw restoreError
    }
    return try bodyResult.get()
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func defaultLoginKeychain() throws -> SecKeychain {
    var keychain: SecKeychain?
    try checkSecurityStatus(
        SecKeychainCopyDefault(&keychain),
        operation: "open the default login Keychain"
    )
    guard let keychain else {
        throw BridgeInputError(message: "SecKeychainCopyDefault returned no Keychain")
    }
    return keychain
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func currentExecutableTrustedApplication() throws -> SecTrustedApplication {
    var trustedApplication: SecTrustedApplication?
    try checkSecurityStatus(
        SecTrustedApplicationCreateFromPath(nil, &trustedApplication),
        operation: "identify the current executable for its Keychain ACL"
    )
    guard let trustedApplication else {
        throw BridgeInputError(
            message: "SecTrustedApplicationCreateFromPath returned no application"
        )
    }
    return trustedApplication
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func currentExecutableAccess() throws -> SecAccess {
    let trustedApplication = try currentExecutableTrustedApplication()
    var access: SecAccess?
    let trustedApplications = [trustedApplication] as CFArray
    try checkSecurityStatus(
        SecAccessCreate(
            quickUnlockLabel as CFString,
            trustedApplications,
            &access
        ),
        operation: "create the Quick Unlock Keychain ACL"
    )
    guard let access else {
        throw BridgeInputError(message: "SecAccessCreate returned no access object")
    }
    return access
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func quickUnlockRecordQuery(
    recordID: String,
    keychain: SecKeychain
) -> [CFString: Any] {
    [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: quickUnlockService,
        kSecAttrAccount: recordID,
        kSecMatchSearchList: [keychain],
        kSecUseAuthenticationUI: kSecUseAuthenticationUIFail,
    ]
}

private func quickUnlockRecordID(
    _ pointer: UnsafePointer<UInt8>?,
    length: Int
) throws -> String {
    let recordID = try copiedString(pointer, length: length, label: "record ID")
    guard !recordID.isEmpty else {
        throw BridgeInputError(message: "record ID must not be empty")
    }
    return recordID
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func copyQuickUnlockRecordItem(
    recordID: String,
    keychain: SecKeychain
) throws -> SecKeychainItem? {
    var query = quickUnlockRecordQuery(recordID: recordID, keychain: keychain)
    query[kSecMatchLimit] = kSecMatchLimitOne
    query[kSecReturnRef] = true
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        return nil
    }
    try checkSecurityStatus(status, operation: "find the existing Quick Unlock record")
    guard let result, CFGetTypeID(result) == SecKeychainItemGetTypeID() else {
        throw BridgeInputError(
            message: "Keychain returned a non-item reference for the Quick Unlock record"
        )
    }
    let item = unsafeBitCast(result, to: SecKeychainItem.self)
    return item
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func trustedApplicationIdentity(_ application: SecTrustedApplication) throws -> CFData {
    var identity: CFData?
    try checkSecurityStatus(
        SecTrustedApplicationCopyData(application, &identity),
        operation: "copy a trusted application's Keychain identity"
    )
    guard let identity else {
        throw BridgeInputError(message: "SecTrustedApplicationCopyData returned no identity")
    }
    return identity
}

private func object(at index: CFIndex, in array: CFArray, label: String) throws -> CFTypeRef {
    guard let pointer = CFArrayGetValueAtIndex(array, index) else {
        throw BridgeInputError(message: "\(label) contained a null object")
    }
    return Unmanaged<AnyObject>.fromOpaque(pointer).takeUnretainedValue()
}

private func containsAuthorization(_ authorization: CFString, in values: CFArray) -> Bool {
    for index in 0..<CFArrayGetCount(values) {
        guard let pointer = CFArrayGetValueAtIndex(values, index) else { continue }
        let value = Unmanaged<AnyObject>.fromOpaque(pointer).takeUnretainedValue()
        if CFEqual(value, authorization) {
            return true
        }
    }
    return false
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func trustedApplication(
    at index: CFIndex,
    in applicationList: CFArray
) throws -> SecTrustedApplication {
    let application = try object(
        at: index,
        in: applicationList,
        label: "Quick Unlock trusted application list"
    )
    guard CFGetTypeID(application) == SecTrustedApplicationGetTypeID() else {
        throw BridgeInputError(
            message: "Quick Unlock ACL contained a non-application trust object"
        )
    }
    return unsafeBitCast(application, to: SecTrustedApplication.self)
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func applicationMatchesCurrentExecutable(
    _ application: SecTrustedApplication,
    currentIdentity: CFData
) throws -> Bool {
    let storedIdentity = try trustedApplicationIdentity(application)
    return CFEqual(storedIdentity, currentIdentity)
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func validateSecretReadingApplicationList(
    _ applicationList: CFArray?,
    currentIdentity: CFData
) throws {
    guard let applicationList, CFArrayGetCount(applicationList) == 1 else {
        throw BridgeInputError(
            message: "Quick Unlock secret-reading ACL must trust exactly one executable"
        )
    }
    let application = try trustedApplication(at: 0, in: applicationList)
    guard try applicationMatchesCurrentExecutable(
        application,
        currentIdentity: currentIdentity
    ) else {
        throw BridgeInputError(
            message: "Quick Unlock secret-reading ACL trusts another executable"
        )
    }
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func validateMutatingApplicationList(
    _ applicationList: CFArray?,
    currentIdentity: CFData
) throws {
    guard let applicationList else {
        throw BridgeInputError(
            message: "Quick Unlock mutating ACL permits every executable"
        )
    }
    for index in 0..<CFArrayGetCount(applicationList) {
        let application = try trustedApplication(at: index, in: applicationList)
        guard try applicationMatchesCurrentExecutable(
            application,
            currentIdentity: currentIdentity
        ) else {
            throw BridgeInputError(
                message: "Quick Unlock mutating ACL trusts another executable"
            )
        }
    }
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func validateQuickUnlockRecordAccess(_ item: SecKeychainItem) throws {
    var access: SecAccess?
    try checkSecurityStatus(
        SecKeychainItemCopyAccess(item, &access),
        operation: "copy the existing Quick Unlock record's ACL"
    )
    guard let access else {
        throw BridgeInputError(message: "existing Quick Unlock record has no ACL")
    }

    var aclList: CFArray?
    try checkSecurityStatus(
        SecAccessCopyACLList(access, &aclList),
        operation: "copy the existing Quick Unlock record's full ACL"
    )
    guard let aclList else {
        throw BridgeInputError(message: "existing Quick Unlock record has no ACL entries")
    }

    let currentApplication = try currentExecutableTrustedApplication()
    let currentIdentity = try trustedApplicationIdentity(currentApplication)
    var foundSecretReadingACL = false
    for index in 0..<CFArrayGetCount(aclList) {
        let aclObject = try object(
            at: index,
            in: aclList,
            label: "Quick Unlock ACL list"
        )
        guard CFGetTypeID(aclObject) == SecACLGetTypeID() else {
            throw BridgeInputError(message: "Quick Unlock access contained a non-ACL object")
        }
        let acl = unsafeBitCast(aclObject, to: SecACL.self)
        let authorizations = SecACLCopyAuthorizations(acl)
        let readsSecret = containsAuthorization(
            kSecACLAuthorizationDecrypt,
            in: authorizations
        ) || containsAuthorization(
            kSecACLAuthorizationAny,
            in: authorizations
        ) || containsAuthorization(
            kSecACLAuthorizationKeychainItemRead,
            in: authorizations
        )
        let mutatesAccess = containsAuthorization(
            kSecACLAuthorizationChangeACL,
            in: authorizations
        ) || containsAuthorization(
            kSecACLAuthorizationChangeOwner,
            in: authorizations
        ) || containsAuthorization(
            kSecACLAuthorizationKeychainItemModify,
            in: authorizations
        ) || containsAuthorization(
            kSecACLAuthorizationDelete,
            in: authorizations
        ) || containsAuthorization(
            kSecACLAuthorizationKeychainItemDelete,
            in: authorizations
        )
        guard readsSecret || mutatesAccess else { continue }

        var applicationList: CFArray?
        var description: CFString?
        var promptSelector = SecKeychainPromptSelector(rawValue: 0)
        try checkSecurityStatus(
            SecACLCopyContents(
                acl,
                &applicationList,
                &description,
                &promptSelector
            ),
            operation: "inspect an existing Quick Unlock ACL entry"
        )
        if readsSecret {
            try validateSecretReadingApplicationList(
                applicationList,
                currentIdentity: currentIdentity
            )
            foundSecretReadingACL = true
        }
        if mutatesAccess {
            try validateMutatingApplicationList(
                applicationList,
                currentIdentity: currentIdentity
            )
        }
    }
    guard foundSecretReadingACL else {
        throw BridgeInputError(
            message: "existing Quick Unlock record has no secret-reading ACL"
        )
    }
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
private func storeQuickUnlockRecord(
    recordID: String,
    recordData: Data,
    keychain: SecKeychain
) throws {
    let replacement = [kSecValueData: recordData]
    if let existingItem = try copyQuickUnlockRecordItem(
        recordID: recordID,
        keychain: keychain
    ) {
        try validateQuickUnlockRecordAccess(existingItem)
        let updateQuery: [CFString: Any] = [
            kSecMatchItemList: [existingItem],
            kSecUseAuthenticationUI: kSecUseAuthenticationUIFail,
        ]
        try checkSecurityStatus(
            SecItemUpdate(updateQuery as CFDictionary, replacement as CFDictionary),
            operation: "update the Quick Unlock record"
        )
        return
    }

    let access = try currentExecutableAccess()
    let newItem: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: quickUnlockService,
        kSecAttrAccount: recordID,
        kSecAttrLabel: quickUnlockLabel,
        kSecValueData: recordData,
        kSecAttrAccess: access,
        kSecUseKeychain: keychain,
        kSecUseAuthenticationUI: kSecUseAuthenticationUIFail,
    ]
    let addStatus = SecItemAdd(newItem as CFDictionary, nil)
    try checkSecurityStatus(addStatus, operation: "add the Quick Unlock record")
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
@_cdecl("vaultkern_macos_quick_unlock_keychain_is_available")
public func vaultkernMacosQuickUnlockKeychainIsAvailable() -> Int32 {
    do {
        return try withKeychainUserInteractionDisabled {
            _ = try defaultLoginKeychain()
            return 1
        }
    } catch {
        return 0
    }
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
@_cdecl("vaultkern_macos_quick_unlock_record_store")
public func vaultkernMacosQuickUnlockRecordStore(
    _ recordIDPointer: UnsafePointer<UInt8>?,
    _ recordIDLength: Int,
    _ recordPointer: UnsafePointer<UInt8>?,
    _ recordLength: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ errorLengthOut: UnsafeMutablePointer<Int>?
) -> Int32 {
    do {
        _ = try resetOutput(errorOut, errorLengthOut)
        let recordID = try quickUnlockRecordID(recordIDPointer, length: recordIDLength)
        var recordData = try copiedData(recordPointer, length: recordLength, label: "record")
        defer { wipeData(&recordData) }
        guard !recordData.isEmpty else {
            throw BridgeInputError(message: "record must not be empty")
        }
        return try withKeychainUserInteractionDisabled {
            let keychain = try defaultLoginKeychain()
            try storeQuickUnlockRecord(
                recordID: recordID,
                recordData: recordData,
                keychain: keychain
            )
            return statusOK
        }
    } catch {
        return publishError(
            error,
            invalidationEligible: false,
            errorOut: errorOut,
            errorLengthOut: errorLengthOut
        )
    }
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
@_cdecl("vaultkern_macos_quick_unlock_record_contains")
public func vaultkernMacosQuickUnlockRecordContains(
    _ recordIDPointer: UnsafePointer<UInt8>?,
    _ recordIDLength: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ errorLengthOut: UnsafeMutablePointer<Int>?
) -> Int32 {
    do {
        _ = try resetOutput(errorOut, errorLengthOut)
        let recordID = try quickUnlockRecordID(recordIDPointer, length: recordIDLength)
        return try withKeychainUserInteractionDisabled {
            let keychain = try defaultLoginKeychain()
            guard let existingItem = try copyQuickUnlockRecordItem(
                recordID: recordID,
                keychain: keychain
            ) else {
                return statusMissingItem
            }
            try validateQuickUnlockRecordAccess(existingItem)
            return statusOK
        }
    } catch {
        return publishError(
            error,
            invalidationEligible: false,
            errorOut: errorOut,
            errorLengthOut: errorLengthOut
        )
    }
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
@_cdecl("vaultkern_macos_quick_unlock_record_load")
public func vaultkernMacosQuickUnlockRecordLoad(
    _ recordIDPointer: UnsafePointer<UInt8>?,
    _ recordIDLength: Int,
    _ recordOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ recordLengthOut: UnsafeMutablePointer<Int>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ errorLengthOut: UnsafeMutablePointer<Int>?
) -> Int32 {
    do {
        let recordOutput = try resetOutput(recordOut, recordLengthOut)
        _ = try resetOutput(errorOut, errorLengthOut)
        let recordID = try quickUnlockRecordID(recordIDPointer, length: recordIDLength)
        return try withKeychainUserInteractionDisabled {
            let keychain = try defaultLoginKeychain()
            guard let existingItem = try copyQuickUnlockRecordItem(
                recordID: recordID,
                keychain: keychain
            ) else {
                throw securityError(errSecItemNotFound, operation: "load the Quick Unlock record")
            }
            try validateQuickUnlockRecordAccess(existingItem)
            let fetchQuery: [CFString: Any] = [
                kSecMatchItemList: [existingItem],
                kSecMatchLimit: kSecMatchLimitOne,
                kSecReturnData: true,
                kSecUseAuthenticationUI: kSecUseAuthenticationUIFail,
            ]
            var result: CFTypeRef?
            try checkSecurityStatus(
                SecItemCopyMatching(fetchQuery as CFDictionary, &result),
                operation: "load the Quick Unlock record"
            )
            guard var recordData = result as? Data else {
                throw BridgeInputError(
                    message: "Keychain returned a non-data Quick Unlock record"
                )
            }
            defer { wipeData(&recordData) }
            publish(recordData, pointerOut: recordOutput.0, lengthOut: recordOutput.1)
            return statusOK
        }
    } catch {
        return publishError(
            error,
            invalidationEligible: false,
            errorOut: errorOut,
            errorLengthOut: errorLengthOut
        )
    }
}

@available(macOS, deprecated: 10.10, message: "File-based Keychain ACLs are required here")
@_cdecl("vaultkern_macos_quick_unlock_record_delete")
public func vaultkernMacosQuickUnlockRecordDelete(
    _ recordIDPointer: UnsafePointer<UInt8>?,
    _ recordIDLength: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ errorLengthOut: UnsafeMutablePointer<Int>?
) -> Int32 {
    do {
        _ = try resetOutput(errorOut, errorLengthOut)
        let recordID = try quickUnlockRecordID(recordIDPointer, length: recordIDLength)
        return try withKeychainUserInteractionDisabled {
            let keychain = try defaultLoginKeychain()
            guard let existingItem = try copyQuickUnlockRecordItem(
                recordID: recordID,
                keychain: keychain
            ) else {
                return statusMissingItem
            }
            try validateQuickUnlockRecordAccess(existingItem)
            let deleteQuery: [CFString: Any] = [
                kSecMatchItemList: [existingItem],
                kSecUseAuthenticationUI: kSecUseAuthenticationUIFail,
            ]
            try checkSecurityStatus(
                SecItemDelete(deleteQuery as CFDictionary),
                operation: "delete the Quick Unlock record"
            )
            return statusOK
        }
    } catch {
        return publishError(
            error,
            invalidationEligible: false,
            errorOut: errorOut,
            errorLengthOut: errorLengthOut
        )
    }
}

// MARK: - Secure Enclave C ABI

@_cdecl("vaultkern_macos_secure_enclave_is_available")
public func vaultkernMacosSecureEnclaveIsAvailable() -> Int32 {
    SecureEnclave.isAvailable ? 1 : 0
}

@_cdecl("vaultkern_macos_secure_enclave_create")
public func vaultkernMacosSecureEnclaveCreate(
    _ saltPointer: UnsafePointer<UInt8>?,
    _ saltLength: Int,
    _ sharedInfoPointer: UnsafePointer<UInt8>?,
    _ sharedInfoLength: Int,
    _ localizedReasonPointer: UnsafePointer<UInt8>?,
    _ localizedReasonLength: Int,
    _ privateKeyOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ privateKeyLengthOut: UnsafeMutablePointer<Int>?,
    _ peerPublicKeyOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ peerPublicKeyLengthOut: UnsafeMutablePointer<Int>?,
    _ kekOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ kekLengthOut: UnsafeMutablePointer<Int>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ errorLengthOut: UnsafeMutablePointer<Int>?
) -> Int32 {
    securityInteractionLock.lock()
    defer { securityInteractionLock.unlock() }
    do {
        let privateKeyOutput = try resetOutput(privateKeyOut, privateKeyLengthOut)
        let peerPublicKeyOutput = try resetOutput(peerPublicKeyOut, peerPublicKeyLengthOut)
        let kekOutput = try resetOutput(kekOut, kekLengthOut)
        _ = try resetOutput(errorOut, errorLengthOut)
        let salt = try copiedData(saltPointer, length: saltLength, label: "salt")
        let sharedInfo = try copiedData(
            sharedInfoPointer,
            length: sharedInfoLength,
            label: "shared info"
        )
        let reason = try copiedString(
            localizedReasonPointer,
            length: localizedReasonLength,
            label: "localized reason"
        )
        guard !reason.isEmpty else {
            throw BridgeInputError(message: "localized reason must not be empty")
        }

        let context = LAContext()
        context.localizedReason = reason
        defer { context.invalidate() }
        let secureEnclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl(),
            authenticationContext: context
        )
        let peerPrivateKey = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
        let kek = try derivedKEK(
            privateKey: secureEnclaveKey,
            peerPublicKey: peerPrivateKey.publicKey,
            salt: salt,
            sharedInfo: sharedInfo
        )

        var privateKeyData = secureEnclaveKey.dataRepresentation
        defer { wipeData(&privateKeyData) }

        publish(
            privateKeyData,
            pointerOut: privateKeyOutput.0,
            lengthOut: privateKeyOutput.1
        )
        publish(
            peerPrivateKey.publicKey.rawRepresentation,
            pointerOut: peerPublicKeyOutput.0,
            lengthOut: peerPublicKeyOutput.1
        )
        kek.withUnsafeBytes { bytes in
            publish(bytes, pointerOut: kekOutput.0, lengthOut: kekOutput.1)
        }
        return statusOK
    } catch {
        return publishError(
            error,
            invalidationEligible: false,
            errorOut: errorOut,
            errorLengthOut: errorLengthOut
        )
    }
}

@_cdecl("vaultkern_macos_secure_enclave_derive_for_refresh")
public func vaultkernMacosSecureEnclaveDeriveForRefresh(
    _ privateKeyPointer: UnsafePointer<UInt8>?,
    _ privateKeyLength: Int,
    _ saltPointer: UnsafePointer<UInt8>?,
    _ saltLength: Int,
    _ sharedInfoPointer: UnsafePointer<UInt8>?,
    _ sharedInfoLength: Int,
    _ peerPublicKeyOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ peerPublicKeyLengthOut: UnsafeMutablePointer<Int>?,
    _ kekOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ kekLengthOut: UnsafeMutablePointer<Int>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ errorLengthOut: UnsafeMutablePointer<Int>?
) -> Int32 {
    securityInteractionLock.lock()
    defer { securityInteractionLock.unlock() }
    do {
        let peerPublicKeyOutput = try resetOutput(peerPublicKeyOut, peerPublicKeyLengthOut)
        let kekOutput = try resetOutput(kekOut, kekLengthOut)
        _ = try resetOutput(errorOut, errorLengthOut)
        var privateKeyData = try copiedData(
            privateKeyPointer,
            length: privateKeyLength,
            label: "private key representation"
        )
        defer { wipeData(&privateKeyData) }
        let salt = try copiedData(saltPointer, length: saltLength, label: "salt")
        let sharedInfo = try copiedData(
            sharedInfoPointer,
            length: sharedInfoLength,
            label: "shared info"
        )

        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        let secureEnclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: privateKeyData,
            authenticationContext: context
        )
        let peerPrivateKey = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
        let sharedSecret = try peerPrivateKey.sharedSecretFromKeyAgreement(with: secureEnclaveKey.publicKey)
        let kek = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
        publish(
            peerPrivateKey.publicKey.rawRepresentation,
            pointerOut: peerPublicKeyOutput.0,
            lengthOut: peerPublicKeyOutput.1
        )
        kek.withUnsafeBytes { bytes in
            publish(bytes, pointerOut: kekOutput.0, lengthOut: kekOutput.1)
        }
        return statusOK
    } catch {
        return publishError(
            error,
            invalidationEligible: true,
            errorOut: errorOut,
            errorLengthOut: errorLengthOut
        )
    }
}

@_cdecl("vaultkern_macos_secure_enclave_restore_and_derive")
public func vaultkernMacosSecureEnclaveRestoreAndDerive(
    _ privateKeyPointer: UnsafePointer<UInt8>?,
    _ privateKeyLength: Int,
    _ peerPublicKeyPointer: UnsafePointer<UInt8>?,
    _ peerPublicKeyLength: Int,
    _ saltPointer: UnsafePointer<UInt8>?,
    _ saltLength: Int,
    _ sharedInfoPointer: UnsafePointer<UInt8>?,
    _ sharedInfoLength: Int,
    _ localizedReasonPointer: UnsafePointer<UInt8>?,
    _ localizedReasonLength: Int,
    _ kekOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ kekLengthOut: UnsafeMutablePointer<Int>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ errorLengthOut: UnsafeMutablePointer<Int>?
) -> Int32 {
    securityInteractionLock.lock()
    defer { securityInteractionLock.unlock() }
    do {
        let kekOutput = try resetOutput(kekOut, kekLengthOut)
        _ = try resetOutput(errorOut, errorLengthOut)
        var privateKeyData = try copiedData(
            privateKeyPointer,
            length: privateKeyLength,
            label: "private key representation"
        )
        defer { wipeData(&privateKeyData) }
        let peerPublicKeyData = try copiedData(
            peerPublicKeyPointer,
            length: peerPublicKeyLength,
            label: "peer public key"
        )
        let salt = try copiedData(saltPointer, length: saltLength, label: "salt")
        let sharedInfo = try copiedData(
            sharedInfoPointer,
            length: sharedInfoLength,
            label: "shared info"
        )
        let reason = try copiedString(
            localizedReasonPointer,
            length: localizedReasonLength,
            label: "localized reason"
        )
        guard !reason.isEmpty else {
            throw BridgeInputError(message: "localized reason must not be empty")
        }

        let context = LAContext()
        context.localizedReason = reason
        defer { context.invalidate() }
        let secureEnclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: privateKeyData,
            authenticationContext: context
        )
        let peerPublicKey = try P256.KeyAgreement.PublicKey(
            rawRepresentation: peerPublicKeyData
        )
        let kek = try derivedKEK(
            privateKey: secureEnclaveKey,
            peerPublicKey: peerPublicKey,
            salt: salt,
            sharedInfo: sharedInfo
        )
        kek.withUnsafeBytes { bytes in
            publish(bytes, pointerOut: kekOutput.0, lengthOut: kekOutput.1)
        }
        return statusOK
    } catch {
        return publishError(
            error,
            invalidationEligible: true,
            errorOut: errorOut,
            errorLengthOut: errorLengthOut
        )
    }
}

@_cdecl("vaultkern_macos_buffer_free")
public func vaultkernMacosBufferFree(
    _ pointer: UnsafeMutableRawPointer?,
    _ length: Int
) {
    guard let pointer else { return }
    if length > 0 {
        _ = memset_s(pointer, length, 0, length)
    }
    pointer.deallocate()
}
