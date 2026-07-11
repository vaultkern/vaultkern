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
        || localAuthentication.contains(.notInteractive)
    {
        return statusInteractionUnavailable
    }
    if invalidationEligible
        && (containsSecurityStatus(errSecItemNotFound, in: errors)
            || containsSecurityStatus(errSecDecode, in: errors)
            || localAuthentication.contains(.biometryNotAvailable)
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

// MARK: - C ABI

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
    _ privateKeyOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ privateKeyLengthOut: UnsafeMutablePointer<Int>?,
    _ peerPublicKeyOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ peerPublicKeyLengthOut: UnsafeMutablePointer<Int>?,
    _ kekOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ kekLengthOut: UnsafeMutablePointer<Int>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ errorLengthOut: UnsafeMutablePointer<Int>?
) -> Int32 {
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

        let secureEnclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl(),
            authenticationContext: nil
        )
        let peerPrivateKey = P256.KeyAgreement.PrivateKey()
        let kek = try derivedKEK(
            privateKey: secureEnclaveKey,
            peerPublicKey: peerPrivateKey.publicKey,
            salt: salt,
            sharedInfo: sharedInfo
        )

        publish(
            secureEnclaveKey.dataRepresentation,
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
    do {
        let kekOutput = try resetOutput(kekOut, kekLengthOut)
        _ = try resetOutput(errorOut, errorLengthOut)
        let privateKeyData = try copiedData(
            privateKeyPointer,
            length: privateKeyLength,
            label: "private key representation"
        )
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
