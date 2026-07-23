import Foundation

/// Clearable text storage for secret-bearing UniFFI DTO fields.
///
/// `reveal()` necessarily creates a Swift String for rendering or an FFI call;
/// callers should keep that value short-lived and call `close()` on this owner.
public final class VaultKernSensitiveString: @unchecked Sendable,
    CustomStringConvertible, Equatable, Hashable
{
    private let lock = NSLock()
    private var storage: Data

    public init(_ value: String) {
        storage = Data(value.utf8)
    }

    private init(storage: Data) {
        self.storage = storage
    }

    public var isEmpty: Bool {
        lock.lock()
        defer { lock.unlock() }
        return storage.isEmpty
    }

    public func reveal() -> String {
        lock.lock()
        defer { lock.unlock() }
        return String(decoding: storage, as: UTF8.self)
    }

    public func replace(with value: String) {
        lock.lock()
        defer { lock.unlock() }
        storage.resetBytes(in: storage.startIndex..<storage.endIndex)
        storage = Data(value.utf8)
    }

    /// Creates the short-lived independent owner required for an FFI transfer.
    public func copyForTransfer() -> VaultKernSensitiveString {
        lock.lock()
        defer { lock.unlock() }
        return VaultKernSensitiveString(storage: Self.deepCopy(storage))
    }

    public func close() {
        lock.lock()
        defer { lock.unlock() }
        storage.resetBytes(in: storage.startIndex..<storage.endIndex)
        storage.removeAll(keepingCapacity: false)
    }

    deinit { close() }

    public var description: String { "[REDACTED]" }

    public static func == (lhs: VaultKernSensitiveString, rhs: VaultKernSensitiveString) -> Bool {
        lhs === rhs
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }

    private static func deepCopy(_ value: Data) -> Data {
        var copy = Data(count: value.count)
        copy.withUnsafeMutableBytes { (destination: UnsafeMutableRawBufferPointer) in
            value.withUnsafeBytes { (source: UnsafeRawBufferPointer) in
                guard let destinationAddress = destination.baseAddress,
                      let sourceAddress = source.baseAddress
                else { return }
                destinationAddress.copyMemory(from: sourceAddress, byteCount: source.count)
            }
        }
        return copy
    }
}

/// Clearable bytes used only while crossing the protected-storage adapter.
public final class VaultKernSensitiveBytes: @unchecked Sendable, CustomStringConvertible {
    private let lock = NSLock()
    private var storage: Data

    public init(_ value: Data) {
        storage = Self.deepCopy(value)
    }

    public func copyData() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return Self.deepCopy(storage)
    }

    public func close() {
        lock.lock()
        defer { lock.unlock() }
        storage.resetBytes(in: storage.startIndex..<storage.endIndex)
        storage.removeAll(keepingCapacity: false)
    }

    deinit { close() }

    public var description: String { "VaultKernSensitiveBytes([REDACTED])" }

    private static func deepCopy(_ value: Data) -> Data {
        var copy = Data(count: value.count)
        copy.withUnsafeMutableBytes { (destination: UnsafeMutableRawBufferPointer) in
            value.withUnsafeBytes { (source: UnsafeRawBufferPointer) in
                guard let destinationAddress = destination.baseAddress,
                      let sourceAddress = source.baseAddress
                else { return }
                destinationAddress.copyMemory(from: sourceAddress, byteCount: source.count)
            }
        }
        return copy
    }
}
