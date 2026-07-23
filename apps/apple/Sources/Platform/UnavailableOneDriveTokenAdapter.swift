import Foundation

/// M2 deliberately does not expose remote sources. M3 replaces this adapter
/// with data-protection Keychain storage before enabling OneDrive in the UI.
final class UnavailableOneDriveTokenAdapter: OneDriveTokenAdapter, @unchecked Sendable {
  func loadRefreshToken() throws -> VaultKernSensitiveString? { nil }

  func storeRefreshToken(token: VaultKernSensitiveString) throws {
    token.close()
    throw PlatformAdapterError.Failure(details: "OneDrive is not enabled in this milestone")
  }

  func deleteRefreshToken() throws {}
}
