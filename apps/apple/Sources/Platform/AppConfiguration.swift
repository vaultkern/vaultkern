import Foundation

struct AppConfiguration: Sendable {
  let stateDirectory: URL
  let temporaryDirectory: URL
  let keychainAccessGroup: String

  static func live(bundle: Bundle = .main, fileManager: FileManager = .default) throws -> Self {
    guard
      let accessGroup = bundle.object(forInfoDictionaryKey: "VaultKernKeychainAccessGroup")
        as? String,
      !accessGroup.isEmpty,
      !accessGroup.contains("$(")
    else {
      throw AppConfigurationError.missingKeychainAccessGroup
    }

    let applicationSupport = try requiredDirectory(
      .applicationSupportDirectory,
      fileManager: fileManager
    )
    let caches = try requiredDirectory(.cachesDirectory, fileManager: fileManager)
    let stateDirectory = applicationSupport.appending(
      path: "VaultKern", directoryHint: .isDirectory)
    let temporaryDirectory = caches.appending(
      path: "VaultKern/Temporary",
      directoryHint: .isDirectory
    )

    try createPrivateDirectory(stateDirectory, fileManager: fileManager)
    try createPrivateDirectory(temporaryDirectory, fileManager: fileManager)
    return Self(
      stateDirectory: stateDirectory,
      temporaryDirectory: temporaryDirectory,
      keychainAccessGroup: accessGroup
    )
  }

  private static func requiredDirectory(
    _ directory: FileManager.SearchPathDirectory,
    fileManager: FileManager
  ) throws -> URL {
    guard let url = fileManager.urls(for: directory, in: .userDomainMask).first else {
      throw AppConfigurationError.missingUserDirectory
    }
    return url
  }

  private static func createPrivateDirectory(_ url: URL, fileManager: FileManager) throws {
    try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
    try fileManager.setAttributes(
      [.posixPermissions: NSNumber(value: Int16(0o700))],
      ofItemAtPath: url.path
    )
  }
}

enum AppConfigurationError: LocalizedError {
  case missingKeychainAccessGroup
  case missingUserDirectory

  var errorDescription: String? {
    switch self {
    case .missingKeychainAccessGroup:
      "The signed app is missing its Keychain access group."
    case .missingUserDirectory:
      "The user application directory is unavailable."
    }
  }
}
