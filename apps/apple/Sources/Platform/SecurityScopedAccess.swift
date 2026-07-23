import Foundation

@MainActor
protocol SecurityScopedAccessing: AnyObject {
  func retain(_ url: URL)
  func release(_ url: URL)
  func releaseAll()
}

@MainActor
final class SecurityScopedAccess: SecurityScopedAccessing {
  private var activeURLs: [URL] = []

  func retain(_ url: URL) {
    // Callers transfer an active scope: panels start one implicitly, while
    // SwiftUI file importers start one explicitly before handing off the URL.
    activeURLs.append(url)
  }

  func release(_ url: URL) {
    guard let index = activeURLs.firstIndex(of: url) else { return }
    activeURLs.remove(at: index).stopAccessingSecurityScopedResource()
  }

  func releaseAll() {
    let urls = activeURLs
    activeURLs.removeAll(keepingCapacity: false)
    for url in urls {
      url.stopAccessingSecurityScopedResource()
    }
  }

  deinit {
    for url in activeURLs {
      url.stopAccessingSecurityScopedResource()
    }
  }
}
