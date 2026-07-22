import Foundation

@MainActor
final class SecurityScopedAccess {
  private var activeURLs: [URL] = []

  func retain(_ url: URL) {
    guard url.startAccessingSecurityScopedResource() else { return }
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
