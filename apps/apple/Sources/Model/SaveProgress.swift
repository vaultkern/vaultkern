import Foundation

enum SaveProgress: Equatable, Sendable {
  case clean
  case dirty
  case staged

  var hasUncommittedChanges: Bool { self != .clean }
  var shouldApplyDraft: Bool { self == .dirty }

  mutating func markDraftChanged() {
    precondition(self != .staged, "a staged edit must be saved before further mutation")
    self = .dirty
  }

  mutating func markEditApplied() {
    precondition(self == .dirty, "only a dirty draft can be staged")
    self = .staged
  }

  mutating func markSaveSucceeded() {
    precondition(self == .staged, "only a staged edit can be committed")
    self = .clean
  }

  mutating func discardDraft() {
    precondition(self != .staged, "a staged runtime edit cannot be discarded in memory")
    self = .clean
  }
}
