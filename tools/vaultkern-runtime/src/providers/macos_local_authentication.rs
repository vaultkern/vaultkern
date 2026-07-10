use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use block2::RcBlock;
use objc2::AnyThread;
use objc2::rc::{Retained, autoreleasepool};
use objc2_foundation::{NSData, NSError, NSString};
use objc2_local_authentication::{
    LAAuthenticationRequirement, LABiometryType, LAContext, LAPersistedRight, LAPolicy, LARight,
    LARightStore, LASecret,
};

const NS_OS_STATUS_ERROR_DOMAIN: &str = "NSOSStatusErrorDomain";
const ERR_SEC_ITEM_NOT_FOUND: isize = -25300;
const MAX_UNDERLYING_ERROR_DEPTH: usize = 16;

type CallbackResult<T> = std::result::Result<T, MacLocalAuthenticationError>;

pub(super) trait MacLocalAuthenticationApi {
    fn is_touch_id_available(&self) -> bool;
    fn authorize(&self, reason: &str) -> Result<()>;
    fn contains(&self, identifier: &str) -> Result<bool>;
    fn save(&self, identifier: &str, secret: &[u8]) -> Result<()>;
    fn authorize_and_load(&self, identifier: &str, reason: &str) -> Result<Option<Vec<u8>>>;
    fn remove(&self, identifier: &str) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NSErrorSnapshot {
    domain: String,
    code: isize,
    description: String,
    underlying: Vec<NSErrorSnapshot>,
}

impl NSErrorSnapshot {
    fn from_error(error: &NSError) -> Self {
        Self::from_error_at_depth(error, 0)
    }

    fn from_error_at_depth(error: &NSError, depth: usize) -> Self {
        let underlying = if depth >= MAX_UNDERLYING_ERROR_DEPTH {
            Vec::new()
        } else {
            let errors = error.underlyingErrors();
            (0..errors.count())
                .map(|index| Self::from_error_at_depth(&errors.objectAtIndex(index), depth + 1))
                .collect()
        };
        Self {
            domain: error.domain().to_string(),
            code: error.code(),
            description: error.localizedDescription().to_string(),
            underlying,
        }
    }

    pub(super) fn is_missing_item(&self) -> bool {
        (self.domain == NS_OS_STATUS_ERROR_DOMAIN && self.code == ERR_SEC_ITEM_NOT_FOUND)
            || self.underlying.iter().any(NSErrorSnapshot::is_missing_item)
    }
}

#[derive(Debug)]
pub(super) enum MacLocalAuthenticationError {
    MissingItem,
    Apple(NSErrorSnapshot),
    InvalidCallback(&'static str),
    CallbackPanicked(&'static str),
    CallbackDisconnected(&'static str),
}

impl MacLocalAuthenticationError {
    fn from_snapshot(snapshot: NSErrorSnapshot) -> Self {
        if snapshot.is_missing_item() {
            Self::MissingItem
        } else {
            Self::Apple(snapshot)
        }
    }
}

impl fmt::Display for MacLocalAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingItem => formatter.write_str("quick unlock record was not found"),
            Self::Apple(snapshot) => write!(
                formatter,
                "LocalAuthentication failed ({} {}): {}",
                snapshot.domain, snapshot.code, snapshot.description
            ),
            Self::InvalidCallback(operation) => {
                write!(
                    formatter,
                    "LocalAuthentication returned no {operation} result"
                )
            }
            Self::CallbackPanicked(operation) => {
                write!(
                    formatter,
                    "LocalAuthentication {operation} callback panicked"
                )
            }
            Self::CallbackDisconnected(operation) => {
                write!(
                    formatter,
                    "LocalAuthentication {operation} callback disconnected"
                )
            }
        }
    }
}

impl std::error::Error for MacLocalAuthenticationError {}

pub(super) fn is_missing_item_error(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<MacLocalAuthenticationError>(),
        Some(MacLocalAuthenticationError::MissingItem)
    )
}

struct Completion<T> {
    sender: Mutex<Option<SyncSender<T>>>,
}

impl<T> Completion<T> {
    fn channel() -> (Arc<Self>, Receiver<T>) {
        let (sender, receiver) = sync_channel(1);
        (
            Arc::new(Self {
                sender: Mutex::new(Some(sender)),
            }),
            receiver,
        )
    }

    fn finish(&self, value: T) {
        let sender = match self.sender.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(sender) = sender {
            let _ = sender.send(value);
        }
    }
}

fn finish_callback<T>(
    completion: &Completion<CallbackResult<T>>,
    operation: &'static str,
    callback: impl FnOnce() -> CallbackResult<T>,
) {
    let result = catch_unwind(AssertUnwindSafe(|| autoreleasepool(|_| callback()))).unwrap_or(Err(
        MacLocalAuthenticationError::CallbackPanicked(operation),
    ));
    completion.finish(result);
}

fn wait_for_callback<T>(
    receiver: Receiver<CallbackResult<T>>,
    operation: &'static str,
) -> CallbackResult<T> {
    match receiver.recv() {
        Ok(result) => result,
        Err(_) => Err(MacLocalAuthenticationError::CallbackDisconnected(operation)),
    }
}

fn assert_send_sync<T: Send + Sync>(_: &T) {}

fn snapshot_callback_error(error: *mut NSError) -> Option<NSErrorSnapshot> {
    // SAFETY: LocalAuthentication supplies either null or a valid NSError for
    // the duration of the completion callback. The snapshot owns every field.
    unsafe { error.as_ref().map(NSErrorSnapshot::from_error) }
}

fn error_only_callback_result(error: *mut NSError) -> CallbackResult<()> {
    match snapshot_callback_error(error) {
        Some(snapshot) => Err(MacLocalAuthenticationError::from_snapshot(snapshot)),
        None => Ok(()),
    }
}

struct SendablePersistedRight(Retained<LAPersistedRight>);

// SAFETY: This non-Clone wrapper transfers exclusive ownership of one +1
// retain from an NS_SWIFT_SENDABLE completion to the waiting caller. The
// object is never accessed concurrently, and LAPersistedRight inherits
// objc2's AnyThread thread kind, so use and final release are valid there.
unsafe impl Send for SendablePersistedRight {}

fn fetched_right_callback_result(
    right: *mut LAPersistedRight,
    error: *mut NSError,
) -> CallbackResult<SendablePersistedRight> {
    if let Some(snapshot) = snapshot_callback_error(error) {
        return Err(MacLocalAuthenticationError::from_snapshot(snapshot));
    }
    // SAFETY: The non-null pointer, when present, is a valid borrowed callback
    // argument. Retaining it before the callback returns creates owned +1 state.
    let right = unsafe { Retained::retain(right) }
        .ok_or(MacLocalAuthenticationError::InvalidCallback("fetch"))?;
    Ok(SendablePersistedRight(right))
}

fn saved_right_callback_result(
    right: *mut LAPersistedRight,
    error: *mut NSError,
) -> CallbackResult<()> {
    if let Some(snapshot) = snapshot_callback_error(error) {
        return Err(MacLocalAuthenticationError::from_snapshot(snapshot));
    }
    // SAFETY: The successful save callback returns a valid borrowed right.
    // Take a +1 retain before callback return, then release it after validation.
    let right = unsafe { Retained::retain(right) }
        .ok_or(MacLocalAuthenticationError::InvalidCallback("save"))?;
    drop(right);
    Ok(())
}

fn loaded_data_callback_result(data: *mut NSData, error: *mut NSError) -> CallbackResult<Vec<u8>> {
    if let Some(snapshot) = snapshot_callback_error(error) {
        return Err(MacLocalAuthenticationError::from_snapshot(snapshot));
    }
    // SAFETY: The borrowed NSData is valid during this callback. to_vec copies
    // all bytes before the callback's autorelease pool is drained.
    let data = unsafe { data.as_ref() }
        .ok_or(MacLocalAuthenticationError::InvalidCallback("secret load"))?;
    Ok(data.to_vec())
}

pub(super) fn touch_id_policy_is_available(
    policy_available: bool,
    biometry_type: LABiometryType,
) -> bool {
    policy_available && biometry_type == LABiometryType::TouchID
}

fn strict_biometry_right() -> Retained<LARight> {
    // SAFETY: Both Objective-C constructors are available on the macOS 13
    // deployment target and receive the required non-null requirement.
    unsafe {
        let requirement = LAAuthenticationRequirement::biometryCurrentSetRequirement();
        LARight::initWithRequirement(LARight::alloc(), &requirement)
    }
}

pub(super) struct MacLocalAuthentication;

impl MacLocalAuthentication {
    fn authorize_right(&self, right: &LARight, reason: &str) -> CallbackResult<()> {
        let reason = NSString::from_str(reason);
        let (completion, receiver) = Completion::channel();
        let callback_completion = Arc::clone(&completion);
        assert_send_sync(&callback_completion);
        let callback = RcBlock::new(move |error: *mut NSError| {
            finish_callback(&callback_completion, "authorization", || {
                error_only_callback_result(error)
            });
        });

        // SAFETY: The heap block owns only Arc-backed thread-safe state and
        // catches all panics. `right`, `reason`, and `callback` remain alive
        // until the completion result is received.
        unsafe { right.authorizeWithLocalizedReason_completion(&reason, &callback) };
        wait_for_callback(receiver, "authorization")
    }

    fn fetch_right(&self, identifier: &str) -> CallbackResult<Option<SendablePersistedRight>> {
        // SAFETY: sharedStore is the designated non-null LARightStore singleton.
        let store = unsafe { LARightStore::sharedStore() };
        let identifier = NSString::from_str(identifier);
        let (completion, receiver) = Completion::channel();
        let callback_completion = Arc::clone(&completion);
        assert_send_sync(&callback_completion);
        let callback = RcBlock::new(move |right: *mut LAPersistedRight, error: *mut NSError| {
            finish_callback(&callback_completion, "fetch", || {
                fetched_right_callback_result(right, error)
            });
        });

        // SAFETY: The sendable heap block captures only Arc-backed completion
        // state. Store, identifier, and callback live until recv completes.
        unsafe { store.rightForIdentifier_completion(&identifier, &callback) };
        match wait_for_callback(receiver, "fetch") {
            Ok(right) => Ok(Some(right)),
            Err(MacLocalAuthenticationError::MissingItem) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn save_right(&self, identifier: &str, secret: &[u8]) -> CallbackResult<()> {
        // SAFETY: sharedStore is the designated non-null LARightStore singleton.
        let store = unsafe { LARightStore::sharedStore() };
        let right = strict_biometry_right();
        let identifier = NSString::from_str(identifier);
        let secret = NSData::with_bytes(secret);
        let (completion, receiver) = Completion::channel();
        let callback_completion = Arc::clone(&completion);
        assert_send_sync(&callback_completion);
        let callback = RcBlock::new(move |right: *mut LAPersistedRight, error: *mut NSError| {
            finish_callback(&callback_completion, "save", || {
                saved_right_callback_result(right, error)
            });
        });

        // SAFETY: The sendable heap block captures only Arc-backed completion
        // state. All Objective-C arguments and the block outlive the callback.
        unsafe {
            store.saveRight_identifier_secret_completion(&right, &identifier, &secret, &callback)
        };
        wait_for_callback(receiver, "save")
    }

    fn remove_right(&self, identifier: &str) -> CallbackResult<()> {
        // SAFETY: sharedStore is the designated non-null LARightStore singleton.
        let store = unsafe { LARightStore::sharedStore() };
        let identifier = NSString::from_str(identifier);
        let (completion, receiver) = Completion::channel();
        let callback_completion = Arc::clone(&completion);
        assert_send_sync(&callback_completion);
        let callback = RcBlock::new(move |error: *mut NSError| {
            finish_callback(&callback_completion, "remove", || {
                error_only_callback_result(error)
            });
        });

        // SAFETY: The heap block captures only Arc-backed thread-safe state;
        // store, identifier, and callback remain live through completion.
        unsafe { store.removeRightForIdentifier_completion(&identifier, &callback) };
        wait_for_callback(receiver, "remove")
    }

    fn load_secret(&self, secret: &LASecret) -> CallbackResult<Vec<u8>> {
        let (completion, receiver) = Completion::channel();
        let callback_completion = Arc::clone(&completion);
        assert_send_sync(&callback_completion);
        let callback = RcBlock::new(move |data: *mut NSData, error: *mut NSError| {
            finish_callback(&callback_completion, "secret load", || {
                loaded_data_callback_result(data, error)
            });
        });

        // SAFETY: The block captures only Arc-backed thread-safe state and
        // `secret` plus the callback remain live until completion.
        unsafe { secret.loadDataWithCompletion(&callback) };
        wait_for_callback(receiver, "secret load")
    }
}

impl MacLocalAuthenticationApi for MacLocalAuthentication {
    fn is_touch_id_available(&self) -> bool {
        autoreleasepool(|_| {
            // SAFETY: LAContext::new is available and returns retained context.
            let context = unsafe { LAContext::new() };
            // SAFETY: The policy is valid and the generated binding owns the
            // NSError result when evaluation is unavailable.
            let policy_available = unsafe {
                context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            }
            .is_ok();
            if !policy_available {
                return false;
            }
            // SAFETY: Apple documents biometryType after canEvaluatePolicy.
            touch_id_policy_is_available(true, unsafe { context.biometryType() })
        })
    }

    fn authorize(&self, reason: &str) -> Result<()> {
        autoreleasepool(|_| {
            self.authorize_right(&strict_biometry_right(), reason)
                .map_err(Into::into)
        })
    }

    fn contains(&self, identifier: &str) -> Result<bool> {
        autoreleasepool(|_| {
            self.fetch_right(identifier)
                .map(|right| right.is_some())
                .map_err(Into::into)
        })
    }

    fn save(&self, identifier: &str, secret: &[u8]) -> Result<()> {
        autoreleasepool(|_| self.save_right(identifier, secret).map_err(Into::into))
    }

    fn authorize_and_load(&self, identifier: &str, reason: &str) -> Result<Option<Vec<u8>>> {
        autoreleasepool(|_| {
            let Some(right) = self.fetch_right(identifier)? else {
                return Ok(None);
            };
            self.authorize_right(&right.0, reason)?;
            // SAFETY: The fetched right remains retained and authorized while
            // its non-null managed LASecret is loaded.
            let secret = unsafe { right.0.secret() };
            self.load_secret(&secret).map(Some)
        })
        .map_err(Into::into)
    }

    fn remove(&self, identifier: &str) -> Result<()> {
        autoreleasepool(|_| self.remove_right(identifier).map_err(Into::into))
    }
}

#[cfg(test)]
mod tests {
    use objc2_local_authentication::LABiometryType;

    use super::{NSErrorSnapshot, touch_id_policy_is_available};

    #[test]
    fn macos_quick_unlock_touch_id_policy_rejects_other_biometry_types() {
        assert!(touch_id_policy_is_available(true, LABiometryType::TouchID));
        assert!(!touch_id_policy_is_available(true, LABiometryType::None));
        assert!(!touch_id_policy_is_available(true, LABiometryType::FaceID));
        assert!(!touch_id_policy_is_available(
            false,
            LABiometryType::TouchID
        ));
    }

    #[test]
    fn macos_quick_unlock_missing_item_recognition_walks_underlying_error_snapshots() {
        let snapshot = NSErrorSnapshot {
            domain: "com.apple.LocalAuthentication".into(),
            code: -1019,
            description: "Biometric accessory is not connected.".into(),
            underlying: vec![NSErrorSnapshot {
                domain: "NSOSStatusErrorDomain".into(),
                code: -25300,
                description: "The specified item could not be found in the keychain.".into(),
                underlying: Vec::new(),
            }],
        };

        assert!(snapshot.is_missing_item());
    }

    #[test]
    fn macos_quick_unlock_unrelated_error_snapshot_is_not_missing_item() {
        let snapshot = NSErrorSnapshot {
            domain: "com.apple.LocalAuthentication".into(),
            code: -2,
            description: "User canceled.".into(),
            underlying: Vec::new(),
        };

        assert!(!snapshot.is_missing_item());
    }
}
