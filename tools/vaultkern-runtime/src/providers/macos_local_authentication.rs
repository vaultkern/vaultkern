use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use block2::RcBlock;
use objc2::rc::autoreleasepool;
use objc2::runtime::Bool;
use objc2_foundation::{NSDate, NSError, NSRunLoop, NSString};
use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};

type CallbackResult<T> = std::result::Result<T, MacLocalAuthenticationError>;

pub(super) trait MacLocalAuthenticationApi {
    fn is_touch_id_available(&self) -> bool;
    fn authorize(&self, reason: &str) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NSErrorSnapshot {
    domain: String,
    code: isize,
    description: String,
}

impl NSErrorSnapshot {
    fn from_error(error: &NSError) -> Self {
        Self {
            domain: error.domain().to_string(),
            code: error.code(),
            description: error.localizedDescription().to_string(),
        }
    }
}

#[derive(Debug)]
pub(super) enum MacLocalAuthenticationError {
    Apple(NSErrorSnapshot),
    InvalidCallback(&'static str),
    CallbackPanicked(&'static str),
    CallbackDisconnected(&'static str),
}

impl fmt::Display for MacLocalAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
    wait_for_callback_with_pump(receiver, operation, || {
        autoreleasepool(|_| {
            // Native messaging runs on the main thread, so blocking here would
            // prevent Cocoa from delivering the LocalAuthentication callback.
            let deadline = NSDate::dateWithTimeIntervalSinceNow(0.05);
            NSRunLoop::currentRunLoop().runUntilDate(&deadline);
        });
        // A run loop with no registered sources can return immediately.
        std::thread::sleep(Duration::from_millis(1));
    })
}

fn wait_for_callback_with_pump<T>(
    receiver: Receiver<CallbackResult<T>>,
    operation: &'static str,
    mut pump: impl FnMut(),
) -> CallbackResult<T> {
    loop {
        match receiver.try_recv() {
            Ok(result) => return result,
            Err(TryRecvError::Empty) => pump(),
            Err(TryRecvError::Disconnected) => {
                return Err(MacLocalAuthenticationError::CallbackDisconnected(operation));
            }
        }
    }
}

fn assert_send_sync<T: Send + Sync>(_: &T) {}

fn snapshot_callback_error(error: *mut NSError) -> Option<NSErrorSnapshot> {
    // SAFETY: LocalAuthentication supplies either null or a valid NSError for
    // the duration of the completion callback. The snapshot owns every field.
    unsafe { error.as_ref().map(NSErrorSnapshot::from_error) }
}

fn policy_evaluation_result(succeeded: bool, error: Option<NSErrorSnapshot>) -> CallbackResult<()> {
    match (succeeded, error) {
        (true, None) => Ok(()),
        (_, Some(error)) => Err(MacLocalAuthenticationError::Apple(error)),
        (false, None) => Err(MacLocalAuthenticationError::InvalidCallback(
            "policy evaluation",
        )),
    }
}

fn policy_evaluation_callback_result(succeeded: Bool, error: *mut NSError) -> CallbackResult<()> {
    policy_evaluation_result(succeeded.as_bool(), snapshot_callback_error(error))
}

pub(super) fn touch_id_policy_is_available(
    policy_available: bool,
    biometry_type: LABiometryType,
) -> bool {
    policy_available && biometry_type == LABiometryType::TouchID
}

pub(super) struct MacLocalAuthentication;

impl MacLocalAuthentication {
    fn authorize_policy(&self, reason: &str) -> CallbackResult<()> {
        // SAFETY: LAContext::new is available and returns a retained context.
        let context = unsafe { LAContext::new() };
        let reason = NSString::from_str(reason);
        let (completion, receiver) = Completion::channel();
        let callback_completion = Arc::clone(&completion);
        assert_send_sync(&callback_completion);
        let callback = RcBlock::new(move |succeeded: Bool, error: *mut NSError| {
            finish_callback(&callback_completion, "policy evaluation", || {
                policy_evaluation_callback_result(succeeded, error)
            });
        });

        // SAFETY: The sendable heap block captures only Arc-backed completion
        // state. Context, reason, and callback remain alive through completion.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &reason,
                &callback,
            )
        };
        wait_for_callback(receiver, "policy evaluation")
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
        autoreleasepool(|_| self.authorize_policy(reason).map_err(Into::into))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::sync_channel;
    use std::thread;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2_foundation::NSRunLoop;
    use objc2_local_authentication::LABiometryType;

    use super::{
        Completion, MacLocalAuthenticationError, NSErrorSnapshot, policy_evaluation_result,
        touch_id_policy_is_available, wait_for_callback, wait_for_callback_with_pump,
    };

    #[test]
    fn macos_quick_unlock_callback_wait_pumps_until_completion() {
        let (sender, receiver) = sync_channel(1);
        let pump_calls = Cell::new(0);

        let result = wait_for_callback_with_pump(receiver, "authorization", || {
            pump_calls.set(pump_calls.get() + 1);
            sender
                .send(Ok(()))
                .expect("callback result should be received");
        });

        assert!(result.is_ok());
        assert_eq!(pump_calls.get(), 1);
    }

    #[test]
    fn macos_quick_unlock_callback_wait_services_current_run_loop() {
        let (completion, receiver) = Completion::channel();
        let (cancel_watchdog, watchdog_cancelled) = sync_channel(1);
        let did_run = Arc::new(AtomicBool::new(false));
        let callback_completion = Arc::clone(&completion);
        let callback_did_run = Arc::clone(&did_run);
        let callback = RcBlock::new(move || {
            callback_did_run.store(true, Ordering::SeqCst);
            callback_completion.finish(Ok(()));
        });

        // SAFETY: The block captures only Send + Sync Arc-backed state.
        unsafe { NSRunLoop::currentRunLoop().performBlock(&callback) };

        let watchdog_completion = Arc::clone(&completion);
        let watchdog = thread::spawn(move || {
            if watchdog_cancelled
                .recv_timeout(Duration::from_millis(500))
                .is_err()
            {
                watchdog_completion.finish(Err(MacLocalAuthenticationError::InvalidCallback(
                    "run loop test timeout",
                )));
            }
        });

        let result = wait_for_callback(receiver, "run loop test");
        let _ = cancel_watchdog.send(());
        watchdog.join().expect("watchdog should exit cleanly");

        assert!(result.is_ok());
        assert!(did_run.load(Ordering::SeqCst));
    }

    #[test]
    fn macos_quick_unlock_callback_panics_are_returned_as_errors() {
        let (completion, receiver) = Completion::channel();

        super::finish_callback(
            &completion,
            "policy evaluation",
            || -> super::CallbackResult<()> {
                panic!("injected callback panic");
            },
        );

        assert!(matches!(
            receiver.recv().unwrap(),
            Err(MacLocalAuthenticationError::CallbackPanicked(
                "policy evaluation"
            ))
        ));
    }

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
    fn macos_quick_unlock_transient_policy_accepts_success_without_an_error() {
        assert!(policy_evaluation_result(true, None).is_ok());
    }

    #[test]
    fn macos_quick_unlock_transient_policy_preserves_apple_errors() {
        let snapshot = NSErrorSnapshot {
            domain: "com.apple.LocalAuthentication".into(),
            code: -2,
            description: "User canceled.".into(),
        };

        let error = policy_evaluation_result(false, Some(snapshot.clone())).unwrap_err();

        let MacLocalAuthenticationError::Apple(actual) = error else {
            panic!("policy failure did not preserve the Apple error");
        };
        assert_eq!(actual, snapshot);
    }

    #[test]
    fn macos_quick_unlock_transient_policy_rejects_failure_without_an_error() {
        assert!(matches!(
            policy_evaluation_result(false, None),
            Err(MacLocalAuthenticationError::InvalidCallback(
                "policy evaluation"
            ))
        ));
    }
}
