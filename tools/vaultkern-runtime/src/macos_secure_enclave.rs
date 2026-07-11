#![allow(dead_code)]

use std::ffi::c_void;
use std::fmt;

use zeroize::Zeroize;

const STATUS_OK: i32 = 0;
const STATUS_MISSING_ITEM: i32 = 1;
const STATUS_AUTHENTICATION_FAILED: i32 = 2;
const STATUS_KEY_INVALIDATED: i32 = 3;
const STATUS_INTERACTION_UNAVAILABLE: i32 = 4;
const STATUS_PLATFORM_FAILURE: i32 = 5;

type BufferFree = unsafe extern "C" fn(*mut c_void, usize);

unsafe extern "C" {
    fn vaultkern_macos_quick_unlock_record_store(
        record_id: *const u8,
        record_id_length: usize,
        record: *const u8,
        record_length: usize,
        error_out: *mut *mut c_void,
        error_length_out: *mut usize,
    ) -> i32;
    fn vaultkern_macos_quick_unlock_record_contains(
        record_id: *const u8,
        record_id_length: usize,
        error_out: *mut *mut c_void,
        error_length_out: *mut usize,
    ) -> i32;
    fn vaultkern_macos_quick_unlock_record_load(
        record_id: *const u8,
        record_id_length: usize,
        record_out: *mut *mut c_void,
        record_length_out: *mut usize,
        error_out: *mut *mut c_void,
        error_length_out: *mut usize,
    ) -> i32;
    fn vaultkern_macos_quick_unlock_record_delete(
        record_id: *const u8,
        record_id_length: usize,
        error_out: *mut *mut c_void,
        error_length_out: *mut usize,
    ) -> i32;
    fn vaultkern_macos_secure_enclave_is_available() -> i32;
    fn vaultkern_macos_secure_enclave_create(
        salt: *const u8,
        salt_length: usize,
        shared_info: *const u8,
        shared_info_length: usize,
        private_key_out: *mut *mut c_void,
        private_key_length_out: *mut usize,
        peer_public_key_out: *mut *mut c_void,
        peer_public_key_length_out: *mut usize,
        kek_out: *mut *mut c_void,
        kek_length_out: *mut usize,
        error_out: *mut *mut c_void,
        error_length_out: *mut usize,
    ) -> i32;
    fn vaultkern_macos_secure_enclave_restore_and_derive(
        private_key: *const u8,
        private_key_length: usize,
        peer_public_key: *const u8,
        peer_public_key_length: usize,
        salt: *const u8,
        salt_length: usize,
        shared_info: *const u8,
        shared_info_length: usize,
        localized_reason: *const u8,
        localized_reason_length: usize,
        kek_out: *mut *mut c_void,
        kek_length_out: *mut usize,
        error_out: *mut *mut c_void,
        error_length_out: *mut usize,
    ) -> i32;
    fn vaultkern_macos_buffer_free(pointer: *mut c_void, length: usize);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BridgeErrorKind {
    MissingItem,
    AuthenticationFailed,
    KeyInvalidated,
    InteractionUnavailable,
    PlatformFailure,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct BridgeError {
    kind: BridgeErrorKind,
    diagnostic: String,
}

impl BridgeError {
    fn from_status(status: i32, diagnostic: String) -> Self {
        let kind = match status {
            STATUS_MISSING_ITEM => BridgeErrorKind::MissingItem,
            STATUS_AUTHENTICATION_FAILED => BridgeErrorKind::AuthenticationFailed,
            STATUS_KEY_INVALIDATED => BridgeErrorKind::KeyInvalidated,
            STATUS_INTERACTION_UNAVAILABLE => BridgeErrorKind::InteractionUnavailable,
            STATUS_PLATFORM_FAILURE => BridgeErrorKind::PlatformFailure,
            _ => BridgeErrorKind::PlatformFailure,
        };
        Self { kind, diagnostic }
    }

    fn platform(diagnostic: impl Into<String>) -> Self {
        Self {
            kind: BridgeErrorKind::PlatformFailure,
            diagnostic: diagnostic.into(),
        }
    }

    pub(super) fn kind(&self) -> BridgeErrorKind {
        self.kind
    }

    pub(super) fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "macOS security bridge {:?}: {}",
            self.kind, self.diagnostic
        )
    }
}

impl std::error::Error for BridgeError {}

struct ForeignBuffer {
    pointer: *mut c_void,
    length: usize,
    free: BufferFree,
}

impl ForeignBuffer {
    /// The pointer must either be null or be an allocation owned by `free`.
    unsafe fn new(pointer: *mut c_void, length: usize, free: BufferFree) -> Self {
        Self {
            pointer,
            length,
            free,
        }
    }

    fn bytes(&self, label: &str) -> Result<&[u8], BridgeError> {
        if self.pointer.is_null() {
            return Err(BridgeError::platform(format!(
                "Swift returned a null {label} buffer with length {}",
                self.length
            )));
        }
        if self.length > isize::MAX as usize {
            return Err(BridgeError::platform(format!(
                "Swift returned an oversized {label} buffer"
            )));
        }
        // SAFETY: The Swift bridge owns a readable allocation of exactly
        // `length` bytes until this guard invokes its matching free function.
        Ok(unsafe { std::slice::from_raw_parts(self.pointer.cast::<u8>(), self.length) })
    }

    fn to_vec(&self, label: &str) -> Result<Vec<u8>, BridgeError> {
        self.bytes(label).map(<[u8]>::to_vec)
    }

    fn to_secret32(&self, label: &str) -> Result<Secret32, BridgeError> {
        Secret32::from_slice(self.bytes(label)?, label)
    }

    fn diagnostic_or_fallback(&self, status: i32) -> String {
        if self.pointer.is_null() {
            return format!("Swift bridge failed with status {status} without diagnostics");
        }
        match self.to_vec("diagnostic") {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) => error.diagnostic,
        }
    }
}

impl Drop for ForeignBuffer {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: `new` requires this pointer to be owned by the matching
            // Swift allocator. The Swift free path zeroes before deallocation.
            unsafe { (self.free)(self.pointer, self.length) };
            self.pointer = std::ptr::null_mut();
            self.length = 0;
        }
    }
}

#[derive(Default)]
struct RawOutput {
    pointer: *mut c_void,
    length: usize,
}

impl RawOutput {
    unsafe fn into_foreign(self) -> ForeignBuffer {
        unsafe { ForeignBuffer::new(self.pointer, self.length, vaultkern_macos_buffer_free) }
    }
}

pub(super) struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub(super) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveBytes")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(super) struct Secret32([u8; 32]);

impl Secret32 {
    fn from_slice(bytes: &[u8], label: &str) -> Result<Self, BridgeError> {
        let value: [u8; 32] = bytes.try_into().map_err(|_| {
            BridgeError::platform(format!(
                "Swift returned {} bytes for {label}; expected 32",
                bytes.len()
            ))
        })?;
        Ok(Self(value))
    }

    pub(super) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret32([REDACTED])")
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug)]
pub(super) struct CreatedKeyMaterial {
    private_key: SensitiveBytes,
    peer_public_key: Vec<u8>,
    kek: Secret32,
}

impl CreatedKeyMaterial {
    pub(super) fn private_key(&self) -> &[u8] {
        self.private_key.expose()
    }

    pub(super) fn peer_public_key(&self) -> &[u8] {
        &self.peer_public_key
    }

    pub(super) fn kek(&self) -> &Secret32 {
        &self.kek
    }
}

fn ffi_pointer(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        std::ptr::null()
    } else {
        bytes.as_ptr()
    }
}

pub(super) fn is_secure_enclave_available() -> bool {
    // SAFETY: This C ABI function accepts no pointers and returns 0 or 1.
    unsafe { vaultkern_macos_secure_enclave_is_available() == 1 }
}

pub(super) fn store_quick_unlock_record(record_id: &str, record: &[u8]) -> Result<(), BridgeError> {
    let record_id = record_id.as_bytes();
    let mut diagnostic = RawOutput::default();

    // SAFETY: Both input slices remain valid for the synchronous call and the
    // diagnostic output points to initialized stack storage.
    let status = unsafe {
        vaultkern_macos_quick_unlock_record_store(
            ffi_pointer(record_id),
            record_id.len(),
            ffi_pointer(record),
            record.len(),
            &mut diagnostic.pointer,
            &mut diagnostic.length,
        )
    };

    // SAFETY: Swift leaves this null or transfers it to the matching free path.
    let diagnostic = unsafe { diagnostic.into_foreign() };
    if status != STATUS_OK {
        return Err(BridgeError::from_status(
            status,
            diagnostic.diagnostic_or_fallback(status),
        ));
    }
    Ok(())
}

pub(super) fn quick_unlock_record_exists(record_id: &str) -> Result<bool, BridgeError> {
    let record_id = record_id.as_bytes();
    let mut diagnostic = RawOutput::default();

    // SAFETY: The record ID remains valid for the synchronous call and the
    // diagnostic output points to initialized stack storage.
    let status = unsafe {
        vaultkern_macos_quick_unlock_record_contains(
            ffi_pointer(record_id),
            record_id.len(),
            &mut diagnostic.pointer,
            &mut diagnostic.length,
        )
    };

    // SAFETY: Swift leaves this null or transfers it to the matching free path.
    let diagnostic = unsafe { diagnostic.into_foreign() };
    match status {
        STATUS_OK => Ok(true),
        STATUS_MISSING_ITEM => Ok(false),
        _ => Err(BridgeError::from_status(
            status,
            diagnostic.diagnostic_or_fallback(status),
        )),
    }
}

pub(super) fn load_quick_unlock_record(record_id: &str) -> Result<SensitiveBytes, BridgeError> {
    let record_id = record_id.as_bytes();
    let mut record = RawOutput::default();
    let mut diagnostic = RawOutput::default();

    // SAFETY: The record ID remains valid for the call and both output pairs
    // point to initialized stack storage.
    let status = unsafe {
        vaultkern_macos_quick_unlock_record_load(
            ffi_pointer(record_id),
            record_id.len(),
            &mut record.pointer,
            &mut record.length,
            &mut diagnostic.pointer,
            &mut diagnostic.length,
        )
    };

    // SAFETY: Swift leaves each output null or transfers ownership to the
    // matching zeroizing free function.
    let record = unsafe { record.into_foreign() };
    let diagnostic = unsafe { diagnostic.into_foreign() };
    if status != STATUS_OK {
        return Err(BridgeError::from_status(
            status,
            diagnostic.diagnostic_or_fallback(status),
        ));
    }

    Ok(SensitiveBytes(record.to_vec("Quick Unlock record")?))
}

pub(super) fn delete_quick_unlock_record(record_id: &str) -> Result<(), BridgeError> {
    let record_id = record_id.as_bytes();
    let mut diagnostic = RawOutput::default();

    // SAFETY: The record ID remains valid for the synchronous call and the
    // diagnostic output points to initialized stack storage.
    let status = unsafe {
        vaultkern_macos_quick_unlock_record_delete(
            ffi_pointer(record_id),
            record_id.len(),
            &mut diagnostic.pointer,
            &mut diagnostic.length,
        )
    };

    // SAFETY: Swift leaves this null or transfers it to the matching free path.
    let diagnostic = unsafe { diagnostic.into_foreign() };
    if status != STATUS_OK {
        return Err(BridgeError::from_status(
            status,
            diagnostic.diagnostic_or_fallback(status),
        ));
    }
    Ok(())
}

pub(super) fn create_key_material(
    salt: &[u8],
    shared_info: &[u8],
) -> Result<CreatedKeyMaterial, BridgeError> {
    let mut private_key = RawOutput::default();
    let mut peer_public_key = RawOutput::default();
    let mut kek = RawOutput::default();
    let mut diagnostic = RawOutput::default();

    // SAFETY: Every input slice remains alive for the call, and every output
    // points to initialized pointer/length storage owned by this stack frame.
    let status = unsafe {
        vaultkern_macos_secure_enclave_create(
            ffi_pointer(salt),
            salt.len(),
            ffi_pointer(shared_info),
            shared_info.len(),
            &mut private_key.pointer,
            &mut private_key.length,
            &mut peer_public_key.pointer,
            &mut peer_public_key.length,
            &mut kek.pointer,
            &mut kek.length,
            &mut diagnostic.pointer,
            &mut diagnostic.length,
        )
    };

    // SAFETY: Swift either leaves each output null or transfers ownership to
    // the matching `vaultkern_macos_buffer_free` function.
    let private_key = unsafe { private_key.into_foreign() };
    let peer_public_key = unsafe { peer_public_key.into_foreign() };
    let kek = unsafe { kek.into_foreign() };
    let diagnostic = unsafe { diagnostic.into_foreign() };
    if status != STATUS_OK {
        return Err(BridgeError::from_status(
            status,
            diagnostic.diagnostic_or_fallback(status),
        ));
    }

    let private_key = SensitiveBytes(private_key.to_vec("private key representation")?);
    let peer_public_key = peer_public_key.to_vec("peer public key")?;
    let kek = kek.to_secret32("KEK")?;
    Ok(CreatedKeyMaterial {
        private_key,
        peer_public_key,
        kek,
    })
}

pub(super) fn restore_and_derive_kek(
    private_key: &[u8],
    peer_public_key: &[u8],
    salt: &[u8],
    shared_info: &[u8],
    localized_reason: &str,
) -> Result<Secret32, BridgeError> {
    let reason = localized_reason.as_bytes();
    let mut kek = RawOutput::default();
    let mut diagnostic = RawOutput::default();

    // SAFETY: Input buffers remain valid for the synchronous call and output
    // slots are initialized stack storage. The biometric prompt is owned by LA.
    let status = unsafe {
        vaultkern_macos_secure_enclave_restore_and_derive(
            ffi_pointer(private_key),
            private_key.len(),
            ffi_pointer(peer_public_key),
            peer_public_key.len(),
            ffi_pointer(salt),
            salt.len(),
            ffi_pointer(shared_info),
            shared_info.len(),
            ffi_pointer(reason),
            reason.len(),
            &mut kek.pointer,
            &mut kek.length,
            &mut diagnostic.pointer,
            &mut diagnostic.length,
        )
    };

    // SAFETY: Swift transfers every non-null output to the matching free path.
    let kek = unsafe { kek.into_foreign() };
    let diagnostic = unsafe { diagnostic.into_foreign() };
    if status != STATUS_OK {
        return Err(BridgeError::from_status(
            status,
            diagnostic.diagnostic_or_fallback(status),
        ));
    }

    kek.to_secret32("KEK")
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::sync::Mutex;

    use super::{
        BridgeError, BridgeErrorKind, ForeignBuffer, STATUS_AUTHENTICATION_FAILED,
        STATUS_INTERACTION_UNAVAILABLE, STATUS_KEY_INVALIDATED, STATUS_MISSING_ITEM,
        STATUS_PLATFORM_FAILURE, Secret32,
    };

    #[derive(Debug, PartialEq, Eq)]
    struct FreeObservation {
        before_zero: Vec<u8>,
        after_zero: Vec<u8>,
    }

    static FREE_OBSERVATIONS: Mutex<Vec<FreeObservation>> = Mutex::new(Vec::new());
    static BUFFER_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn recording_free(pointer: *mut c_void, length: usize) {
        let pointer = pointer.cast::<u8>();
        let before_zero = unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec();
        unsafe { pointer.write_bytes(0, length) };
        let after_zero = unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec();
        FREE_OBSERVATIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(FreeObservation {
                before_zero,
                after_zero,
            });
        let slice = std::ptr::slice_from_raw_parts_mut(pointer, length);
        drop(unsafe { Box::from_raw(slice) });
    }

    #[test]
    fn macos_bridge_owned_foreign_buffer_uses_matching_zeroizing_free_once() {
        let _test_guard = BUFFER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        FREE_OBSERVATIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let mut bytes = vec![0x11_u8, 0x22, 0x33, 0x44].into_boxed_slice();
        let pointer = bytes.as_mut_ptr().cast::<c_void>();
        let length = bytes.len();
        std::mem::forget(bytes);

        let buffer = unsafe { ForeignBuffer::new(pointer, length, recording_free) };
        assert_eq!(
            buffer.to_vec("test output").unwrap(),
            [0x11, 0x22, 0x33, 0x44]
        );
        drop(buffer);

        assert_eq!(
            *FREE_OBSERVATIONS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            [FreeObservation {
                before_zero: vec![0x11, 0x22, 0x33, 0x44],
                after_zero: vec![0, 0, 0, 0],
            }]
        );
    }

    #[test]
    fn macos_bridge_rejects_a_null_owned_buffer_without_reading_it() {
        let _test_guard = BUFFER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        FREE_OBSERVATIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let buffer = unsafe { ForeignBuffer::new(std::ptr::null_mut(), 32, recording_free) };

        let error = buffer.to_vec("KEK").unwrap_err();

        assert_eq!(error.kind(), BridgeErrorKind::PlatformFailure);
        assert!(error.diagnostic().contains("KEK"));
        assert!(
            FREE_OBSERVATIONS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn macos_bridge_requires_exactly_32_bytes_for_kek_material() {
        let bytes = [0x5a; 32];
        let secret = Secret32::from_slice(&bytes, "KEK").unwrap();
        assert_eq!(secret.expose(), &bytes);

        let error = Secret32::from_slice(&bytes[..31], "KEK").unwrap_err();
        assert_eq!(error.kind(), BridgeErrorKind::PlatformFailure);
        assert!(error.diagnostic().contains("32"));
        assert!(error.diagnostic().contains("31"));
    }

    #[test]
    fn macos_bridge_copies_kek_directly_from_the_owned_foreign_buffer() {
        let _test_guard = BUFFER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        FREE_OBSERVATIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let mut bytes = vec![0xa5_u8; 32].into_boxed_slice();
        let pointer = bytes.as_mut_ptr().cast::<c_void>();
        let length = bytes.len();
        std::mem::forget(bytes);
        let buffer = unsafe { ForeignBuffer::new(pointer, length, recording_free) };

        let secret = buffer.to_secret32("KEK").unwrap();
        assert_eq!(secret.expose(), &[0xa5; 32]);
        drop(buffer);

        assert_eq!(
            *FREE_OBSERVATIONS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            [FreeObservation {
                before_zero: vec![0xa5; 32],
                after_zero: vec![0; 32],
            }]
        );
    }

    #[test]
    fn macos_bridge_maps_each_security_error_class_and_preserves_diagnostics() {
        for (status, expected) in [
            (STATUS_MISSING_ITEM, BridgeErrorKind::MissingItem),
            (
                STATUS_AUTHENTICATION_FAILED,
                BridgeErrorKind::AuthenticationFailed,
            ),
            (STATUS_KEY_INVALIDATED, BridgeErrorKind::KeyInvalidated),
            (
                STATUS_INTERACTION_UNAVAILABLE,
                BridgeErrorKind::InteractionUnavailable,
            ),
            (STATUS_PLATFORM_FAILURE, BridgeErrorKind::PlatformFailure),
            (91_337, BridgeErrorKind::PlatformFailure),
        ] {
            let diagnostic = format!("NSOSStatusErrorDomain {status}: Apple diagnostic");
            let error = BridgeError::from_status(status, diagnostic.clone());

            assert_eq!(error.kind(), expected);
            assert_eq!(error.diagnostic(), diagnostic);
        }
    }

    #[test]
    fn macos_bridge_error_display_covers_keychain_and_secure_enclave_operations() {
        let error = BridgeError::platform("Keychain refused the request");

        assert_eq!(
            error.to_string(),
            "macOS security bridge PlatformFailure: Keychain refused the request"
        );
    }

    #[test]
    fn macos_bridge_availability_probe_links_and_is_noninteractive() {
        let first = super::is_secure_enclave_available();
        let second = super::is_secure_enclave_available();

        assert_eq!(first, second);
    }
}
