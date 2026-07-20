use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::slice;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use vaultkern_runtime::{
    PlatformPasskeyAssertionInput, PlatformPasskeyCredential, PlatformPasskeyRegistrationInput,
};

use crate::plugin_operation_state::{PluginOperationId, PluginOperationState};
use crate::{RuntimeBridge, plugin_callback_available};

const S_OK: i32 = 0;
const E_FAIL: i32 = 0x8000_4005_u32 as i32;
const E_INVALIDARG: i32 = 0x8007_0057_u32 as i32;
const NTE_EXISTS: i32 = 0x8009_000f_u32 as i32;
const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;
const HRESULT_ERROR_BUSY: i32 = 0x8007_00aa_u32 as i32;
const MAX_WIDE_STRING_UNITS: usize = 4096;
const MAX_CREDENTIAL_LIST_ITEMS: usize = 1024;
const MAX_FFI_BYTES: usize = 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
struct VkBytes {
    data: *const u8,
    len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VkOwnedBytes {
    data: *mut u8,
    len: u32,
}

#[repr(C)]
struct VkMakeCredentialInput {
    rp_id: *const u16,
    rp_name: *const u16,
    user_name: *const u16,
    user_display_name: *const u16,
    user_handle: VkBytes,
    public_key_algorithm: i32,
    excluded_credential_ids: *const VkBytes,
    excluded_credential_count: u32,
}

#[repr(C)]
struct VkMakeCredentialOutput {
    credential_id: VkOwnedBytes,
    authenticator_data: VkOwnedBytes,
}

#[repr(C)]
struct VkGetAssertionInput {
    rp_id: *const u16,
    allowed_credential_ids: *const VkBytes,
    allowed_credential_count: u32,
    client_data_hash: VkBytes,
}

#[repr(C)]
struct VkGetAssertionOutput {
    credential_id: VkOwnedBytes,
    authenticator_data: VkOwnedBytes,
    signature_der: VkOwnedBytes,
    user_handle: VkOwnedBytes,
}

#[repr(C)]
struct VkCredentialMetadata {
    credential_id: VkBytes,
    rp_id: *const u16,
    rp_name: *const u16,
    user_handle: VkBytes,
    user_name: *const u16,
    user_display_name: *const u16,
}

#[repr(C)]
struct VkPluginCallbacks {
    version: u32,
    context: *mut c_void,
    retain_context: extern "system" fn(*mut c_void),
    release_context: extern "system" fn(*mut c_void),
    is_unlocked: extern "system" fn(*mut c_void) -> i32,
    make_credential: extern "system" fn(
        *mut c_void,
        *const VkMakeCredentialInput,
        *mut VkMakeCredentialOutput,
    ) -> i32,
    get_assertion: extern "system" fn(
        *mut c_void,
        *const VkGetAssertionInput,
        *mut VkGetAssertionOutput,
    ) -> i32,
    begin_operation: extern "system" fn(*mut c_void, VkBytes) -> i32,
    is_operation_cancelled: extern "system" fn(*mut c_void, VkBytes) -> i32,
    cancel_operation: extern "system" fn(*mut c_void, VkBytes) -> i32,
    end_operation: extern "system" fn(*mut c_void, VkBytes),
    free_bytes: extern "system" fn(*mut c_void, VkOwnedBytes),
}

unsafe extern "system" {
    fn vaultkern_plugin_start(
        callbacks: *const VkPluginCallbacks,
        registration_cookie: *mut u32,
    ) -> i32;
    fn vaultkern_plugin_stop(registration_cookie: u32) -> i32;
    fn vaultkern_plugin_ensure_registered(authenticator_state: *mut i32) -> i32;
    fn vaultkern_plugin_remove_registered() -> i32;
    fn vaultkern_plugin_sync_credentials(
        credentials: *const VkCredentialMetadata,
        credential_count: u32,
    ) -> i32;
    #[cfg(test)]
    fn vaultkern_plugin_test_replaces_cached_account_credential() -> i32;
}

struct CallbackContext {
    bridge: RuntimeBridge,
    operations: PluginOperationState,
    enabled: Arc<AtomicBool>,
}

pub struct PasskeyPluginServer {
    context: Arc<CallbackContext>,
    registration_cookie: u32,
    start_error: Option<String>,
    enabled: Arc<AtomicBool>,
}

impl PasskeyPluginServer {
    pub fn start(bridge: RuntimeBridge) -> Self {
        let enabled = Arc::new(AtomicBool::new(false));
        let context = Arc::new(CallbackContext {
            bridge,
            operations: PluginOperationState::default(),
            enabled: Arc::clone(&enabled),
        });
        let callbacks = VkPluginCallbacks {
            version: 3,
            context: Arc::as_ptr(&context).cast_mut().cast(),
            retain_context: retain_context_callback,
            release_context: release_context_callback,
            is_unlocked: is_unlocked_callback,
            make_credential: make_credential_callback,
            get_assertion: get_assertion_callback,
            begin_operation: begin_operation_callback,
            is_operation_cancelled: is_operation_cancelled_callback,
            cancel_operation: cancel_operation_callback,
            end_operation: end_operation_callback,
            free_bytes: free_bytes_callback,
        };
        let mut registration_cookie = 0;
        let status = unsafe { vaultkern_plugin_start(&callbacks, &mut registration_cookie) };
        let start_error = failed(status).then(|| hresult_message("register COM class", status));
        Self {
            context,
            registration_cookie,
            start_error,
            enabled,
        }
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<bool, String> {
        if !enabled {
            let was_enabled = self.enabled.swap(false, Ordering::AcqRel);
            let status = unsafe { vaultkern_plugin_remove_registered() };
            if failed(status) {
                self.enabled.store(was_enabled, Ordering::Release);
                return Err(hresult_message("unregister plugin authenticator", status));
            }
            return Ok(false);
        }

        let os_enabled = self.ensure_registered()?;
        self.enabled.store(true, Ordering::Release);
        if let Err(error) = self.sync_credentials() {
            self.enabled.store(false, Ordering::Release);
            let _ = unsafe { vaultkern_plugin_remove_registered() };
            return Err(error);
        }
        Ok(os_enabled)
    }

    pub fn ensure_registered(&self) -> Result<bool, String> {
        self.ensure_started()?;
        let mut state = 0;
        let status = unsafe { vaultkern_plugin_ensure_registered(&mut state) };
        if failed(status) {
            return Err(hresult_message("register plugin authenticator", status));
        }
        Ok(state == 1)
    }

    pub fn sync_credentials(&self) -> Result<usize, String> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(0);
        }
        self.ensure_started()?;
        let credentials = self
            .context
            .bridge
            .list_platform_passkey_credentials_for_sync()?;
        let backings = credentials
            .iter()
            .map(CredentialBacking::new)
            .collect::<Vec<_>>();
        let native = backings
            .iter()
            .map(CredentialBacking::native)
            .collect::<Vec<_>>();
        let status = unsafe {
            vaultkern_plugin_sync_credentials(
                if native.is_empty() {
                    ptr::null()
                } else {
                    native.as_ptr()
                },
                native.len() as u32,
            )
        };
        if failed(status) {
            return Err(hresult_message("sync plugin credential cache", status));
        }
        Ok(native.len())
    }

    pub fn start_error(&self) -> Option<&str> {
        self.start_error.as_deref()
    }

    fn ensure_started(&self) -> Result<(), String> {
        match &self.start_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

extern "system" fn retain_context_callback(context: *mut c_void) {
    if !context.is_null() {
        unsafe {
            Arc::increment_strong_count(context.cast::<CallbackContext>());
        }
    }
}

extern "system" fn release_context_callback(context: *mut c_void) {
    if !context.is_null() {
        unsafe {
            Arc::decrement_strong_count(context.cast::<CallbackContext>());
        }
    }
}

extern "system" fn begin_operation_callback(context: *mut c_void, id: VkBytes) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let Some(context) = callback_context(context) else {
            return E_INVALIDARG;
        };
        let id = match operation_id(id) {
            Ok(id) => id,
            Err(status) => return status,
        };
        if context.operations.begin(id) {
            S_OK
        } else {
            HRESULT_ERROR_BUSY
        }
    }))
    .unwrap_or(E_FAIL)
}

extern "system" fn is_operation_cancelled_callback(context: *mut c_void, id: VkBytes) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let Some(context) = callback_context(context) else {
            return 1;
        };
        let Ok(id) = operation_id(id) else {
            return 1;
        };
        i32::from(context.operations.is_cancelled(id))
    }))
    .unwrap_or(1)
}

extern "system" fn cancel_operation_callback(context: *mut c_void, id: VkBytes) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let Some(context) = callback_context(context) else {
            return E_INVALIDARG;
        };
        let id = match operation_id(id) {
            Ok(id) => id,
            Err(status) => return status,
        };
        if context.operations.cancel(id) {
            S_OK
        } else {
            NTE_NOT_FOUND
        }
    }))
    .unwrap_or(E_FAIL)
}

extern "system" fn end_operation_callback(context: *mut c_void, id: VkBytes) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        let Some(context) = callback_context(context) else {
            return;
        };
        if let Ok(id) = operation_id(id) {
            context.operations.end(id);
        }
    }));
}

impl Drop for PasskeyPluginServer {
    fn drop(&mut self) {
        if self.registration_cookie != 0 {
            unsafe {
                let _ = vaultkern_plugin_stop(self.registration_cookie);
            }
        }
    }
}

struct CredentialBacking {
    credential_id: Vec<u8>,
    rp_id: Vec<u16>,
    rp_name: Vec<u16>,
    user_handle: Vec<u8>,
    user_name: Vec<u16>,
    user_display_name: Vec<u16>,
}

impl CredentialBacking {
    fn new(credential: &PlatformPasskeyCredential) -> Self {
        Self {
            credential_id: credential.credential_id.clone(),
            rp_id: nul_terminated_wide(&credential.relying_party),
            rp_name: nul_terminated_wide(&credential.relying_party_name),
            user_handle: credential.user_handle.clone(),
            user_name: nul_terminated_wide(&credential.user_name),
            user_display_name: nul_terminated_wide(&credential.user_display_name),
        }
    }

    fn native(&self) -> VkCredentialMetadata {
        VkCredentialMetadata {
            credential_id: borrowed_bytes(&self.credential_id),
            rp_id: self.rp_id.as_ptr(),
            rp_name: self.rp_name.as_ptr(),
            user_handle: borrowed_bytes(&self.user_handle),
            user_name: self.user_name.as_ptr(),
            user_display_name: self.user_display_name.as_ptr(),
        }
    }
}

extern "system" fn is_unlocked_callback(context: *mut c_void) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        callback_context(context)
            .is_some_and(callback_available)
            .into()
    }))
    .unwrap_or(0)
}

extern "system" fn make_credential_callback(
    context: *mut c_void,
    input: *const VkMakeCredentialInput,
    output: *mut VkMakeCredentialOutput,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        if output.is_null() {
            return E_INVALIDARG;
        }
        *output = VkMakeCredentialOutput {
            credential_id: empty_owned_bytes(),
            authenticator_data: empty_owned_bytes(),
        };
        let Some(context) = callback_context(context) else {
            return E_INVALIDARG;
        };
        if !callback_available(context) {
            return NTE_NOT_FOUND;
        }
        let Some(input) = input.as_ref() else {
            return E_INVALIDARG;
        };
        let rp_id = match wide_string(input.rp_id) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let user_name = match wide_string(input.user_name) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let user_handle = match byte_vec(input.user_handle) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let excluded = match byte_vec_list(
            input.excluded_credential_ids,
            input.excluded_credential_count,
        ) {
            Ok(value) => value,
            Err(status) => return status,
        };
        if !excluded.is_empty() {
            let credentials = match context.bridge.list_platform_passkey_credentials() {
                Ok(credentials) => credentials,
                Err(error) => return runtime_error_hresult(&error),
            };
            if credentials.iter().any(|credential| {
                credential.relying_party == rp_id
                    && excluded
                        .iter()
                        .any(|excluded| excluded == &credential.credential_id)
            }) {
                return NTE_EXISTS;
            }
        }

        let registration =
            match context
                .bridge
                .register_platform_passkey(PlatformPasskeyRegistrationInput {
                    relying_party: rp_id,
                    user_name,
                    user_handle,
                    public_key_algorithm: input.public_key_algorithm,
                    user_verified: true,
                }) {
                Ok(registration) => registration,
                Err(error) => return runtime_error_hresult(&error),
            };
        let credential_id = match owned_bytes(registration.credential.credential_id) {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        let authenticator_data = match owned_bytes(registration.authenticator_data) {
            Ok(bytes) => bytes,
            Err(status) => {
                free_owned_bytes(credential_id);
                return status;
            }
        };
        (*output).credential_id = credential_id;
        (*output).authenticator_data = authenticator_data;
        S_OK
    }))
    .unwrap_or(E_FAIL)
}

extern "system" fn get_assertion_callback(
    context: *mut c_void,
    input: *const VkGetAssertionInput,
    output: *mut VkGetAssertionOutput,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        if output.is_null() {
            return E_INVALIDARG;
        }
        *output = VkGetAssertionOutput {
            credential_id: empty_owned_bytes(),
            authenticator_data: empty_owned_bytes(),
            signature_der: empty_owned_bytes(),
            user_handle: empty_owned_bytes(),
        };
        let Some(context) = callback_context(context) else {
            return E_INVALIDARG;
        };
        if !callback_available(context) {
            return NTE_NOT_FOUND;
        }
        let Some(input) = input.as_ref() else {
            return E_INVALIDARG;
        };
        let relying_party = match wide_string(input.rp_id) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let allowed_credential_ids =
            match byte_vec_list(input.allowed_credential_ids, input.allowed_credential_count) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let client_data_hash = match byte_vec(input.client_data_hash) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let assertion =
            match context
                .bridge
                .create_platform_passkey_assertion(PlatformPasskeyAssertionInput {
                    relying_party,
                    allowed_credential_ids,
                    client_data_hash,
                    user_verified: true,
                }) {
                Ok(assertion) => assertion,
                Err(error) => return runtime_error_hresult(&error),
            };

        let values = [
            assertion.credential_id,
            assertion.authenticator_data,
            assertion.signature_der,
            assertion.user_handle,
        ];
        let mut owned = [empty_owned_bytes(); 4];
        for (index, value) in values.into_iter().enumerate() {
            match owned_bytes(value) {
                Ok(bytes) => owned[index] = bytes,
                Err(status) => {
                    for bytes in owned {
                        free_owned_bytes(bytes);
                    }
                    return status;
                }
            }
        }
        (*output).credential_id = owned[0];
        (*output).authenticator_data = owned[1];
        (*output).signature_der = owned[2];
        (*output).user_handle = owned[3];
        S_OK
    }))
    .unwrap_or(E_FAIL)
}

fn callback_available(context: &CallbackContext) -> bool {
    plugin_callback_available(
        context.enabled.load(Ordering::Acquire),
        context.bridge.platform_passkey_is_unlocked(),
    )
}

extern "system" fn free_bytes_callback(_context: *mut c_void, bytes: VkOwnedBytes) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        free_owned_bytes(bytes);
    }));
}

fn callback_context(context: *mut c_void) -> Option<&'static CallbackContext> {
    unsafe { context.cast::<CallbackContext>().as_ref() }
}

fn nul_terminated_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn borrowed_bytes(bytes: &[u8]) -> VkBytes {
    VkBytes {
        data: if bytes.is_empty() {
            ptr::null()
        } else {
            bytes.as_ptr()
        },
        len: bytes.len() as u32,
    }
}

unsafe fn wide_string(pointer: *const u16) -> Result<String, i32> {
    if pointer.is_null() {
        return Err(E_INVALIDARG);
    }
    let mut length = 0;
    while length < MAX_WIDE_STRING_UNITS {
        if unsafe { *pointer.add(length) } == 0 {
            return String::from_utf16(unsafe { slice::from_raw_parts(pointer, length) })
                .map_err(|_| E_INVALIDARG);
        }
        length += 1;
    }
    Err(E_INVALIDARG)
}

unsafe fn byte_vec(bytes: VkBytes) -> Result<Vec<u8>, i32> {
    let length = bytes.len as usize;
    if length > MAX_FFI_BYTES || (length != 0 && bytes.data.is_null()) {
        return Err(E_INVALIDARG);
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    Ok(unsafe { slice::from_raw_parts(bytes.data, length) }.to_vec())
}

unsafe fn operation_id(bytes: VkBytes) -> Result<PluginOperationId, i32> {
    if bytes.len as usize != std::mem::size_of::<PluginOperationId>() || bytes.data.is_null() {
        return Err(E_INVALIDARG);
    }
    unsafe { slice::from_raw_parts(bytes.data, bytes.len as usize) }
        .try_into()
        .map_err(|_| E_INVALIDARG)
}

unsafe fn byte_vec_list(pointer: *const VkBytes, count: u32) -> Result<Vec<Vec<u8>>, i32> {
    let count = count as usize;
    if count > MAX_CREDENTIAL_LIST_ITEMS || (count != 0 && pointer.is_null()) {
        return Err(E_INVALIDARG);
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    unsafe { slice::from_raw_parts(pointer, count) }
        .iter()
        .copied()
        .map(|bytes| unsafe { byte_vec(bytes) })
        .collect()
}

fn owned_bytes(bytes: Vec<u8>) -> Result<VkOwnedBytes, i32> {
    if bytes.len() > u32::MAX as usize {
        return Err(E_INVALIDARG);
    }
    if bytes.is_empty() {
        return Ok(empty_owned_bytes());
    }
    let mut bytes = bytes.into_boxed_slice();
    let output = VkOwnedBytes {
        data: bytes.as_mut_ptr(),
        len: bytes.len() as u32,
    };
    let _ = Box::into_raw(bytes);
    Ok(output)
}

const fn empty_owned_bytes() -> VkOwnedBytes {
    VkOwnedBytes {
        data: ptr::null_mut(),
        len: 0,
    }
}

unsafe fn free_owned_bytes(bytes: VkOwnedBytes) {
    if bytes.data.is_null() {
        return;
    }
    let slice = ptr::slice_from_raw_parts_mut(bytes.data, bytes.len as usize);
    unsafe {
        drop(Box::from_raw(slice));
    }
}

fn runtime_error_hresult(message: &str) -> i32 {
    if message.contains("not found")
        || message.contains("multiple passkey credentials found for credential id")
        || message.contains("active unlocked vault")
    {
        NTE_NOT_FOUND
    } else if message.contains("collision") || message.contains("already exists") {
        NTE_EXISTS
    } else {
        E_FAIL
    }
}

fn failed(status: i32) -> bool {
    status < 0
}

fn hresult_message(operation: &str, status: i32) -> String {
    format!("{operation} failed with HRESULT 0x{:08x}", status as u32)
}

#[cfg(test)]
mod tests {
    use super::{
        CallbackContext, NTE_NOT_FOUND, S_OK, VkOwnedBytes, free_owned_bytes, owned_bytes,
        release_context_callback, retain_context_callback, runtime_error_hresult,
        vaultkern_plugin_test_replaces_cached_account_credential,
    };
    use crate::RuntimeBridge;
    use crate::plugin_operation_state::PluginOperationState;
    use std::sync::{Arc, atomic::AtomicBool};

    #[test]
    fn ffi_context_lease_keeps_the_runtime_context_alive() {
        let context = Arc::new(CallbackContext {
            bridge: RuntimeBridge::new_for_tests(),
            operations: PluginOperationState::default(),
            enabled: Arc::new(AtomicBool::new(false)),
        });
        let weak = Arc::downgrade(&context);
        let raw = Arc::as_ptr(&context).cast_mut().cast();

        retain_context_callback(raw);
        drop(context);
        assert_eq!(weak.strong_count(), 1);

        release_context_callback(raw);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn owned_ffi_bytes_round_trip_through_the_matching_deallocator() {
        let bytes = owned_bytes(vec![1, 2, 3, 4]).unwrap();
        assert_eq!(bytes.len, 4);
        unsafe {
            assert_eq!(std::slice::from_raw_parts(bytes.data, 4), &[1, 2, 3, 4]);
            free_owned_bytes(bytes);
            free_owned_bytes(VkOwnedBytes {
                data: std::ptr::null_mut(),
                len: 0,
            });
        }
    }

    #[test]
    fn replacing_an_account_credential_evicts_the_old_cached_id() {
        assert_eq!(
            unsafe { vaultkern_plugin_test_replaces_cached_account_credential() },
            S_OK
        );
    }

    #[test]
    fn ambiguous_runtime_credentials_are_reported_as_not_found() {
        assert_eq!(
            runtime_error_hresult(
                "multiple passkey credentials found for credential id: duplicate-id"
            ),
            NTE_NOT_FOUND
        );
    }
}
