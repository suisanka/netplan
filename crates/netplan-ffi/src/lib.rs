//! Stable C ABI for direct `FlatBuffers` access to `netpland`.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::expect_used, clippy::unwrap_used)]

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Mutex;

use netplan::{Client, Error};
use tokio::runtime::{Builder, Runtime};

/// Opaque client handle owned by the C caller.
pub struct NetplanClient {
    client: Client,
    runtime: Mutex<Runtime>,
    last_error: Mutex<CString>,
}

/// Operation succeeded.
pub const NETPLAN_OK: i32 = 0;
/// A pointer, length, UTF-8 string, or other argument was invalid.
pub const NETPLAN_INVALID_ARGUMENT: i32 = 1;
/// A `FlatBuffers` frame failed protocol verification.
pub const NETPLAN_PROTOCOL_ERROR: i32 = 2;
/// Local IPC failed.
pub const NETPLAN_IO_ERROR: i32 = 3;
/// Reserved for APIs that unwrap a typed daemon application error.
pub const NETPLAN_DAEMON_ERROR: i32 = 4;
/// Runtime initialization or synchronization failed.
pub const NETPLAN_INTERNAL_ERROR: i32 = 5;

/// Return the C ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn netplan_abi_version() -> u32 {
    1
}

/// Create a client using the supplied endpoint or the platform default when `endpoint` is null.
///
/// # Safety
///
/// `out_client` must point to writable storage for one pointer. When non-null, `endpoint` must
/// point to a valid NUL-terminated UTF-8 string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netplan_client_create(
    endpoint: *const c_char,
    out_client: *mut *mut NetplanClient,
) -> i32 {
    if out_client.is_null() {
        return NETPLAN_INVALID_ARGUMENT;
    }
    // Initialize the caller-owned slot even when a later step fails.
    // SAFETY: The caller contract requires `out_client` to be writable.
    unsafe { out_client.write(ptr::null_mut()) };
    let endpoint = if endpoint.is_null() {
        netplan::client::default_endpoint()
    } else {
        // SAFETY: The caller contract requires a valid NUL-terminated string.
        let value = unsafe { CStr::from_ptr(endpoint) };
        match value.to_str() {
            Ok(value) if !value.is_empty() => value.to_owned(),
            _ => return NETPLAN_INVALID_ARGUMENT,
        }
    };
    let Ok(runtime) = Builder::new_current_thread().enable_all().build() else {
        return NETPLAN_INTERNAL_ERROR;
    };
    let handle = Box::new(NetplanClient {
        client: Client::new(endpoint),
        runtime: Mutex::new(runtime),
        last_error: Mutex::new(empty_c_string()),
    });
    // SAFETY: The caller contract requires `out_client` to be writable. Ownership is transferred
    // to the caller and must later be returned to `netplan_client_destroy` exactly once.
    unsafe { out_client.write(Box::into_raw(handle)) };
    NETPLAN_OK
}

/// Destroy a client returned by `netplan_client_create`.
///
/// # Safety
///
/// `client` must be null or a live pointer returned by `netplan_client_create` that has not
/// previously been destroyed. No other thread may use the handle during this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netplan_client_destroy(client: *mut NetplanClient) {
    if client.is_null() {
        return;
    }
    // SAFETY: The caller contract transfers the unique allocation back to Rust exactly once.
    let handle = unsafe { Box::from_raw(client) };
    let NetplanClient { runtime, .. } = *handle;
    let runtime = match runtime.into_inner() {
        Ok(runtime) => runtime,
        Err(poisoned) => poisoned.into_inner(),
    };
    // This avoids Tokio's blocking Runtime drop path, which is invalid inside an async context.
    runtime.shutdown_background();
}

/// Send one size-prefixed `PNET` `FlatBuffers` request and receive the encoded response.
///
/// # Safety
///
/// `client` must be a live client handle. `request` must reference `request_len` readable bytes.
/// `out_response` and `out_response_len` must be writable. On success, the returned buffer must
/// be released exactly once with `netplan_buffer_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netplan_client_call(
    client: *mut NetplanClient,
    request: *const u8,
    request_len: usize,
    out_response: *mut *mut u8,
    out_response_len: *mut usize,
) -> i32 {
    if client.is_null()
        || request.is_null()
        || request_len == 0
        || out_response.is_null()
        || out_response_len.is_null()
    {
        return NETPLAN_INVALID_ARGUMENT;
    }
    // SAFETY: The caller contract requires both output slots to be writable.
    unsafe {
        out_response.write(ptr::null_mut());
        out_response_len.write(0);
    }
    // SAFETY: The caller contract guarantees `request_len` readable bytes.
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    // SAFETY: The null check above establishes a live handle for the duration of this call.
    let handle = unsafe { &*client };
    let Ok(runtime) = handle.runtime.lock() else {
        set_last_error(handle, "runtime lock is poisoned");
        return NETPLAN_INTERNAL_ERROR;
    };
    let call = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(handle.client.call_frame(request))
    }));
    let response = match call {
        Err(_) => {
            set_last_error(handle, "the host thread cannot drive the Netplan runtime");
            return NETPLAN_INTERNAL_ERROR;
        }
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            set_last_error(handle, &error.to_string());
            return status_for_error(&error);
        }
    };
    let response = response.into_boxed_slice();
    let response_len = response.len();
    let response_ptr = Box::into_raw(response).cast::<u8>();
    // SAFETY: The output slots were validated above. The boxed slice allocation is now owned by
    // the caller until passed to `netplan_buffer_free` with this exact length.
    unsafe {
        out_response.write(response_ptr);
        out_response_len.write(response_len);
    }
    NETPLAN_OK
}

/// Release a response buffer returned by `netplan_client_call`.
///
/// # Safety
///
/// `data` and `len` must be the unchanged values returned by a successful call and must not have
/// been freed previously. A null pointer is accepted and ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netplan_buffer_free(data: *mut u8, len: usize) {
    if data.is_null() {
        return;
    }
    let slice = ptr::slice_from_raw_parts_mut(data, len);
    // SAFETY: The caller contract returns the unique boxed-slice allocation with its exact length.
    unsafe { drop(Box::from_raw(slice)) };
}

/// Copy the last client error as UTF-8, returning the required byte count including NUL.
///
/// Passing a null buffer or zero capacity only queries the required size. The output is always
/// NUL-terminated when capacity is nonzero.
///
/// # Safety
///
/// `client` must be a live handle. When non-null, `buffer` must reference `capacity` writable
/// bytes. The returned message may change after the next call on the same handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netplan_client_last_error(
    client: *const NetplanClient,
    buffer: *mut c_char,
    capacity: usize,
) -> usize {
    if client.is_null() {
        return 0;
    }
    // SAFETY: The caller contract establishes a live shared handle.
    let handle = unsafe { &*client };
    let Ok(message) = handle.last_error.lock() else {
        return 0;
    };
    let bytes = message.as_bytes_with_nul();
    if !buffer.is_null() && capacity > 0 {
        let copy_len = bytes.len().min(capacity);
        // SAFETY: The caller contract guarantees `capacity` writable bytes and the source is a
        // distinct CString allocation.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast::<u8>(), copy_len) };
        // Ensure termination even when the caller supplied a short buffer.
        // SAFETY: capacity is nonzero, so `capacity - 1` is within the writable output buffer.
        unsafe { buffer.add(copy_len.saturating_sub(1)).write(0) };
    }
    bytes.len()
}

fn status_for_error(error: &Error) -> i32 {
    match error {
        Error::Protocol(_) => NETPLAN_PROTOCOL_ERROR,
        Error::Io(_) => NETPLAN_IO_ERROR,
        Error::Daemon(_) => NETPLAN_DAEMON_ERROR,
        Error::Decode { .. } | Error::Validation(_) => NETPLAN_INVALID_ARGUMENT,
    }
}

fn set_last_error(client: &NetplanClient, message: &str) {
    if let Ok(mut target) = client.last_error.lock() {
        *target = CString::new(message).unwrap_or_else(|_| empty_c_string());
    }
}

fn empty_c_string() -> CString {
    CString::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_handle_lifecycle_accepts_default_endpoint() {
        let mut handle = ptr::null_mut();
        // SAFETY: `handle` is valid writable storage and the endpoint is intentionally null.
        let status = unsafe { netplan_client_create(ptr::null(), &raw mut handle) };
        assert_eq!(status, NETPLAN_OK);
        assert!(!handle.is_null());
        // SAFETY: The successful create call returned a unique live handle.
        unsafe { netplan_client_destroy(handle) };
    }

    #[tokio::test]
    async fn ffi_catches_nested_runtime_and_destroys_safely() {
        let mut handle = ptr::null_mut();
        // SAFETY: `handle` is valid writable storage and the endpoint is intentionally null.
        assert_eq!(
            unsafe { netplan_client_create(ptr::null(), &raw mut handle) },
            NETPLAN_OK
        );
        let request = netplan::protocol::encode_request(1, &netplan::protocol::Request::Ping);
        let mut response = ptr::null_mut();
        let mut response_len = 0;
        // SAFETY: All pointers refer to live storage for the duration of the call.
        let status = unsafe {
            netplan_client_call(
                handle,
                request.as_ptr(),
                request.len(),
                &raw mut response,
                &raw mut response_len,
            )
        };
        assert_eq!(status, NETPLAN_INTERNAL_ERROR);
        assert!(response.is_null());
        assert_eq!(response_len, 0);
        // SAFETY: The handle remains live and uniquely owned after the failed call.
        unsafe { netplan_client_destroy(handle) };
    }
}
