//! Windows Service Control Manager host for `netpland`.

use std::ffi::c_void;
use std::io;
use std::sync::atomic::{AtomicPtr, Ordering};

use netplan::DAEMON_SERVICE_NAME;
use tokio::sync::watch;
use windows::Win32::Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
    StartServiceCtrlDispatcherW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::run_daemon;

struct ServiceContext {
    shutdown: watch::Sender<bool>,
    status_handle: AtomicPtr<c_void>,
}

pub(crate) fn run_dispatcher() -> io::Result<()> {
    let mut service_name = wide(DAEMON_SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(service_name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: The table is NUL-terminated, both entries and the service-name buffer remain
    // alive while the dispatcher blocks, and `service_main` uses the required ABI.
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }.map_err(|error| windows_io(&error))
}

unsafe extern "system" fn service_main(_argument_count: u32, _arguments: *mut PWSTR) {
    if let Err(error) = service_main_inner() {
        eprintln!("netpland service failed: {error}");
    }
}

fn service_main_inner() -> io::Result<()> {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let context = Box::new(ServiceContext {
        shutdown,
        status_handle: AtomicPtr::new(std::ptr::null_mut()),
    });
    let service_name = wide(DAEMON_SERVICE_NAME);
    let context_ptr = (&raw const *context).cast::<c_void>();
    // SAFETY: The service name is NUL-terminated, the callback has the required ABI, and the
    // boxed context remains alive until after the service reports `STOPPED`.
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            PCWSTR(service_name.as_ptr()),
            Some(control_handler),
            Some(context_ptr),
        )
    }
    .map_err(|error| windows_io(&error))?;
    context
        .status_handle
        .store(status_handle.0, Ordering::Release);
    set_status(
        status_handle,
        SERVICE_START_PENDING,
        0,
        NO_ERROR.0,
        1,
        5_000,
    )?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    set_status(
        status_handle,
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP,
        NO_ERROR.0,
        0,
        0,
    )?;
    let result = runtime.block_on(run_daemon(
        netplan::client::DEFAULT_WINDOWS_ENDPOINT.into(),
        context.shutdown.clone(),
        shutdown_rx,
    ));
    let exit_code = if result.is_ok() {
        NO_ERROR.0
    } else {
        ERROR_SERVICE_SPECIFIC_ERROR.0
    };
    set_status(status_handle, SERVICE_STOPPED, 0, exit_code, 0, 0)?;
    result
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    context: *mut c_void,
) -> u32 {
    if control == SERVICE_CONTROL_STOP && !context.is_null() {
        // SAFETY: SCM supplies the same boxed context pointer registered by
        // `service_main_inner`, and that allocation remains alive until `STOPPED` is reported.
        let context = unsafe { &*context.cast::<ServiceContext>() };
        let status = context.status_handle.load(Ordering::Acquire);
        if !status.is_null() {
            let _ = set_status(
                SERVICE_STATUS_HANDLE(status),
                SERVICE_STOP_PENDING,
                0,
                NO_ERROR.0,
                1,
                5_000,
            );
        }
        let _ = context.shutdown.send(true);
    }
    NO_ERROR.0
}

fn set_status(
    handle: SERVICE_STATUS_HANDLE,
    state: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
    accepted_controls: u32,
    win32_exit_code: u32,
    checkpoint: u32,
    wait_hint: u32,
) -> io::Result<()> {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted_controls,
        dwWin32ExitCode: win32_exit_code,
        dwServiceSpecificExitCode: u32::from(win32_exit_code != NO_ERROR.0),
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    // SAFETY: `handle` was returned by SCM and `status` is valid readable storage.
    unsafe { SetServiceStatus(handle, &raw const status) }.map_err(|error| windows_io(&error))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn windows_io(error: &windows::core::Error) -> io::Error {
    io::Error::other(error.to_string())
}
