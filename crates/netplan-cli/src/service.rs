//! Daemon lifecycle commands and Windows service management.

use std::time::Duration;

#[cfg(windows)]
use std::path::PathBuf;

use netplan::Client;
#[cfg(windows)]
use netplan::client::DEFAULT_WINDOWS_ENDPOINT;
#[cfg(not(windows))]
use netplan::client::default_endpoint;
use netplan::protocol::{Request, Response};

use crate::{is_endpoint_absent, spawn_daemon};

const DAEMON_WAIT_ATTEMPTS: usize = 100;
const DAEMON_WAIT_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifecycleAction {
    Enable,
    Disable,
    Start,
    Stop,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LifecycleResult {
    pub(crate) action: &'static str,
    pub(crate) mode: &'static str,
    pub(crate) installed: bool,
    pub(crate) state: &'static str,
    pub(crate) message: String,
}

pub(crate) async fn execute(
    action: LifecycleAction,
    client: &Client,
) -> Result<LifecycleResult, String> {
    match action {
        LifecycleAction::Enable => enable(client).await,
        LifecycleAction::Disable => disable(client).await,
        LifecycleAction::Start => start(client).await,
        LifecycleAction::Stop => stop(client).await,
    }
}

#[cfg_attr(not(windows), allow(clippy::unnecessary_wraps))]
pub(crate) fn start_installed_service(endpoint: &str) -> Result<bool, String> {
    #[cfg(windows)]
    {
        if endpoint == DEFAULT_WINDOWS_ENDPOINT && windows::is_installed()? {
            windows::start()?;
            return Ok(true);
        }
    }
    #[cfg(not(windows))]
    let _ = endpoint;
    Ok(false)
}

#[cfg_attr(not(windows), allow(clippy::unused_async))]
async fn enable(client: &Client) -> Result<LifecycleResult, String> {
    require_default_service_endpoint(client.endpoint())?;
    #[cfg(not(windows))]
    return Err("enable is only available on Windows".into());

    #[cfg(windows)]
    {
        if windows::is_installed()? {
            windows::stop()?;
        }
        shutdown_if_running(client).await?;
        windows::enable(&daemon_program()?)?;
        wait_until_ready(client).await?;
        Ok(LifecycleResult {
            action: "enable",
            mode: "windows-service",
            installed: true,
            state: "running",
            message: "installed for automatic startup and started".into(),
        })
    }
}

#[cfg_attr(not(windows), allow(clippy::unused_async))]
async fn disable(client: &Client) -> Result<LifecycleResult, String> {
    require_default_service_endpoint(client.endpoint())?;
    #[cfg(not(windows))]
    return Err("disable is only available on Windows".into());

    #[cfg(windows)]
    {
        if windows::is_installed()? {
            windows::disable()?;
        }
        shutdown_if_running(client).await?;
        Ok(LifecycleResult {
            action: "disable",
            mode: "windows-service",
            installed: false,
            state: "stopped",
            message: "stopped and removed from automatic startup".into(),
        })
    }
}

async fn start(client: &Client) -> Result<LifecycleResult, String> {
    #[cfg(windows)]
    if client.endpoint() == DEFAULT_WINDOWS_ENDPOINT && windows::is_installed()? {
        windows::start()?;
        wait_until_ready(client).await?;
        return Ok(LifecycleResult {
            action: "start",
            mode: "windows-service",
            installed: true,
            state: "running",
            message: "Windows service is running".into(),
        });
    }

    if daemon_is_ready(client).await? {
        return Ok(LifecycleResult {
            action: "start",
            mode: "background-process",
            installed: false,
            state: "running",
            message: "daemon was already running".into(),
        });
    }
    spawn_daemon(client.endpoint())?;
    wait_until_ready(client).await?;
    Ok(LifecycleResult {
        action: "start",
        mode: "background-process",
        installed: false,
        state: "running",
        message: "started sibling netpland in the background".into(),
    })
}

async fn stop(client: &Client) -> Result<LifecycleResult, String> {
    #[cfg(windows)]
    let installed = client.endpoint() == DEFAULT_WINDOWS_ENDPOINT && windows::is_installed()?;
    #[cfg(not(windows))]
    let installed = false;

    #[cfg(windows)]
    if installed {
        windows::stop()?;
    }
    shutdown_if_running(client).await?;
    Ok(LifecycleResult {
        action: "stop",
        mode: if installed {
            "windows-service"
        } else {
            "background-process"
        },
        installed,
        state: "stopped",
        message: if installed {
            "Windows service is stopped; automatic startup remains enabled"
        } else {
            "background daemon is stopped"
        }
        .into(),
    })
}

async fn daemon_is_ready(client: &Client) -> Result<bool, String> {
    match client.call(&Request::Ping).await {
        Ok(Response::Pong { .. }) => Ok(true),
        Ok(Response::Error { code, message }) => Err(format!(
            "daemon rejected readiness probe ({code:?}): {message}"
        )),
        Ok(response) => Err(format!(
            "daemon returned an unexpected readiness response: {response:?}"
        )),
        Err(error) if is_endpoint_absent(&error) => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

async fn shutdown_if_running(client: &Client) -> Result<bool, String> {
    match client.call(&Request::Shutdown).await {
        Ok(Response::ShutdownAccepted) => {
            wait_until_stopped(client).await?;
            Ok(true)
        }
        Ok(Response::Error { code, message }) => {
            Err(format!("daemon rejected shutdown ({code:?}): {message}"))
        }
        Ok(response) => Err(format!(
            "daemon returned an unexpected shutdown response: {response:?}"
        )),
        Err(error) if is_endpoint_absent(&error) => Ok(false),
        Err(error) => Err(format!(
            "daemon shutdown failed: {error}; if this daemon predates lifecycle support, end the existing netpland process once and retry"
        )),
    }
}

async fn wait_until_ready(client: &Client) -> Result<(), String> {
    let mut last_error = None;
    for _ in 0..DAEMON_WAIT_ATTEMPTS {
        match client.call(&Request::Ping).await {
            Ok(Response::Pong { .. }) => return Ok(()),
            Ok(response) => last_error = Some(format!("unexpected response: {response:?}")),
            Err(error) => last_error = Some(error.to_string()),
        }
        tokio::time::sleep(DAEMON_WAIT_INTERVAL).await;
    }
    Err(last_error.map_or_else(
        || "daemon did not become ready".into(),
        |error| format!("daemon did not become ready: {error}"),
    ))
}

async fn wait_until_stopped(client: &Client) -> Result<(), String> {
    for _ in 0..DAEMON_WAIT_ATTEMPTS {
        match client.call(&Request::Ping).await {
            Err(error) if is_endpoint_absent(&error) => return Ok(()),
            _ => tokio::time::sleep(DAEMON_WAIT_INTERVAL).await,
        }
    }
    Err("daemon did not stop within 5 seconds".into())
}

fn require_default_service_endpoint(endpoint: &str) -> Result<(), String> {
    #[cfg(windows)]
    let service_endpoint = DEFAULT_WINDOWS_ENDPOINT;
    #[cfg(not(windows))]
    let service_endpoint = default_endpoint();

    if endpoint == service_endpoint {
        Ok(())
    } else {
        Err(format!(
            "Windows service installation uses the default endpoint {service_endpoint:?}; remove --endpoint for enable/disable"
        ))
    }
}

#[cfg(windows)]
fn daemon_program() -> Result<PathBuf, String> {
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    let sibling = current.with_file_name("netpland.exe");
    if !sibling.is_file() {
        return Err(format!(
            "cannot install the service because sibling daemon {} does not exist",
            sibling.display()
        ));
    }
    std::fs::canonicalize(&sibling)
        .map_err(|error| format!("failed to resolve {}: {error}", sibling.display()))
}

#[cfg(windows)]
mod windows {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant};

    use netplan::{DAEMON_SERVICE_DISPLAY_NAME, DAEMON_SERVICE_NAME};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
        ERROR_SERVICE_NOT_ACTIVE, WIN32_ERROR,
    };
    use windows::Win32::System::Services::{
        ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
        OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT,
        SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONTROL_STOP,
        SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
        SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED,
        SERVICE_WIN32_OWN_PROCESS, StartServiceW,
    };
    use windows::core::PCWSTR;

    const DELETE_ACCESS: u32 = 0x0001_0000;
    const SERVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

    struct ServiceHandle(SC_HANDLE);

    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            // SAFETY: This wrapper owns the live SCM handle and closes it exactly once.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }

    pub(super) fn is_installed() -> Result<bool, String> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        match open_service(&manager, SERVICE_QUERY_STATUS) {
            Ok(_) => Ok(true),
            Err(ServiceOpenError::Missing) => Ok(false),
            Err(ServiceOpenError::Other(error)) => Err(error),
        }
    }

    pub(super) fn enable(program: &Path) -> Result<(), String> {
        let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        let binary_path = service_binary_path(program);
        let name = wide(DAEMON_SERVICE_NAME);
        let display_name = wide(DAEMON_SERVICE_DISPLAY_NAME);
        let service = match open_service(&manager, SERVICE_ALL_ACCESS) {
            Ok(service) => {
                // SAFETY: All strings are NUL-terminated and the handle has change-config access.
                unsafe {
                    ChangeServiceConfigW(
                        service.0,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        PCWSTR(binary_path.as_ptr()),
                        PCWSTR::null(),
                        None,
                        PCWSTR::null(),
                        PCWSTR::null(),
                        PCWSTR::null(),
                        PCWSTR(display_name.as_ptr()),
                    )
                }
                .map_err(|error| windows_error("update PE Netplan service", &error))?;
                service
            }
            Err(ServiceOpenError::Missing) => {
                // SAFETY: All strings are NUL-terminated, optional pointers are null, and the
                // manager handle has create-service access.
                let handle = unsafe {
                    CreateServiceW(
                        manager.0,
                        PCWSTR(name.as_ptr()),
                        PCWSTR(display_name.as_ptr()),
                        SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        PCWSTR(binary_path.as_ptr()),
                        PCWSTR::null(),
                        None,
                        PCWSTR::null(),
                        PCWSTR::null(),
                        PCWSTR::null(),
                    )
                }
                .map_err(|error| windows_error("install PE Netplan service", &error))?;
                ServiceHandle(handle)
            }
            Err(ServiceOpenError::Other(error)) => return Err(error),
        };
        start_handle(&service)
    }

    pub(super) fn disable() -> Result<(), String> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = match open_service(
            &manager,
            SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE_ACCESS,
        ) {
            Ok(service) => service,
            Err(ServiceOpenError::Missing) => return Ok(()),
            Err(ServiceOpenError::Other(error)) => return Err(error),
        };
        stop_handle(&service)?;
        // SAFETY: The service handle has delete access and remains live for this call.
        unsafe { DeleteService(service.0) }
            .map_err(|error| windows_error("remove PE Netplan service", &error))
    }

    pub(super) fn start() -> Result<(), String> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_required_service(&manager, SERVICE_QUERY_STATUS | SERVICE_START)?;
        start_handle(&service)
    }

    pub(super) fn stop() -> Result<(), String> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_required_service(&manager, SERVICE_QUERY_STATUS | SERVICE_STOP)?;
        stop_handle(&service)
    }

    fn start_handle(service: &ServiceHandle) -> Result<(), String> {
        let mut state = query_state(service)?;
        if state == SERVICE_RUNNING {
            return Ok(());
        }
        if state == SERVICE_STOP_PENDING {
            wait_for_state(service, SERVICE_STOPPED)?;
            state = SERVICE_STOPPED;
        }
        if state == SERVICE_START_PENDING {
            return wait_for_state(service, SERVICE_RUNNING);
        }
        // SAFETY: The service handle has start access and no arguments are supplied.
        if let Err(error) = unsafe { StartServiceW(service.0, None) }
            && WIN32_ERROR::from_error(&error) != Some(ERROR_SERVICE_ALREADY_RUNNING)
        {
            return Err(windows_error("start PE Netplan service", &error));
        }
        wait_for_state(service, SERVICE_RUNNING)
    }

    fn stop_handle(service: &ServiceHandle) -> Result<(), String> {
        let state = query_state(service)?;
        if state == SERVICE_STOPPED {
            return Ok(());
        }
        if state == SERVICE_STOP_PENDING {
            return wait_for_state(service, SERVICE_STOPPED);
        }
        let mut status = SERVICE_STATUS::default();
        // SAFETY: The service handle has stop access and `status` is writable storage.
        if let Err(error) =
            unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &raw mut status) }
            && WIN32_ERROR::from_error(&error) != Some(ERROR_SERVICE_NOT_ACTIVE)
        {
            return Err(windows_error("stop PE Netplan service", &error));
        }
        wait_for_state(service, SERVICE_STOPPED)
    }

    fn wait_for_state(
        service: &ServiceHandle,
        desired: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
    ) -> Result<(), String> {
        let deadline = Instant::now() + SERVICE_WAIT_TIMEOUT;
        loop {
            let current = query_state(service)?;
            if current == desired {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "PE Netplan service did not reach state {} within {} seconds",
                    desired.0,
                    SERVICE_WAIT_TIMEOUT.as_secs()
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn query_state(
        service: &ServiceHandle,
    ) -> Result<windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE, String> {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: The service handle has query access and `status` is writable storage.
        unsafe { QueryServiceStatus(service.0, &raw mut status) }
            .map_err(|error| windows_error("query PE Netplan service", &error))?;
        Ok(status.dwCurrentState)
    }

    fn open_manager(access: u32) -> Result<ServiceHandle, String> {
        // SAFETY: Null names select the local machine and active service database.
        let handle = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
            .map_err(|error| windows_error("open Windows Service Control Manager", &error))?;
        Ok(ServiceHandle(handle))
    }

    enum ServiceOpenError {
        Missing,
        Other(String),
    }

    fn open_service(
        manager: &ServiceHandle,
        access: u32,
    ) -> Result<ServiceHandle, ServiceOpenError> {
        let name = wide(DAEMON_SERVICE_NAME);
        // SAFETY: The manager handle is live and the service name is NUL-terminated.
        match unsafe { OpenServiceW(manager.0, PCWSTR(name.as_ptr()), access) } {
            Ok(handle) => Ok(ServiceHandle(handle)),
            Err(error) if WIN32_ERROR::from_error(&error) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
                Err(ServiceOpenError::Missing)
            }
            Err(error) => Err(ServiceOpenError::Other(windows_error(
                "open PE Netplan service",
                &error,
            ))),
        }
    }

    fn open_required_service(
        manager: &ServiceHandle,
        access: u32,
    ) -> Result<ServiceHandle, String> {
        match open_service(manager, access) {
            Ok(service) => Ok(service),
            Err(ServiceOpenError::Missing) => {
                Err("PE Netplan service is not installed; run `netplan enable` first".into())
            }
            Err(ServiceOpenError::Other(error)) => Err(error),
        }
    }

    fn service_binary_path(program: &Path) -> Vec<u16> {
        let mut command = Vec::new();
        command.push(u16::from(b'"'));
        command.extend(program.as_os_str().encode_wide());
        command.push(u16::from(b'"'));
        command.extend(" --service".encode_utf16());
        command.push(0);
        command
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn windows_error(operation: &str, error: &windows::core::Error) -> String {
        if WIN32_ERROR::from_error(error) == Some(ERROR_ACCESS_DENIED) {
            format!(
                "{operation} failed: access denied after UAC elevation; verify the account's Administrator rights and local policy"
            )
        } else {
            format!("{operation} failed: {error}")
        }
    }

    #[cfg(test)]
    mod tests {
        use std::path::Path;

        use super::service_binary_path;

        #[test]
        fn service_command_quotes_the_daemon_path_and_selects_service_mode() {
            let command =
                service_binary_path(Path::new(r"C:\Program Files\PE Netplan\netpland.exe"));
            let command = String::from_utf16(&command[..command.len() - 1]).ok();
            assert_eq!(
                command.as_deref(),
                Some(r#""C:\Program Files\PE Netplan\netpland.exe" --service"#)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_actions_have_stable_names() {
        assert_eq!(LifecycleAction::Enable, LifecycleAction::Enable);
        assert_eq!(LifecycleAction::Disable, LifecycleAction::Disable);
        assert_eq!(LifecycleAction::Start, LifecycleAction::Start);
        assert_eq!(LifecycleAction::Stop, LifecycleAction::Stop);
    }

    #[test]
    fn service_installation_rejects_custom_endpoints() {
        let result = require_default_service_endpoint("custom-endpoint");
        assert!(matches!(result, Err(message) if message.contains("default endpoint")));
    }
}
