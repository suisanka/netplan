//! Windows elevation helpers shared by the CLI and daemon executables.

use std::ffi::{OsStr, OsString};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{
    SEE_MASK_FLAG_NO_UI, SEE_MASK_NO_CONSOLE, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
    SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{HRESULT, PCWSTR};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this type takes ownership of a valid Win32 handle exactly once.
        let _close_result = unsafe { CloseHandle(self.0) };
    }
}

/// Reports whether the current process token is elevated.
pub fn is_elevated() -> io::Result<bool> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid writable out parameter and the pseudo process
    // handle returned by `GetCurrentProcess` remains valid for this call.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
        .map_err(|error| windows_error(&error))?;
    let token = OwnedHandle(token);

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    let elevation_size = u32::try_from(size_of::<TOKEN_ELEVATION>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows token elevation structure is unexpectedly large",
        )
    })?;
    // SAFETY: `elevation` points to an initialized, correctly-sized output
    // buffer for the requested `TokenElevation` information class.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&raw mut elevation).cast()),
            elevation_size,
            &raw mut returned,
        )
    }
    .map_err(|error| windows_error(&error))?;
    if returned < elevation_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an incomplete token elevation record",
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}

/// Starts an executable through the UAC `runas` verb.
///
/// When `wait` is true, the child inherits the current console and its process
/// exit code is returned. Otherwise this returns after the elevated process is
/// created and closes the local process handle without terminating the child.
pub fn run_as_administrator(
    executable: &Path,
    arguments: &[OsString],
    wait: bool,
) -> io::Result<Option<u32>> {
    let verb = wide_null(OsStr::new("runas"))?;
    let executable = wide_null(executable.as_os_str())?;
    let parameters = command_line(arguments)?;
    let directory = std::env::current_dir().and_then(|path| wide_null(path.as_os_str()))?;

    let structure_size = u32::try_from(size_of::<SHELLEXECUTEINFOW>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows shell execute structure is unexpectedly large",
        )
    })?;
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: structure_size,
        fMask: SEE_MASK_NOCLOSEPROCESS
            | SEE_MASK_NOASYNC
            | SEE_MASK_NO_CONSOLE
            | SEE_MASK_FLAG_NO_UI,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        lpDirectory: PCWSTR(directory.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };

    // SAFETY: all pointers in `execute` refer to live, NUL-terminated buffers
    // for the duration of the call, and `cbSize` matches the structure.
    if let Err(error) = unsafe { ShellExecuteExW(&raw mut execute) } {
        if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "administrator permission was not granted; UAC elevation was cancelled",
            ));
        }
        return Err(windows_error(&error));
    }
    if execute.hProcess.is_invalid() {
        return Err(io::Error::other(
            "Windows accepted the elevation request but returned no process handle",
        ));
    }
    let process = OwnedHandle(execute.hProcess);
    if !wait {
        return Ok(None);
    }

    // SAFETY: `process` owns a live process handle returned by ShellExecuteExW.
    let wait_result = unsafe { WaitForSingleObject(process.0, INFINITE) };
    if wait_result == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }
    if wait_result != WAIT_OBJECT_0 {
        return Err(io::Error::other(format!(
            "unexpected Windows wait result: {}",
            wait_result.0
        )));
    }
    let mut exit_code = 1_u32;
    // SAFETY: the process is signalled and `exit_code` is a valid out parameter.
    unsafe { GetExitCodeProcess(process.0, &raw mut exit_code) }
        .map_err(|error| windows_error(&error))?;
    Ok(Some(exit_code))
}

fn windows_error(error: &windows::core::Error) -> io::Error {
    io::Error::other(error.to_string())
}

fn wide_null(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows paths and arguments cannot contain NUL characters",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn command_line(arguments: &[OsString]) -> io::Result<Vec<u16>> {
    let mut result = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            result.push(u16::from(b' '));
        }
        append_quoted_argument(&mut result, argument)?;
    }
    result.push(0);
    Ok(result)
}

fn append_quoted_argument(output: &mut Vec<u16>, argument: &OsStr) -> io::Result<()> {
    let value: Vec<u16> = argument.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows paths and arguments cannot contain NUL characters",
        ));
    }
    let quote = u16::from(b'"');
    let slash = u16::from(b'\\');
    if !value.is_empty()
        && !value
            .iter()
            .any(|character| matches!(*character, 9 | 32) || *character == quote)
    {
        output.extend(value);
        return Ok(());
    }

    output.push(quote);
    let mut slashes = 0_usize;
    for character in value {
        if character == slash {
            slashes += 1;
            continue;
        }
        if character == quote {
            output.extend(std::iter::repeat_n(slash, slashes * 2 + 1));
            output.push(quote);
        } else {
            output.extend(std::iter::repeat_n(slash, slashes));
            output.push(character);
        }
        slashes = 0;
    }
    output.extend(std::iter::repeat_n(slash, slashes * 2));
    output.push(quote);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(arguments: &[&str]) -> io::Result<String> {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        let encoded = command_line(&arguments)?;
        Ok(String::from_utf16_lossy(&encoded[..encoded.len() - 1]))
    }

    #[test]
    fn quotes_windows_arguments_without_losing_spaces_or_quotes() -> io::Result<()> {
        assert_eq!(
            rendered(&["--endpoint", r"\\.\pipe\pe netplan"])?,
            r#"--endpoint "\\.\pipe\pe netplan""#
        );
        assert_eq!(rendered(&["", r#"a\"b"#])?, r#""" "a\\\"b""#);
        assert_eq!(rendered(&[r"trailing\"])?, r"trailing\");
        Ok(())
    }
}
