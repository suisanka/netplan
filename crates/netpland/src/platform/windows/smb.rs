//! Native SMB account, share, and mapping operations.

use std::fmt::Write as _;
use std::ptr;

use netplan::NetplanConfig;
use netplan::config::{SecretRef, SmbAccount, SmbAccountKind, SmbMapping, SmbShare};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, GENERIC_ALL, GENERIC_READ, HLOCAL, LocalFree,
};
use windows::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NERR_UserNotFound, NetApiBufferFree, NetUserAdd, NetUserDel, NetUserGetInfo,
    UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
};
use windows::Win32::NetworkManagement::WNet::{
    NET_CONNECT_FLAGS, NETRESOURCEW, RESOURCETYPE_DISK, WNetAddConnection2W,
    WNetCancelConnection2W, WNetGetConnectionW,
};
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows::Win32::Security::{
    ACL, CreateWellKnownSid, GetSecurityDescriptorLength, InitializeSecurityDescriptor,
    LookupAccountNameW, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR,
    SID_NAME_USE, SetSecurityDescriptorDacl, WinBuiltinAdministratorsSid, WinWorldSid,
};
use windows::Win32::Storage::FileSystem::{
    NetShareAdd, NetShareDel, NetShareGetInfo, NetShareSetInfo, SHARE_INFO_502, SHARE_INFO_1501,
    SHARE_INFO_PERMISSIONS, SHARE_TYPE, STYPE_DISKTREE,
};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::core::{PCWSTR, PWSTR};

use super::super::{PlatformError, PlatformErrorKind, PlatformResult};

const NERR_DUPLICATE_SHARE: u32 = 2118;
const NERR_NET_NAME_NOT_FOUND: u32 = 2310;
const ERROR_ALREADY_ASSIGNED: u32 = 85;
const ERROR_INVALID_PASSWORD: u32 = 86;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_BAD_USERNAME: u32 = 2202;
const ERROR_NOT_CONNECTED: u32 = 2250;
const ERROR_LOGON_FAILURE: u32 = 1326;
const ERROR_SESSION_CREDENTIAL_CONFLICT: u32 = 1219;
const MAX_SID_BYTES: usize = 68;

pub(super) fn probe_accounts() -> Result<(), String> {
    probe_library("netapi32.dll")
}

pub(super) fn probe_shares() -> Result<(), String> {
    probe_library("netapi32.dll")?;
    super::apply::service_available("LanmanServer")
        .map_err(|error| format!("LanmanServer service is unavailable: {}", error.message))
}

pub(super) fn probe_mappings() -> Result<(), String> {
    probe_library("mpr.dll")?;
    super::apply::service_available("LanmanWorkstation").map_err(|error| {
        format!(
            "LanmanWorkstation service is unavailable: {}",
            error.message
        )
    })
}

fn probe_library(name: &str) -> Result<(), String> {
    let name_wide = wide(name);
    // SAFETY: The supplied DLL name is NUL-terminated. The temporary reference is immediately
    // released when it leaves this scope.
    let module = unsafe { LoadLibraryW(PCWSTR(name_wide.as_ptr())) }
        .map_err(|error| format!("{name} is unavailable: {error}"))?;
    // SAFETY: `module` is the valid reference returned above.
    let _ = unsafe { windows::Win32::Foundation::FreeLibrary(module) };
    Ok(())
}

pub(super) enum Rollback {
    Account {
        username: String,
    },
    Share {
        name: String,
        previous: Option<ShareSnapshot>,
    },
    Mapping {
        target: String,
    },
}

impl Rollback {
    pub(super) fn execute(self) -> PlatformResult<()> {
        match self {
            Self::Account { username } => delete_account(&username),
            Self::Share { name, previous } => match previous {
                Some(snapshot) => set_share_snapshot(&name, &snapshot),
                None => delete_share(&name),
            },
            Self::Mapping { target } => cancel_mapping(&target),
        }
    }
}

pub(super) fn apply_account(account: &SmbAccount) -> PlatformResult<Option<Rollback>> {
    if account.kind != SmbAccountKind::Local {
        return Ok(None);
    }
    if account_exists(&account.username)? {
        // Passwords cannot be read back for a lossless rollback, so existing accounts are left
        // unchanged. The declaration remains usable for share ACL resolution.
        return Ok(None);
    }
    let password = account
        .password
        .as_ref()
        .map(resolve_secret)
        .transpose()?
        .unwrap_or_default();
    let username_wide = wide(&account.username);
    let mut password_wide = wide(&password);
    let mut info = USER_INFO_1 {
        usri1_name: PWSTR(username_wide.as_ptr().cast_mut()),
        usri1_password: PWSTR(password_wide.as_mut_ptr()),
        usri1_priv: USER_PRIV_USER,
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
        ..Default::default()
    };
    let mut parameter_error = 0_u32;
    // SAFETY: `info` and all referenced strings remain alive for the synchronous call.
    let code = unsafe {
        NetUserAdd(
            PCWSTR::null(),
            1,
            (&raw mut info).cast::<u8>(),
            Some(&raw mut parameter_error),
        )
    };
    password_wide.fill(0);
    net_api_result("NetUserAdd", code, Some(parameter_error))?;
    Ok(Some(Rollback::Account {
        username: account.username.clone(),
    }))
}

pub(super) fn apply_share(config: &NetplanConfig, share: &SmbShare) -> PlatformResult<Rollback> {
    let previous = capture_share(&share.name)?;
    let security = ShareSecurity::new(config, share)?;
    let name = wide(&share.name);
    let path = wide(&share.path);
    let remark = share.description.as_deref().map(wide);
    let mut info = SHARE_INFO_502 {
        shi502_netname: PWSTR(name.as_ptr().cast_mut()),
        shi502_type: STYPE_DISKTREE,
        shi502_remark: remark
            .as_ref()
            .map_or(PWSTR::null(), |value| PWSTR(value.as_ptr().cast_mut())),
        shi502_permissions: SHARE_INFO_PERMISSIONS(0),
        shi502_max_uses: u32::MAX,
        shi502_current_uses: 0,
        shi502_path: PWSTR(path.as_ptr().cast_mut()),
        shi502_passwd: PWSTR::null(),
        shi502_reserved: 0,
        shi502_security_descriptor: security.descriptor(),
    };
    let mut parameter_error = 0_u32;
    // SAFETY: The share structure, strings, ACL, and security descriptor all remain alive for the
    // synchronous NetAPI call.
    let code = unsafe {
        if previous.is_some() {
            NetShareSetInfo(
                PCWSTR::null(),
                PCWSTR(name.as_ptr()),
                502,
                (&raw mut info).cast::<u8>(),
                Some(&raw mut parameter_error),
            )
        } else {
            NetShareAdd(
                PCWSTR::null(),
                502,
                (&raw mut info).cast::<u8>(),
                Some(&raw mut parameter_error),
            )
        }
    };
    net_api_result("NetShareAdd/NetShareSetInfo", code, Some(parameter_error))?;
    if previous.is_some()
        && let Err(error) = set_share_security(&share.name, security.descriptor())
    {
        let restore = previous
            .as_ref()
            .and_then(|snapshot| set_share_snapshot(&share.name, snapshot).err());
        let rolled_back = restore.is_none();
        let message = restore.as_ref().map_or_else(
            || error.message.clone(),
            |restore| {
                format!(
                    "{}; immediate share rollback failed: {}",
                    error.message, restore.message
                )
            },
        );
        return Err(PlatformError {
            kind: error.kind,
            message,
            rolled_back,
        });
    }
    Ok(Rollback::Share {
        name: share.name.clone(),
        previous,
    })
}

pub(super) fn apply_mapping(
    config: &NetplanConfig,
    mapping: &SmbMapping,
) -> PlatformResult<Option<Rollback>> {
    if let Some(local) = &mapping.local
        && let Some(existing) = current_mapping(local)?
    {
        if existing.eq_ignore_ascii_case(&mapping.remote) {
            return Ok(None);
        }
        return Err(PlatformError::invalid_config(format!(
            "SMB local device {local:?} is already mapped to {existing:?}"
        )));
    }

    let (username, password) = mapping_credentials(config, mapping)?;
    let local = mapping.local.as_deref().map(wide);
    let remote = wide(&mapping.remote);
    let username = username.as_deref().map(wide);
    let mut password = password.as_deref().map(wide);
    let resource = NETRESOURCEW {
        dwType: RESOURCETYPE_DISK,
        lpLocalName: local
            .as_ref()
            .map_or(PWSTR::null(), |value| PWSTR(value.as_ptr().cast_mut())),
        lpRemoteName: PWSTR(remote.as_ptr().cast_mut()),
        ..Default::default()
    };
    // SAFETY: The resource and optional credential strings remain alive for the synchronous call.
    let code = unsafe {
        WNetAddConnection2W(
            &raw const resource,
            password
                .as_ref()
                .map_or(PCWSTR::null(), |value| PCWSTR(value.as_ptr())),
            username
                .as_ref()
                .map_or(PCWSTR::null(), |value| PCWSTR(value.as_ptr())),
            NET_CONNECT_FLAGS(0),
        )
    };
    if let Some(password) = &mut password {
        password.fill(0);
    }
    wnet_result("WNetAddConnection2W", code.0)?;
    Ok(Some(Rollback::Mapping {
        target: mapping
            .local
            .clone()
            .unwrap_or_else(|| mapping.remote.clone()),
    }))
}

fn account_exists(username: &str) -> PlatformResult<bool> {
    let username = wide(username);
    let mut buffer = ptr::null_mut::<u8>();
    // SAFETY: The username is NUL-terminated and `buffer` is writable output storage.
    let code = unsafe {
        NetUserGetInfo(
            PCWSTR::null(),
            PCWSTR(username.as_ptr()),
            0,
            &raw mut buffer,
        )
    };
    if code == NERR_UserNotFound {
        return Ok(false);
    }
    net_api_result("NetUserGetInfo", code, None)?;
    // SAFETY: On success NetUserGetInfo returned a NetAPI allocation, released once here.
    let free_code = unsafe { NetApiBufferFree(Some(buffer.cast())) };
    net_api_result("NetApiBufferFree", free_code, None)?;
    Ok(true)
}

fn delete_account(username: &str) -> PlatformResult<()> {
    let username = wide(username);
    // SAFETY: The local-server marker and username are valid NUL-terminated strings.
    let code = unsafe { NetUserDel(PCWSTR::null(), PCWSTR(username.as_ptr())) };
    if code == NERR_UserNotFound {
        Ok(())
    } else {
        net_api_result("NetUserDel", code, None)
    }
}

#[derive(Clone)]
pub(super) struct ShareSnapshot {
    share_type: SHARE_TYPE,
    remark: Option<String>,
    permissions: SHARE_INFO_PERMISSIONS,
    max_uses: u32,
    path: String,
    password: Option<String>,
    security_descriptor: Vec<u8>,
}

fn capture_share(name: &str) -> PlatformResult<Option<ShareSnapshot>> {
    let name_wide = wide(name);
    let mut buffer = ptr::null_mut::<u8>();
    // SAFETY: The share name is NUL-terminated and `buffer` is writable output storage.
    let code = unsafe {
        NetShareGetInfo(
            PCWSTR::null(),
            PCWSTR(name_wide.as_ptr()),
            502,
            &raw mut buffer,
        )
    };
    if code == NERR_NET_NAME_NOT_FOUND {
        return Ok(None);
    }
    net_api_result("NetShareGetInfo", code, None)?;
    // SAFETY: A successful level-502 query returns a complete SHARE_INFO_502 record.
    let info = unsafe { &*buffer.cast::<SHARE_INFO_502>() };
    let captured = (|| {
        let length = if info.shi502_security_descriptor.is_invalid() {
            0
        } else {
            // SAFETY: The NetAPI record owns a valid security descriptor until it is freed below.
            unsafe { GetSecurityDescriptorLength(info.shi502_security_descriptor) }
        };
        let security_descriptor = if length == 0 {
            Vec::new()
        } else {
            // SAFETY: GetSecurityDescriptorLength returned the readable byte length.
            unsafe {
                std::slice::from_raw_parts(
                    info.shi502_security_descriptor.0.cast::<u8>(),
                    length as usize,
                )
            }
            .to_vec()
        };
        Ok(ShareSnapshot {
            share_type: info.shi502_type,
            remark: optional_pwstr(info.shi502_remark)?,
            permissions: info.shi502_permissions,
            max_uses: info.shi502_max_uses,
            path: required_pwstr(info.shi502_path, "share path")?,
            password: optional_pwstr(info.shi502_passwd)?,
            security_descriptor,
        })
    })();
    // SAFETY: `buffer` is the NetAPI allocation returned above and is released exactly once.
    let free_code = unsafe { NetApiBufferFree(Some(buffer.cast())) };
    net_api_result("NetApiBufferFree", free_code, None)?;
    captured.map(Some)
}

fn set_share_snapshot(name: &str, snapshot: &ShareSnapshot) -> PlatformResult<()> {
    let name_wide = wide(name);
    let path = wide(&snapshot.path);
    let remark = snapshot.remark.as_deref().map(wide);
    let password = snapshot.password.as_deref().map(wide);
    let mut info = SHARE_INFO_502 {
        shi502_netname: PWSTR(name_wide.as_ptr().cast_mut()),
        shi502_type: snapshot.share_type,
        shi502_remark: remark
            .as_ref()
            .map_or(PWSTR::null(), |value| PWSTR(value.as_ptr().cast_mut())),
        shi502_permissions: snapshot.permissions,
        shi502_max_uses: snapshot.max_uses,
        shi502_current_uses: 0,
        shi502_path: PWSTR(path.as_ptr().cast_mut()),
        shi502_passwd: password
            .as_ref()
            .map_or(PWSTR::null(), |value| PWSTR(value.as_ptr().cast_mut())),
        shi502_reserved: 0,
        shi502_security_descriptor: if snapshot.security_descriptor.is_empty() {
            PSECURITY_DESCRIPTOR::default()
        } else {
            PSECURITY_DESCRIPTOR(snapshot.security_descriptor.as_ptr().cast_mut().cast())
        },
    };
    let mut parameter_error = 0_u32;
    // SAFETY: All snapshot buffers remain live for the synchronous restore call.
    let code = unsafe {
        NetShareSetInfo(
            PCWSTR::null(),
            PCWSTR(name_wide.as_ptr()),
            502,
            (&raw mut info).cast::<u8>(),
            Some(&raw mut parameter_error),
        )
    };
    net_api_result("NetShareSetInfo rollback", code, Some(parameter_error))?;
    if snapshot.security_descriptor.is_empty() {
        Ok(())
    } else {
        set_share_security(
            name,
            PSECURITY_DESCRIPTOR(snapshot.security_descriptor.as_ptr().cast_mut().cast()),
        )
    }
}

fn set_share_security(name: &str, descriptor: PSECURITY_DESCRIPTOR) -> PlatformResult<()> {
    let name = wide(name);
    let mut info = SHARE_INFO_1501 {
        shi1501_reserved: 0,
        shi1501_security_descriptor: descriptor,
    };
    let mut parameter_error = 0_u32;
    // SAFETY: The share name and security descriptor remain live for the synchronous call.
    let code = unsafe {
        NetShareSetInfo(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            1501,
            (&raw mut info).cast::<u8>(),
            Some(&raw mut parameter_error),
        )
    };
    net_api_result("NetShareSetInfo(security)", code, Some(parameter_error))
}

fn delete_share(name: &str) -> PlatformResult<()> {
    let name = wide(name);
    // SAFETY: The local-server marker and share name are valid NUL-terminated strings.
    let code = unsafe { NetShareDel(PCWSTR::null(), PCWSTR(name.as_ptr()), Some(0)) };
    if code == NERR_NET_NAME_NOT_FOUND {
        Ok(())
    } else {
        net_api_result("NetShareDel", code, None)
    }
}

struct ShareSecurity {
    _sids: Vec<Vec<u8>>,
    acl: *mut ACL,
    descriptor: SECURITY_DESCRIPTOR,
}

impl ShareSecurity {
    fn new(config: &NetplanConfig, share: &SmbShare) -> PlatformResult<Self> {
        let mut sids = Vec::new();
        let mut permissions = Vec::new();
        if share.accounts.is_empty() {
            sids.push(well_known_sid(WinWorldSid)?);
            permissions.push(if share.read_only {
                GENERIC_READ.0
            } else {
                GENERIC_ALL.0
            });
        } else {
            for reference in &share.accounts {
                let account = config
                    .smb
                    .accounts
                    .iter()
                    .find(|account| account.id.eq_ignore_ascii_case(reference))
                    .ok_or_else(|| {
                        PlatformError::invalid_config(format!(
                            "unknown SMB account reference {reference:?}"
                        ))
                    })?;
                sids.push(lookup_sid(&account.username)?);
                permissions.push(if share.read_only {
                    GENERIC_READ.0
                } else {
                    GENERIC_ALL.0
                });
            }
        }
        sids.push(well_known_sid(WinBuiltinAdministratorsSid)?);
        permissions.push(GENERIC_ALL.0);
        let entries: Vec<_> = sids
            .iter_mut()
            .zip(permissions)
            .map(|(sid, permission)| EXPLICIT_ACCESS_W {
                grfAccessPermissions: permission,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_UNKNOWN,
                    ptstrName: PWSTR(sid.as_mut_ptr().cast()),
                    ..Default::default()
                },
            })
            .collect();
        let mut acl = ptr::null_mut::<ACL>();
        // SAFETY: Every SID referenced by the entries is a valid live allocation in `sids`.
        let code = unsafe { SetEntriesInAclW(Some(&entries), None, &raw mut acl) };
        if code.0 != 0 {
            return Err(win32_error("SetEntriesInAclW", code.0));
        }
        let mut security = Self {
            _sids: sids,
            acl,
            descriptor: SECURITY_DESCRIPTOR::default(),
        };
        // SAFETY: The descriptor is writable and `acl` is the valid allocation returned above.
        unsafe {
            InitializeSecurityDescriptor(
                PSECURITY_DESCRIPTOR((&raw mut security.descriptor).cast()),
                1,
            )
            .map_err(|error| {
                PlatformError::internal(format!("InitializeSecurityDescriptor failed: {error}"))
            })?;
            SetSecurityDescriptorDacl(
                PSECURITY_DESCRIPTOR((&raw mut security.descriptor).cast()),
                true,
                Some(security.acl),
                false,
            )
            .map_err(|error| {
                PlatformError::internal(format!("SetSecurityDescriptorDacl failed: {error}"))
            })?;
        }
        Ok(security)
    }

    fn descriptor(&self) -> PSECURITY_DESCRIPTOR {
        PSECURITY_DESCRIPTOR((&raw const self.descriptor).cast_mut().cast())
    }
}

impl Drop for ShareSecurity {
    fn drop(&mut self) {
        if !self.acl.is_null() {
            // SAFETY: SetEntriesInAclW returned this LocalAlloc allocation; it is freed once.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.acl.cast()))) };
        }
    }
}

fn lookup_sid(account: &str) -> PlatformResult<Vec<u8>> {
    let account = wide(account);
    let mut sid_bytes = 0_u32;
    let mut domain_chars = 0_u32;
    let mut use_kind = SID_NAME_USE::default();
    // SAFETY: This is the documented size probe with null output buffers and valid size pointers.
    let probe = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            None,
            &raw mut sid_bytes,
            None,
            &raw mut domain_chars,
            &raw mut use_kind,
        )
    };
    if probe.is_ok() || sid_bytes == 0 {
        return Err(PlatformError::not_found(
            "LookupAccountNameW did not identify the requested SMB account",
        ));
    }
    let mut sid = vec![0_u8; sid_bytes as usize];
    let mut domain = vec![0_u16; domain_chars as usize];
    // SAFETY: Both buffers have the exact capacities returned by the size probe.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &raw mut sid_bytes,
            Some(PWSTR(domain.as_mut_ptr())),
            &raw mut domain_chars,
            &raw mut use_kind,
        )
    }
    .map_err(|error| PlatformError::not_found(format!("LookupAccountNameW failed: {error}")))?;
    Ok(sid)
}

fn well_known_sid(kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE) -> PlatformResult<Vec<u8>> {
    let mut sid = vec![0_u8; MAX_SID_BYTES];
    let mut bytes = u32::try_from(sid.len())
        .map_err(|_| PlatformError::internal("fixed SID buffer exceeds DWORD capacity"))?;
    // SAFETY: The buffer is writable for the reported maximum SID size.
    unsafe {
        CreateWellKnownSid(
            kind,
            None,
            Some(PSID(sid.as_mut_ptr().cast())),
            &raw mut bytes,
        )
    }
    .map_err(|error| PlatformError::internal(format!("CreateWellKnownSid failed: {error}")))?;
    sid.truncate(bytes as usize);
    Ok(sid)
}

fn current_mapping(local: &str) -> PlatformResult<Option<String>> {
    let local = wide(local);
    let mut buffer = vec![0_u16; 256];
    loop {
        let mut chars = u32::try_from(buffer.len()).map_err(|_| {
            PlatformError::internal("SMB mapping path exceeds the Windows DWORD size limit")
        })?;
        // SAFETY: The local name is NUL-terminated and buffer contains `chars` writable units.
        let code = unsafe {
            WNetGetConnectionW(
                PCWSTR(local.as_ptr()),
                Some(PWSTR(buffer.as_mut_ptr())),
                &raw mut chars,
            )
        };
        if code.0 == ERROR_NOT_CONNECTED {
            return Ok(None);
        }
        if code.0 == ERROR_MORE_DATA {
            buffer.resize(chars as usize, 0);
            continue;
        }
        wnet_result("WNetGetConnectionW", code.0)?;
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(chars as usize);
        return String::from_utf16(&buffer[..end])
            .map(Some)
            .map_err(|error| {
                PlatformError::internal(format!("invalid SMB mapping UTF-16: {error}"))
            });
    }
}

fn cancel_mapping(target: &str) -> PlatformResult<()> {
    let target = wide(target);
    // SAFETY: The target is a valid NUL-terminated local or remote mapping name.
    let code =
        unsafe { WNetCancelConnection2W(PCWSTR(target.as_ptr()), NET_CONNECT_FLAGS(0), false) };
    if code.0 == ERROR_NOT_CONNECTED {
        Ok(())
    } else {
        wnet_result("WNetCancelConnection2W", code.0)
    }
}

fn mapping_credentials(
    config: &NetplanConfig,
    mapping: &SmbMapping,
) -> PlatformResult<(Option<String>, Option<String>)> {
    if let Some(reference) = &mapping.account {
        let account = config
            .smb
            .accounts
            .iter()
            .find(|account| account.id.eq_ignore_ascii_case(reference))
            .ok_or_else(|| {
                PlatformError::invalid_config(format!(
                    "unknown SMB account reference {reference:?}"
                ))
            })?;
        Ok((
            Some(account.username.clone()),
            account.password.as_ref().map(resolve_secret).transpose()?,
        ))
    } else {
        Ok((
            mapping.username.clone(),
            mapping.password.as_ref().map(resolve_secret).transpose()?,
        ))
    }
}

fn resolve_secret(secret: &SecretRef) -> PlatformResult<String> {
    match secret {
        SecretRef::Literal(value) => Ok(value.clone()),
        SecretRef::Env(name) => std::env::var(name).map_err(|_| {
            PlatformError::not_found(format!(
                "required secret environment variable {name:?} is not set or is not Unicode"
            ))
        }),
    }
}

fn optional_pwstr(value: PWSTR) -> PlatformResult<Option<String>> {
    if value.is_null() {
        Ok(None)
    } else {
        required_pwstr(value, "optional NetAPI string").map(Some)
    }
}

fn required_pwstr(value: PWSTR, field: &str) -> PlatformResult<String> {
    if value.is_null() {
        return Err(PlatformError::internal(format!(
            "NetAPI returned a null {field}"
        )));
    }
    // SAFETY: NetAPI level-502 string members are NUL-terminated for the lifetime of the buffer.
    unsafe { value.to_string() }.map_err(|error| {
        PlatformError::internal(format!(
            "NetAPI returned invalid UTF-16 for {field}: {error}"
        ))
    })
}

fn net_api_result(operation: &str, code: u32, parameter: Option<u32>) -> PlatformResult<()> {
    if code == NERR_Success {
        return Ok(());
    }
    let mut message = format!("{operation} failed with Windows error {code}");
    if let Some(parameter) = parameter.filter(|value| *value != 0) {
        let _ = write!(message, " at parameter {parameter}");
    }
    Err(PlatformError {
        kind: match code {
            value if value == ERROR_ACCESS_DENIED.0 => PlatformErrorKind::PermissionDenied,
            value if value == NERR_UserNotFound || value == NERR_NET_NAME_NOT_FOUND => {
                PlatformErrorKind::NotFound
            }
            NERR_DUPLICATE_SHARE | ERROR_INVALID_PARAMETER | ERROR_BAD_USERNAME => {
                PlatformErrorKind::InvalidConfig
            }
            _ => PlatformErrorKind::Internal,
        },
        message,
        rolled_back: false,
    })
}

fn wnet_result(operation: &str, code: u32) -> PlatformResult<()> {
    if code == 0 {
        return Ok(());
    }
    Err(PlatformError {
        kind: match code {
            value
                if value == ERROR_ACCESS_DENIED.0
                    || value == ERROR_LOGON_FAILURE
                    || value == ERROR_INVALID_PASSWORD =>
            {
                PlatformErrorKind::PermissionDenied
            }
            ERROR_NOT_CONNECTED => PlatformErrorKind::NotFound,
            ERROR_ALREADY_ASSIGNED
            | ERROR_INVALID_PARAMETER
            | ERROR_BAD_USERNAME
            | ERROR_SESSION_CREDENTIAL_CONFLICT => PlatformErrorKind::InvalidConfig,
            _ => PlatformErrorKind::Internal,
        },
        message: format!("{operation} failed with Windows error {code}"),
        rolled_back: false,
    })
}

fn win32_error(operation: &str, code: u32) -> PlatformError {
    PlatformError {
        kind: if code == ERROR_ACCESS_DENIED.0 {
            PlatformErrorKind::PermissionDenied
        } else {
            PlatformErrorKind::Internal
        },
        message: format!("{operation} failed with Windows error {code}"),
        rolled_back: false,
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
