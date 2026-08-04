//! Strict YAML and JSON configuration parsing.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Configuration document encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigFormat {
    /// Infer JSON from the first non-whitespace byte, otherwise parse YAML.
    Auto,
    /// YAML document.
    Yaml,
    /// JSON document.
    Json,
}

/// Top-level PE Netplan configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetplanConfig {
    /// Schema version. The current version is `1`.
    pub version: u32,
    /// Interfaces that the daemon must refuse to mutate.
    #[serde(default)]
    pub protect: ProtectionConfig,
    /// Optional machine identity changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityConfig>,
    /// Desired network adapter states.
    #[serde(default)]
    pub adapters: Vec<AdapterConfig>,
    /// Desired wireless profiles.
    #[serde(default)]
    pub wifi: Vec<WifiProfile>,
    /// Explicit wireless discovery and connection operations.
    #[serde(default)]
    pub wifi_actions: Vec<WifiAction>,
    /// SMB server and client configuration.
    #[serde(default)]
    pub smb: SmbConfig,
    /// Desired Windows firewall state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<FirewallConfig>,
    /// Desired Windows service states.
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    /// Explicit driver installation and adapter restart operations.
    #[serde(default)]
    pub drivers: Vec<DriverOperation>,
    /// Explicit executable hooks. Shell command strings are not accepted.
    #[serde(default)]
    pub hooks: Vec<HookConfig>,
}

/// Selectors protected from live apply.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionConfig {
    /// Management adapters that must remain unchanged.
    #[serde(default)]
    pub management_interfaces: Vec<InterfaceSelector>,
}

/// Machine identity settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// `NetBIOS` computer name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer_name: Option<String>,
    /// Workgroup name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workgroup: Option<String>,
    /// Primary DNS suffix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_suffix: Option<String>,
}

/// Desired state for one adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    /// Stable adapter matcher.
    pub selector: InterfaceSelector,
    /// Enable or disable the adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Optional locally administered MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    /// IPv4 configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Config>,
}

/// Stable fields used to select an adapter.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceSelector {
    /// Windows interface index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_index: Option<u32>,
    /// Exact friendly connection name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Exact Windows adapter GUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
    /// Exact canonical MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    /// Case-insensitive substring of the adapter description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description_contains: Option<String>,
}

/// Desired IPv4 mode.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Ipv4Config {
    /// Obtain addresses and optionally DNS from DHCP.
    Dhcp {
        /// Whether DNS servers should also come from DHCP.
        #[serde(default = "default_true")]
        dns_from_dhcp: bool,
    },
    /// Use explicit addresses, gateways, and name servers.
    Static {
        /// One or more IPv4 CIDR addresses.
        addresses: Vec<Ipv4Net>,
        /// Default gateways in preference order.
        #[serde(default)]
        gateways: Vec<Ipv4Addr>,
        /// DNS servers in preference order.
        #[serde(default)]
        dns: Vec<IpAddr>,
        /// WINS servers in preference order.
        #[serde(default)]
        wins: Vec<Ipv4Addr>,
    },
}

/// Wireless authentication mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiAuthentication {
    /// Open network.
    Open,
    /// WPA2 personal network.
    Wpa2Personal,
    /// WPA3 personal network.
    Wpa3Personal,
}

/// Desired wireless profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WifiProfile {
    /// Adapter matcher. It may be omitted only when exactly one WLAN interface is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<InterfaceSelector>,
    /// Stable profile name. Defaults to the SSID when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// SSID as displayed by Windows WLAN APIs.
    pub ssid: String,
    /// Authentication mode.
    pub authentication: WifiAuthentication,
    /// Pre-shared key reference for secured networks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<SecretRef>,
    /// Connect automatically when the network is visible.
    #[serde(default)]
    pub auto_connect: bool,
    /// Treat this as a hidden SSID.
    #[serde(default)]
    pub hidden: bool,
}

/// An explicit wireless operation performed after profile installation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum WifiAction {
    /// Request a native scan on one selected WLAN interface.
    Scan {
        /// Optional WLAN adapter matcher; required when multiple WLAN interfaces exist.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<InterfaceSelector>,
    },
    /// Connect using a profile declared in this document.
    Connect {
        /// Optional WLAN adapter matcher; required when multiple WLAN interfaces exist.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<InterfaceSelector>,
        /// Profile name, or the SSID when the profile has no explicit name.
        profile: String,
    },
    /// Disconnect one or all WLAN interfaces.
    Disconnect {
        /// Optional WLAN adapter matcher; required when multiple WLAN interfaces exist.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<InterfaceSelector>,
    },
}

/// SMB desired state.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbConfig {
    /// Named local or remote credentials referenced by shares and mappings.
    #[serde(default)]
    pub accounts: Vec<SmbAccount>,
    /// Local shares to create.
    #[serde(default)]
    pub shares: Vec<SmbShare>,
    /// Remote shares to map.
    #[serde(default)]
    pub mappings: Vec<SmbMapping>,
}

/// Named SMB credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbAccount {
    /// Stable identifier used by share and mapping references.
    pub id: String,
    /// Whether this declaration creates a local user or only supplies remote credentials.
    #[serde(default)]
    pub kind: SmbAccountKind,
    /// Windows user name, optionally domain-qualified.
    pub username: String,
    /// Optional password used when creating or authenticating the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretRef>,
}

/// SMB account behavior.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmbAccountKind {
    /// Credentials used only for a remote SMB mapping.
    #[default]
    Credential,
    /// A local Windows user created when absent and usable in share ACLs.
    Local,
}

/// Local SMB share definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbShare {
    /// Share name.
    pub name: String,
    /// Local path.
    pub path: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Deny writes when true.
    #[serde(default)]
    pub read_only: bool,
    /// SMB account identifiers granted access to this share.
    #[serde(default)]
    pub accounts: Vec<String>,
}

/// Remote SMB mapping definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbMapping {
    /// UNC path such as `\\server\share`.
    pub remote: String,
    /// Optional drive letter such as `Z:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    /// Named account declared in `smb.accounts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Optional user name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional password reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretRef>,
}

/// Desired firewall state for all profiles available in the image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    /// Enable or disable the Windows firewall.
    pub enabled: bool,
}

/// Desired service state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    /// The service must be running.
    Running,
    /// The service must be stopped.
    Stopped,
}

/// One shell-free Windows service operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Stable service name, not its localized display name.
    pub name: String,
    /// Desired runtime state.
    pub state: ServiceState,
}

/// Restart behavior after driver installation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// Never restart automatically.
    #[default]
    Never,
    /// Restart only when the native installer reports it is required.
    IfRequired,
    /// Restart the matching adapter after installation.
    Always,
}

/// Explicit driver installation and adapter restart operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum DriverOperation {
    /// Install or update a Plug and Play driver from an INF.
    Install {
        /// Absolute or image-relative INF path.
        inf_path: String,
        /// Optional Plug and Play hardware identifier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hardware_id: Option<String>,
        /// Permit replacement with the supplied driver.
        #[serde(default)]
        force: bool,
        /// Restart policy when installation requests it.
        #[serde(default)]
        restart: RestartPolicy,
    },
    /// Restart one selected network adapter.
    RestartAdapter {
        /// Adapter matcher.
        selector: InterfaceSelector,
    },
}

/// Hook execution stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStage {
    /// Run before applying operations.
    BeforeApply,
    /// Run after successful application.
    AfterApply,
    /// Run after rollback.
    AfterRollback,
}

/// A shell-free process hook.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// Execution stage.
    pub stage: HookStage,
    /// Executable path or name. It is never passed through a shell.
    pub program: String,
    /// Individual process arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Wait for the process to exit.
    #[serde(default = "default_true")]
    pub wait: bool,
}

/// A secret supplied literally or through an environment variable.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "source",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SecretRef {
    /// Read a value from the daemon environment.
    Env(String),
    /// Inline value. Intended for ephemeral PE configuration only.
    Literal(String),
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(name) => formatter.debug_tuple("Env").field(name).finish(),
            Self::Literal(_) => formatter.write_str("Literal([REDACTED])"),
        }
    }
}

const fn default_true() -> bool {
    true
}

impl NetplanConfig {
    /// Parse and semantically validate a YAML or JSON document.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is not UTF-8, cannot be decoded with
    /// the requested format, or violates the schema's semantic constraints.
    pub fn parse(document: &[u8], format: ConfigFormat) -> Result<Self> {
        let text = std::str::from_utf8(document).map_err(|error| Error::Decode {
            format: "UTF-8",
            message: error.to_string(),
        })?;
        let resolved = match format {
            ConfigFormat::Auto if text.trim_start().starts_with(['{', '[']) => ConfigFormat::Json,
            ConfigFormat::Auto => ConfigFormat::Yaml,
            explicit => explicit,
        };
        let config = match resolved {
            ConfigFormat::Json => serde_json::from_str(text).map_err(|error| Error::Decode {
                format: "JSON",
                message: error.to_string(),
            })?,
            ConfigFormat::Yaml => serde_saphyr::from_str(text).map_err(|error| Error::Decode {
                format: "YAML",
                message: error.to_string(),
            })?,
            ConfigFormat::Auto => unreachable!("auto format is resolved before parsing"),
        };
        validate(&config)?;
        Ok(config)
    }
}

#[allow(clippy::too_many_lines)]
fn validate(config: &NetplanConfig) -> Result<()> {
    if config.version != 1 {
        return Err(Error::Validation(format!(
            "unsupported schema version {}; expected 1",
            config.version
        )));
    }
    for selector in config
        .protect
        .management_interfaces
        .iter()
        .chain(config.adapters.iter().map(|adapter| &adapter.selector))
        .chain(config.wifi.iter().filter_map(|wifi| wifi.selector.as_ref()))
        .chain(
            config
                .wifi_actions
                .iter()
                .filter_map(|action| match action {
                    WifiAction::Scan { selector }
                    | WifiAction::Connect { selector, .. }
                    | WifiAction::Disconnect { selector } => selector.as_ref(),
                }),
        )
        .chain(
            config
                .drivers
                .iter()
                .filter_map(|operation| match operation {
                    DriverOperation::RestartAdapter { selector } => Some(selector),
                    DriverOperation::Install { .. } => None,
                }),
        )
    {
        validate_selector(selector)?;
    }
    if let Some(identity) = &config.identity {
        validate_identity(identity)?;
    }
    for adapter in &config.adapters {
        reject_protected_selector(config, &adapter.selector)?;
        if let Some(mac) = &adapter.mac_address {
            validate_mac(mac)?;
        }
        if let Some(ipv4) = &adapter.ipv4 {
            validate_ipv4(ipv4)?;
        }
    }
    for wifi in &config.wifi {
        if let Some(selector) = &wifi.selector {
            reject_protected_selector(config, selector)?;
        }
        if wifi.ssid.is_empty() || wifi.ssid.len() > 32 {
            return Err(Error::Validation(
                "Wi-Fi SSID must contain 1 to 32 bytes".into(),
            ));
        }
        if wifi
            .name
            .as_deref()
            .is_some_and(|name| name.trim().is_empty() || name.contains('\0'))
        {
            return Err(Error::Validation(
                "Wi-Fi profile name must not be empty or contain NUL".into(),
            ));
        }
        match (wifi.authentication, &wifi.psk) {
            (WifiAuthentication::Open, Some(_)) => {
                return Err(Error::Validation(
                    "open Wi-Fi profiles must not contain a PSK".into(),
                ));
            }
            (WifiAuthentication::Wpa2Personal | WifiAuthentication::Wpa3Personal, None) => {
                return Err(Error::Validation(
                    "secured Wi-Fi profiles require a PSK reference".into(),
                ));
            }
            (authentication, Some(SecretRef::Literal(secret))) => {
                validate_psk(secret)?;
                if authentication == WifiAuthentication::Wpa3Personal && secret.len() == 64 {
                    return Err(Error::Validation(
                        "WPA3-Personal requires an 8 to 63 byte passphrase, not a 64-digit raw PSK"
                            .into(),
                    ));
                }
            }
            (_, Some(SecretRef::Env(name))) if name.is_empty() => {
                return Err(Error::Validation(
                    "secret environment variable name must not be empty".into(),
                ));
            }
            _ => {}
        }
    }
    for (index, profile) in config.wifi.iter().enumerate() {
        let name = wifi_profile_name(profile);
        if config.wifi[..index]
            .iter()
            .any(|other| wifi_profile_name(other).eq_ignore_ascii_case(name))
        {
            return Err(Error::Validation(format!(
                "duplicate Wi-Fi profile name {name:?}"
            )));
        }
    }
    for action in &config.wifi_actions {
        if let WifiAction::Connect { profile, .. } = action
            && !config
                .wifi
                .iter()
                .any(|candidate| wifi_profile_name(candidate).eq_ignore_ascii_case(profile))
        {
            return Err(Error::Validation(format!(
                "Wi-Fi connect references unknown Wi-Fi profile {profile:?}"
            )));
        }
    }
    for (index, account) in config.smb.accounts.iter().enumerate() {
        if account.id.trim().is_empty() || account.id.contains('\0') {
            return Err(Error::Validation(
                "SMB account id must not be empty or contain NUL".into(),
            ));
        }
        if account.username.trim().is_empty() || account.username.contains('\0') {
            return Err(Error::Validation(format!(
                "SMB account {:?} has an invalid username",
                account.id
            )));
        }
        if account.kind == SmbAccountKind::Local
            && (account.username.len() > 20
                || account.username.contains([
                    '\\', '/', '@', '[', ']', ':', ';', '|', '=', '+', '*', '?', '<', '>', '"', ',',
                ]))
        {
            return Err(Error::Validation(format!(
                "SMB local account {:?} has an invalid Windows user name",
                account.id
            )));
        }
        if config.smb.accounts[..index]
            .iter()
            .any(|other| other.id.eq_ignore_ascii_case(&account.id))
        {
            return Err(Error::Validation(format!(
                "duplicate SMB account id {:?}",
                account.id
            )));
        }
        validate_optional_secret(account.password.as_ref())?;
    }
    for (index, share) in config.smb.shares.iter().enumerate() {
        if share.name.trim().is_empty()
            || share.name.len() > 80
            || share.name.contains(['\\', '/', '\0'])
            || matches!(
                share.name.to_ascii_lowercase().as_str(),
                "pipe" | "mailslot"
            )
        {
            return Err(Error::Validation(format!(
                "invalid SMB share name {:?}",
                share.name
            )));
        }
        if config.smb.shares[..index]
            .iter()
            .any(|other| other.name.eq_ignore_ascii_case(&share.name))
        {
            return Err(Error::Validation(format!(
                "duplicate SMB share name {:?}",
                share.name
            )));
        }
        if !is_absolute_windows_path(&share.path) || share.path.contains('\0') {
            return Err(Error::Validation(format!(
                "SMB share {:?} requires an absolute local Windows path",
                share.name
            )));
        }
        if share
            .description
            .as_ref()
            .is_some_and(|description| description.len() > 48 || description.contains('\0'))
        {
            return Err(Error::Validation(format!(
                "SMB share {:?} description exceeds 48 bytes or contains NUL",
                share.name
            )));
        }
        for (account_index, account) in share.accounts.iter().enumerate() {
            let Some(declared) = find_smb_account(config, account) else {
                return Err(Error::Validation(format!(
                    "unknown SMB account reference {account:?}"
                )));
            };
            if declared.kind != SmbAccountKind::Local {
                return Err(Error::Validation(format!(
                    "SMB share {:?} requires account {account:?} to have kind local",
                    share.name
                )));
            }
            if share.accounts[..account_index]
                .iter()
                .any(|other| other.eq_ignore_ascii_case(account))
            {
                return Err(Error::Validation(format!(
                    "SMB share {:?} contains duplicate account reference {account:?}",
                    share.name
                )));
            }
        }
    }
    for (index, mapping) in config.smb.mappings.iter().enumerate() {
        if !is_unc_share(&mapping.remote) || mapping.remote.contains('\0') {
            return Err(Error::Validation(format!(
                "SMB mapping {:?} must be a UNC share path",
                mapping.remote
            )));
        }
        if let Some(local) = &mapping.local
            && !is_drive_letter(local)
        {
            return Err(Error::Validation(format!(
                "invalid SMB drive letter {local:?}"
            )));
        }
        if let Some(local) = &mapping.local
            && config.smb.mappings[..index]
                .iter()
                .filter_map(|other| other.local.as_deref())
                .any(|other| other.eq_ignore_ascii_case(local))
        {
            return Err(Error::Validation(format!(
                "duplicate SMB drive mapping for {local:?}"
            )));
        }
        if let Some(account) = &mapping.account {
            validate_smb_account_reference(config, account)?;
            if mapping.username.is_some() || mapping.password.is_some() {
                return Err(Error::Validation(format!(
                    "SMB mapping {:?} cannot combine account with inline credentials",
                    mapping.remote
                )));
            }
        }
        if mapping.password.is_some() && mapping.username.is_none() {
            return Err(Error::Validation(format!(
                "SMB mapping {:?} provides a password without a username",
                mapping.remote
            )));
        }
        validate_optional_secret(mapping.password.as_ref())?;
    }
    for (index, service) in config.services.iter().enumerate() {
        validate_service_name(&service.name)?;
        if config.services[..index]
            .iter()
            .any(|other| other.name.eq_ignore_ascii_case(&service.name))
        {
            return Err(Error::Validation(format!(
                "duplicate service operation for {:?}",
                service.name
            )));
        }
    }
    if !config.smb.shares.is_empty() && service_requested_stopped(config, "LanmanServer") {
        return Err(Error::Validation(
            "SMB shares cannot be combined with stopping LanmanServer".into(),
        ));
    }
    if !config.smb.mappings.is_empty() && service_requested_stopped(config, "LanmanWorkstation") {
        return Err(Error::Validation(
            "SMB mappings cannot be combined with stopping LanmanWorkstation".into(),
        ));
    }
    for operation in &config.drivers {
        match operation {
            DriverOperation::Install {
                inf_path,
                hardware_id,
                restart,
                ..
            } => {
                if inf_path.trim().is_empty()
                    || inf_path.contains('\0')
                    || !inf_path.to_ascii_lowercase().ends_with(".inf")
                {
                    return Err(Error::Validation(format!(
                        "driver install path {inf_path:?} must name an .inf file"
                    )));
                }
                if hardware_id
                    .as_deref()
                    .is_some_and(|value| value.trim().is_empty() || value.contains('\0'))
                {
                    return Err(Error::Validation(
                        "driver hardware_id must not be empty or contain NUL".into(),
                    ));
                }
                if *restart != RestartPolicy::Never && hardware_id.is_none() {
                    return Err(Error::Validation(
                        "driver restart policy requires a hardware_id".into(),
                    ));
                }
            }
            DriverOperation::RestartAdapter { selector } => {
                reject_protected_selector(config, selector)?;
            }
        }
    }
    for hook in &config.hooks {
        if hook.program.trim().is_empty() || hook.program.contains('\0') {
            return Err(Error::Validation(
                "hook executable must not be empty or contain NUL".into(),
            ));
        }
        if hook.args.iter().any(|argument| argument.contains('\0')) {
            return Err(Error::Validation(
                "hook arguments must not contain NUL".into(),
            ));
        }
    }
    Ok(())
}

fn validate_identity(identity: &IdentityConfig) -> Result<()> {
    if let Some(name) = &identity.computer_name {
        let valid = !name.is_empty()
            && name.len() <= 15
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && name.bytes().any(|byte| !byte.is_ascii_digit())
            && !name.starts_with('-')
            && !name.ends_with('-');
        if !valid {
            return Err(Error::Validation(format!(
                "invalid NetBIOS computer name {name:?}"
            )));
        }
    }
    if let Some(workgroup) = &identity.workgroup {
        let valid = !workgroup.is_empty()
            && workgroup.len() <= 15
            && !workgroup.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|', '\0']);
        if !valid {
            return Err(Error::Validation(format!(
                "invalid workgroup name {workgroup:?}"
            )));
        }
    }
    if let Some(suffix) = &identity.dns_suffix
        && !is_dns_name(suffix)
    {
        return Err(Error::Validation(format!(
            "invalid primary DNS suffix {suffix:?}"
        )));
    }
    Ok(())
}

fn is_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn validate_ipv4(ipv4: &Ipv4Config) -> Result<()> {
    let Ipv4Config::Static {
        addresses,
        gateways,
        dns,
        wins,
    } = ipv4
    else {
        return Ok(());
    };
    if addresses.is_empty() {
        return Err(Error::Validation(
            "static IPv4 mode requires at least one address".into(),
        ));
    }
    for address in addresses {
        let host = address.addr();
        if host.is_unspecified() || host.is_multicast() || host.is_broadcast() {
            return Err(Error::Validation(format!(
                "invalid static IPv4 host address {address}"
            )));
        }
    }
    for gateway in gateways {
        if gateway.is_unspecified() || gateway.is_multicast() || gateway.is_broadcast() {
            return Err(Error::Validation(format!("invalid IPv4 gateway {gateway}")));
        }
    }
    for server in dns {
        if server.is_unspecified() || server.is_multicast() {
            return Err(Error::Validation(format!("invalid DNS server {server}")));
        }
    }
    for server in wins {
        if server.is_unspecified() || server.is_multicast() || server.is_broadcast() {
            return Err(Error::Validation(format!("invalid WINS server {server}")));
        }
    }
    Ok(())
}

fn wifi_profile_name(profile: &WifiProfile) -> &str {
    profile.name.as_deref().unwrap_or(&profile.ssid)
}

fn validate_optional_secret(secret: Option<&SecretRef>) -> Result<()> {
    match secret {
        Some(SecretRef::Env(name)) if name.trim().is_empty() || name.contains('\0') => {
            Err(Error::Validation(
                "secret environment variable name must not be empty or contain NUL".into(),
            ))
        }
        Some(SecretRef::Literal(value)) if value.contains('\0') => Err(Error::Validation(
            "literal secret must not contain NUL".into(),
        )),
        _ => Ok(()),
    }
}

fn validate_smb_account_reference(config: &NetplanConfig, reference: &str) -> Result<()> {
    if find_smb_account(config, reference).is_some() {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "unknown SMB account reference {reference:?}"
        )))
    }
}

fn find_smb_account<'a>(config: &'a NetplanConfig, reference: &str) -> Option<&'a SmbAccount> {
    config
        .smb
        .accounts
        .iter()
        .find(|account| account.id.eq_ignore_ascii_case(reference))
}

fn validate_service_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 256 || name.contains(['\\', '/', '\0']) {
        Err(Error::Validation(format!(
            "invalid Windows service name {name:?}"
        )))
    } else {
        Ok(())
    }
}

fn service_requested_stopped(config: &NetplanConfig, name: &str) -> bool {
    config.services.iter().any(|service| {
        service.name.eq_ignore_ascii_case(name) && service.state == ServiceState::Stopped
    })
}

fn reject_protected_selector(config: &NetplanConfig, target: &InterfaceSelector) -> Result<()> {
    if config
        .protect
        .management_interfaces
        .iter()
        .any(|protected| selectors_share_stable_matcher(protected, target))
    {
        return Err(Error::Validation(format!(
            "configuration targets a protected management interface ({})",
            selector_label(target)
        )));
    }
    Ok(())
}

fn selectors_share_stable_matcher(
    protected: &InterfaceSelector,
    target: &InterfaceSelector,
) -> bool {
    matches!((protected.if_index, target.if_index), (Some(left), Some(right)) if left == right)
        || equal_optional_text(protected.name.as_deref(), target.name.as_deref())
        || equal_optional_guid(protected.guid.as_deref(), target.guid.as_deref())
        || equal_optional_mac(
            protected.mac_address.as_deref(),
            target.mac_address.as_deref(),
        )
        || equal_optional_text(
            protected.description_contains.as_deref(),
            target.description_contains.as_deref(),
        )
}

fn equal_optional_text(left: Option<&str>, right: Option<&str>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if left.eq_ignore_ascii_case(right))
}

fn equal_optional_guid(left: Option<&str>, right: Option<&str>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if left.trim_matches(['{', '}']).eq_ignore_ascii_case(right.trim_matches(['{', '}'])))
}

fn equal_optional_mac(left: Option<&str>, right: Option<&str>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if canonical_mac(left) == canonical_mac(right))
}

fn canonical_mac(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != ':' && *ch != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

fn selector_label(selector: &InterfaceSelector) -> String {
    selector.if_index.map_or_else(
        || {
            selector
                .name
                .as_ref()
                .map_or_else(|| "stable selector".into(), |name| format!("name={name:?}"))
        },
        |if_index| format!("if_index={if_index}"),
    )
}

fn validate_selector(selector: &InterfaceSelector) -> Result<()> {
    if selector.if_index.is_none()
        && selector.name.as_deref().is_none_or(str::is_empty)
        && selector.guid.as_deref().is_none_or(str::is_empty)
        && selector.mac_address.as_deref().is_none_or(str::is_empty)
        && selector
            .description_contains
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(Error::Validation(
            "each interface selector must contain at least one matcher".into(),
        ));
    }
    if let Some(mac) = &selector.mac_address {
        validate_mac(mac)?;
    }
    Ok(())
}

fn validate_mac(mac: &str) -> Result<()> {
    let compact: String = mac.chars().filter(|ch| *ch != ':' && *ch != '-').collect();
    if compact.len() != 12 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Validation(format!(
            "invalid MAC address {mac:?}; expected 12 hexadecimal digits"
        )));
    }
    let first_octet = u8::from_str_radix(&compact[..2], 16)
        .map_err(|error| Error::Validation(format!("invalid MAC address {mac:?}: {error}")))?;
    if first_octet & 0b0000_0011 != 0b0000_0010 {
        return Err(Error::Validation(format!(
            "MAC override {mac:?} must be a locally administered unicast address"
        )));
    }
    Ok(())
}

fn validate_psk(secret: &str) -> Result<()> {
    let is_hex_64 = secret.len() == 64 && secret.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !(8..=63).contains(&secret.len()) && !is_hex_64 {
        return Err(Error::Validation(
            "Wi-Fi PSK must be 8 to 63 bytes or 64 hexadecimal digits".into(),
        ));
    }
    Ok(())
}

fn is_unc_share(path: &str) -> bool {
    let mut parts = path.trim_start_matches('\\').split('\\');
    path.starts_with("\\\\")
        && parts.next().is_some_and(|part| !part.is_empty())
        && parts.next().is_some_and(|part| !part.is_empty())
}

fn is_drive_letter(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_absolute_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/'))
        || value.starts_with(r"\\?\")
        || value.starts_with(r"\\.\")
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r"
version: 1
protect:
  management_interfaces:
    - if_index: 6
adapters:
  - selector:
      if_index: 7
    ipv4:
      mode: static
      addresses: [192.0.2.10/24]
      gateways: [192.0.2.1]
      dns: [1.1.1.1]
wifi:
  - ssid: Lab
    authentication: wpa2_personal
    psk:
      source: literal
      value: correct-horse
smb:
  mappings:
    - remote: '\\server\share'
      local: 'Z:'
";

    #[test]
    fn yaml_and_json_decode_to_the_same_model() {
        let yaml = NetplanConfig::parse(YAML.as_bytes(), ConfigFormat::Yaml);
        assert!(yaml.is_ok(), "{yaml:?}");
        let yaml = match yaml {
            Ok(value) => value,
            Err(error) => panic!("unexpected YAML error: {error}"),
        };
        let json = serde_json::to_vec(&yaml);
        assert!(json.is_ok(), "{json:?}");
        let json = match json {
            Ok(value) => value,
            Err(error) => panic!("unexpected JSON serialization error: {error}"),
        };
        let reparsed = NetplanConfig::parse(&json, ConfigFormat::Auto);
        assert_eq!(reparsed.ok(), Some(yaml));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let result = NetplanConfig::parse(b"version: 1\nsurprise: true\n", ConfigFormat::Yaml);
        assert!(matches!(result, Err(Error::Decode { .. })));
    }

    #[test]
    fn empty_adapter_selector_is_rejected() {
        let result = NetplanConfig::parse(
            b"version: 1\nadapters:\n  - selector: {}\n",
            ConfigFormat::Yaml,
        );
        assert!(matches!(result, Err(Error::Validation(_))));
    }

    #[test]
    fn protected_management_interface_cannot_be_targeted() {
        let result = NetplanConfig::parse(
            br#"{
              "version": 1,
              "protect": {"management_interfaces": [{"if_index": 6}]},
              "adapters": [{
                "selector": {"if_index": 6},
                "ipv4": {"mode": "dhcp"}
              }]
            }"#,
            ConfigFormat::Json,
        );
        assert!(matches!(result, Err(Error::Validation(message)) if message.contains("protected")));
    }

    #[test]
    fn literal_secrets_are_redacted_from_debug_output() {
        let secret = SecretRef::Literal("do-not-print-this".into());
        let debug = format!("{secret:?}");
        assert!(!debug.contains("do-not-print-this"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn complete_porting_contract_decodes() {
        let document = br"
version: 1
adapters:
  - selector: { if_index: 7 }
    mac_address: 02-11-22-33-44-55
wifi:
  - name: lab-profile
    ssid: Lab
    authentication: wpa2_personal
    psk: { source: env, value: NETPLAN_WIFI_PSK }
wifi_actions:
  - action: scan
  - action: connect
    profile: lab-profile
  - action: disconnect
smb:
  accounts:
    - id: diagnostics
      kind: local
      username: pe-diagnostics
      password: { source: env, value: NETPLAN_SMB_PASSWORD }
  shares:
    - name: diagnostics
      path: 'X:\diagnostics'
      accounts: [diagnostics]
  mappings:
    - remote: '\\server\share'
      local: 'Z:'
      account: diagnostics
firewall: { enabled: true }
services:
  - name: LanmanServer
    state: running
drivers:
  - action: install
    inf_path: 'X:\drivers\net.inf'
    hardware_id: 'PCI\\VEN_1234&DEV_5678'
    force: true
    restart: if_required
  - action: restart_adapter
    selector: { if_index: 7 }
hooks:
  - stage: before_apply
    program: 'X:\before.exe'
    args: [/quiet]
";
        let parsed = NetplanConfig::parse(document, ConfigFormat::Yaml);
        assert!(parsed.is_ok(), "{parsed:?}");
    }

    #[test]
    fn adapter_override_requires_a_locally_administered_unicast_mac() {
        for mac in ["00-11-22-33-44-55", "03-11-22-33-44-55"] {
            let document = format!(
                "version: 1\nadapters:\n  - selector: {{ if_index: 7 }}\n    mac_address: {mac}\n"
            );
            let parsed = NetplanConfig::parse(document.as_bytes(), ConfigFormat::Yaml);
            assert!(
                matches!(parsed, Err(Error::Validation(ref message)) if message.contains("locally administered unicast")),
                "{parsed:?}"
            );
        }
    }

    #[test]
    fn smb_references_must_resolve_to_declared_accounts() {
        let parsed = NetplanConfig::parse(
            br#"{
              "version": 1,
              "smb": {
                "shares": [{
                  "name": "diagnostics",
                  "path": "X:\\diagnostics",
                  "accounts": ["missing"]
                }]
              }
            }"#,
            ConfigFormat::Json,
        );
        assert!(
            matches!(parsed, Err(Error::Validation(message)) if message.contains("unknown SMB account"))
        );
    }

    #[test]
    fn wifi_connect_requires_a_declared_profile() {
        let parsed = NetplanConfig::parse(
            b"version: 1\nwifi_actions:\n  - action: connect\n    profile: missing\n",
            ConfigFormat::Yaml,
        );
        assert!(
            matches!(parsed, Err(Error::Validation(message)) if message.contains("unknown Wi-Fi profile"))
        );
    }

    #[test]
    fn smb_share_requires_explicit_local_account_kind() {
        let parsed = NetplanConfig::parse(
            br#"{
              "version": 1,
              "smb": {
                "accounts": [{"id": "remote", "username": "server\\user"}],
                "shares": [{"name": "data", "path": "X:\\data", "accounts": ["remote"]}]
              }
            }"#,
            ConfigFormat::Json,
        );
        assert!(matches!(parsed, Err(Error::Validation(_))));
    }

    #[test]
    fn wpa3_rejects_a_raw_64_digit_psk() {
        let document = format!(
            "version: 1\nwifi:\n  - ssid: lab\n    authentication: wpa3_personal\n    psk: {{ source: literal, value: '{}' }}\n",
            "a".repeat(64)
        );
        let parsed = NetplanConfig::parse(document.as_bytes(), ConfigFormat::Yaml);
        assert!(matches!(parsed, Err(Error::Validation(_))));
    }

    #[test]
    fn driver_install_requires_an_inf_path() {
        let parsed = NetplanConfig::parse(
            b"version: 1\ndrivers:\n  - action: install\n    inf_path: X:\\\\driver.exe\n",
            ConfigFormat::Yaml,
        );
        assert!(matches!(parsed, Err(Error::Validation(message)) if message.contains(".inf")));
    }
}
