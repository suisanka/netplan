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
    /// SMB server and client configuration.
    #[serde(default)]
    pub smb: SmbConfig,
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
    /// Adapter matcher. When absent, the first WLAN interface is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<InterfaceSelector>,
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

/// SMB desired state.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbConfig {
    /// Local shares to create.
    #[serde(default)]
    pub shares: Vec<SmbShare>,
    /// Remote shares to map.
    #[serde(default)]
    pub mappings: Vec<SmbMapping>,
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
    /// Optional user name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional password reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretRef>,
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
    {
        validate_selector(selector)?;
    }
    for adapter in &config.adapters {
        reject_protected_selector(config, &adapter.selector)?;
        if let Some(mac) = &adapter.mac_address {
            validate_mac(mac)?;
        }
        if let Some(Ipv4Config::Static { addresses, .. }) = &adapter.ipv4
            && addresses.is_empty()
        {
            return Err(Error::Validation(
                "static IPv4 mode requires at least one address".into(),
            ));
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
            (_, Some(SecretRef::Literal(secret))) => validate_psk(secret)?,
            (_, Some(SecretRef::Env(name))) if name.is_empty() => {
                return Err(Error::Validation(
                    "secret environment variable name must not be empty".into(),
                ));
            }
            _ => {}
        }
    }
    for share in &config.smb.shares {
        if share.name.is_empty() || share.name.contains(['\\', '/']) {
            return Err(Error::Validation(format!(
                "invalid SMB share name {:?}",
                share.name
            )));
        }
        if share.path.is_empty() {
            return Err(Error::Validation(format!(
                "SMB share {:?} has an empty path",
                share.name
            )));
        }
    }
    for mapping in &config.smb.mappings {
        if !is_unc_share(&mapping.remote) {
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
    }
    for hook in &config.hooks {
        if hook.program.trim().is_empty() {
            return Err(Error::Validation(
                "hook executable must not be empty".into(),
            ));
        }
    }
    Ok(())
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
}
