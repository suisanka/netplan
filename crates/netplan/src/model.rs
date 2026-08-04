//! Shared daemon response models.

use serde::{Deserialize, Serialize};

/// Availability level for a feature on the current image.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// Required APIs or services are absent.
    Unavailable,
    /// Discovery is available but changes are disabled.
    ReadOnly,
    /// Planning is supported while live application is disabled.
    DryRun,
    /// Discovery and live application are supported.
    Available,
}

/// One platform capability reported by `netpland`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Capability {
    /// Stable capability identifier.
    pub name: String,
    /// Availability level.
    pub state: CapabilityState,
    /// Optional diagnostic when not fully available.
    pub reason: Option<String>,
}

/// IP address attached to an adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IpAddressInfo {
    /// Address without a prefix suffix.
    pub address: String,
    /// CIDR prefix length.
    pub prefix_length: u8,
}

/// Read-only network adapter information.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdapterInfo {
    /// Windows interface index.
    pub if_index: u32,
    /// Friendly connection name.
    pub name: String,
    /// Driver or device description.
    pub description: Option<String>,
    /// Windows adapter GUID when present.
    pub guid: Option<String>,
    /// Canonical MAC address.
    pub mac_address: Option<String>,
    /// Operational status.
    pub status: String,
    /// Whether this is a physical hardware adapter.
    pub hardware: bool,
    /// Assigned IPv4 addresses.
    pub ipv4: Vec<IpAddressInfo>,
    /// Assigned IPv6 addresses.
    pub ipv6: Vec<IpAddressInfo>,
}

/// Current connection state for one native Wi-Fi interface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WifiInterfaceStatus {
    /// Windows interface index.
    pub if_index: u32,
    /// Friendly interface name.
    pub name: String,
    /// Windows interface GUID when available.
    pub guid: Option<String>,
    /// Stable state such as `connected` or `disconnected`.
    pub state: String,
    /// Active WLAN profile name when connected.
    pub profile_name: Option<String>,
    /// Display form of the active SSID when connected.
    pub ssid: Option<String>,
    /// Exact active SSID bytes encoded as uppercase hexadecimal.
    pub ssid_hex: Option<String>,
    /// Native signal quality from 0 through 100.
    pub signal_quality: Option<u8>,
    /// Whether link-layer security is enabled.
    pub security_enabled: Option<bool>,
    /// Stable authentication algorithm name.
    pub authentication: Option<String>,
    /// Stable cipher algorithm name.
    pub cipher: Option<String>,
    /// Current receive rate in kilobits per second.
    pub rx_rate_kbps: Option<u32>,
    /// Current transmit rate in kilobits per second.
    pub tx_rate_kbps: Option<u32>,
}

/// One network returned by a native Wi-Fi scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WifiNetwork {
    /// Interface index that observed this network.
    pub interface_if_index: u32,
    /// Friendly name of the observing interface.
    pub interface_name: String,
    /// Lossy UTF-8 display form of the SSID.
    pub ssid: String,
    /// Exact SSID bytes encoded as uppercase hexadecimal.
    pub ssid_hex: String,
    /// Matching saved profile name when one exists.
    pub profile_name: Option<String>,
    /// Native signal quality from 0 through 100.
    pub signal_quality: u8,
    /// Whether link-layer security is enabled.
    pub security_enabled: bool,
    /// Stable authentication algorithm name.
    pub authentication: String,
    /// Stable cipher algorithm name.
    pub cipher: String,
    /// Whether Windows considers the network connectable.
    pub connectable: bool,
    /// Native reason code when the network is not connectable.
    pub not_connectable_reason: Option<u32>,
    /// Whether this is the current connection.
    pub connected: bool,
    /// Number of BSS entries represented by this network.
    pub bss_count: u32,
}
