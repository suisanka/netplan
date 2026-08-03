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
