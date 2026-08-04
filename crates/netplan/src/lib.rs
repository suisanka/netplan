//! Public Rust SDK and configuration types for PE Netplan.

#![deny(unsafe_code)]
#![deny(clippy::expect_used, clippy::unwrap_used)]

pub mod client;
pub mod config;
pub mod error;
pub mod model;
pub mod plan;
pub mod protocol;
#[cfg(windows)]
#[doc(hidden)]
#[allow(unsafe_code)]
pub mod windows_elevation;

pub use client::Client;
pub use config::{ConfigFormat, NetplanConfig};
pub use error::{Error, Result};
pub use model::{
    AdapterInfo, Capability, CapabilityState, IpAddressInfo, WifiInterfaceStatus, WifiNetwork,
};
pub use plan::{Operation, OperationRisk, build_plan};

/// `FlatBuffers` IPC protocol version supported by this crate.
pub const PROTOCOL_VERSION: u32 = 1;

/// Stable Windows Service Control Manager name for `netpland`.
pub const DAEMON_SERVICE_NAME: &str = "PENetpland";

/// Human-readable Windows service display name for `netpland`.
pub const DAEMON_SERVICE_DISPLAY_NAME: &str = "PE Netplan Daemon";
