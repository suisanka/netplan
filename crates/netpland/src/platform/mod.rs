//! Platform discovery and mutation boundary.

use std::fmt;
use std::time::Duration;

use netplan::{
    AdapterInfo, Capability, CapabilityState, NetplanConfig, Result, WifiInterfaceStatus,
    WifiNetwork, build_plan,
};

#[cfg(not(windows))]
mod portable;
#[cfg(windows)]
mod windows;

/// Platform services used by the daemon dispatcher.
pub trait Platform: Send + Sync + 'static {
    /// Report feature availability on the current image.
    fn capabilities(&self) -> Vec<Capability>;

    /// Enumerate adapters through native platform APIs.
    fn adapters(&self) -> Result<Vec<AdapterInfo>>;

    /// Query current native Wi-Fi interface connection state.
    fn wifi_status(&self, _if_index: Option<u32>) -> PlatformResult<Vec<WifiInterfaceStatus>> {
        Err(PlatformError::unsupported(
            "native Wi-Fi status is unavailable on this platform",
        ))
    }

    /// Scan or read cached native Wi-Fi networks.
    fn wifi_scan(
        &self,
        _if_index: Option<u32>,
        _refresh: bool,
        _timeout: Duration,
    ) -> PlatformResult<(bool, Vec<WifiNetwork>)> {
        Err(PlatformError::unsupported(
            "native Wi-Fi scanning is unavailable on this platform",
        ))
    }

    /// Reject a live configuration before any mutation when a required capability is absent.
    fn preflight(&self, config: &NetplanConfig) -> PlatformResult<()> {
        require_plan_capabilities(&self.capabilities(), config)
    }

    /// Apply a fully validated and preflighted configuration transaction.
    fn apply(&self, config: &NetplanConfig) -> PlatformResult<ApplyReport>;
}

/// Successful platform transaction report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyReport {
    /// Human-readable summary stored with the daemon job.
    pub message: String,
}

/// Stable platform failure category.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformErrorKind {
    /// A selector is ambiguous or another runtime invariant is invalid.
    InvalidConfig,
    /// A required API, service, or backend is unavailable.
    Unsupported,
    /// The daemon lacks permission for the requested mutation.
    PermissionDenied,
    /// A selected adapter or operating-system object does not exist.
    NotFound,
    /// Execution failed for another reason.
    Internal,
}

/// Failure returned by a platform preflight or transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformError {
    /// Stable failure category.
    pub kind: PlatformErrorKind,
    /// Human-readable diagnostic without secret material.
    pub message: String,
    /// Whether every completed mutation was successfully rolled back.
    pub rolled_back: bool,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl PlatformError {
    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self {
            kind: PlatformErrorKind::Unsupported,
            message: message.into(),
            rolled_back: false,
        }
    }

    pub(crate) fn invalid_config(message: impl Into<String>) -> Self {
        Self::new(PlatformErrorKind::InvalidConfig, message)
    }

    #[cfg(windows)]
    pub(crate) fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(PlatformErrorKind::PermissionDenied, message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(PlatformErrorKind::NotFound, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(PlatformErrorKind::Internal, message)
    }

    fn new(kind: PlatformErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            rolled_back: false,
        }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// Platform transaction result.
pub type PlatformResult<T> = std::result::Result<T, PlatformError>;

pub(crate) fn require_plan_capabilities(
    capabilities: &[Capability],
    config: &NetplanConfig,
) -> PlatformResult<()> {
    for operation in build_plan(config) {
        let Some(capability) = capabilities
            .iter()
            .find(|candidate| candidate.name == operation.capability)
        else {
            return Err(PlatformError::unsupported(format!(
                "operation {:?} requires unreported capability {:?}",
                operation.id, operation.capability
            )));
        };
        let permitted = capability.state == CapabilityState::Available
            || (operation.risk == netplan::OperationRisk::ReadOnly
                && capability.state == CapabilityState::ReadOnly);
        if !permitted {
            let reason = capability
                .reason
                .as_deref()
                .unwrap_or("capability is not available for live execution");
            return Err(PlatformError::unsupported(format!(
                "operation {:?} requires capability {:?}: {reason}",
                operation.id, operation.capability
            )));
        }
    }
    Ok(())
}

/// Construct the current platform implementation.
pub fn current() -> impl Platform {
    #[cfg(windows)]
    {
        windows::WindowsPlatform
    }
    #[cfg(not(windows))]
    {
        portable::PortablePlatform
    }
}
