//! Platform discovery and mutation boundary.

use netplan::{AdapterInfo, Capability, Result};

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
