//! Non-Windows development backend.

use netplan::{AdapterInfo, Capability, CapabilityState, Result};

use super::Platform;

pub struct PortablePlatform;

impl Platform for PortablePlatform {
    fn capabilities(&self) -> Vec<Capability> {
        vec![
            capability("config.validate", CapabilityState::Available, None),
            capability("config.plan", CapabilityState::Available, None),
            capability(
                "config.apply",
                CapabilityState::DryRun,
                Some("live apply is Windows-only"),
            ),
            capability(
                "adapter.inventory",
                CapabilityState::Unavailable,
                Some("native Windows IP Helper API is unavailable"),
            ),
            capability(
                "wifi",
                CapabilityState::Unavailable,
                Some("Windows WLAN API is unavailable"),
            ),
            capability(
                "smb",
                CapabilityState::Unavailable,
                Some("Windows SMB APIs are unavailable"),
            ),
        ]
    }

    fn adapters(&self) -> Result<Vec<AdapterInfo>> {
        Ok(Vec::new())
    }
}

fn capability(name: &str, state: CapabilityState, reason: Option<&str>) -> Capability {
    Capability {
        name: name.into(),
        state,
        reason: reason.map(Into::into),
    }
}
