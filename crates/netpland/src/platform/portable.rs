//! Non-Windows development backend.

use netplan::{AdapterInfo, Capability, CapabilityState, NetplanConfig, Result};

use super::{ApplyReport, Platform, PlatformError, PlatformResult};

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
                "adapter.state.apply",
                CapabilityState::Unavailable,
                Some("Windows adapter state APIs are unavailable"),
            ),
            capability(
                "adapter.mac.apply",
                CapabilityState::Unavailable,
                Some("Windows adapter registry APIs are unavailable"),
            ),
            capability(
                "adapter.ipv4.apply",
                CapabilityState::Unavailable,
                Some("Windows IP configuration APIs are unavailable"),
            ),
            capability(
                "firewall.apply",
                CapabilityState::Unavailable,
                Some("Windows firewall APIs are unavailable"),
            ),
            capability(
                "service.apply",
                CapabilityState::Unavailable,
                Some("Windows service control manager is unavailable"),
            ),
            capability(
                "driver.install",
                CapabilityState::Unavailable,
                Some("Windows driver installation APIs are unavailable"),
            ),
            capability(
                "driver.force_install",
                CapabilityState::Unavailable,
                Some("Windows driver installation APIs are unavailable"),
            ),
            capability(
                "adapter.restart",
                CapabilityState::Unavailable,
                Some("Windows device APIs are unavailable"),
            ),
            capability(
                "hook.execute",
                CapabilityState::Unavailable,
                Some("live hooks are disabled outside Windows"),
            ),
        ]
        .into_iter()
        .chain(
            [
                "identity.computer_name.apply",
                "identity.workgroup.apply",
                "identity.dns_suffix.apply",
            ]
            .map(|name| {
                capability(
                    name,
                    CapabilityState::Unavailable,
                    Some("Windows identity APIs are unavailable"),
                )
            }),
        )
        .chain(
            [
                "wifi.status",
                "wifi.profile.apply",
                "wifi.scan",
                "wifi.connect",
                "wifi.disconnect",
            ]
            .map(|name| {
                capability(
                    name,
                    CapabilityState::Unavailable,
                    Some("Windows WLAN API is unavailable"),
                )
            }),
        )
        .chain(
            ["smb.account.apply", "smb.share.apply", "smb.mapping.apply"].map(|name| {
                capability(
                    name,
                    CapabilityState::Unavailable,
                    Some("Windows SMB APIs are unavailable"),
                )
            }),
        )
        .collect()
    }

    fn adapters(&self) -> Result<Vec<AdapterInfo>> {
        Ok(Vec::new())
    }

    fn apply(&self, _config: &NetplanConfig) -> PlatformResult<ApplyReport> {
        Err(PlatformError::unsupported(
            "live apply is available only on Windows",
        ))
    }
}

fn capability(name: &str, state: CapabilityState, reason: Option<&str>) -> Capability {
    Capability {
        name: name.into(),
        state,
        reason: reason.map(Into::into),
    }
}
