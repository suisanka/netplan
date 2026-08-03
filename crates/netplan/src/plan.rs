//! Deterministic configuration planning.

use serde::{Deserialize, Serialize};

use crate::config::{Ipv4Config, NetplanConfig};

/// Risk level of a planned operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRisk {
    /// Does not mutate system state.
    ReadOnly,
    /// Local mutation that should not interrupt connectivity.
    Low,
    /// May interrupt network connectivity.
    Connectivity,
    /// Destructive or difficult-to-recover mutation.
    Destructive,
}

/// One deterministic operation produced by the planner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Operation {
    /// Stable operation identifier within the plan.
    pub id: String,
    /// Capability required by the backend.
    pub capability: String,
    /// Human-readable summary.
    pub summary: String,
    /// Risk classification.
    pub risk: OperationRisk,
    /// Optional target selector summary.
    pub target: Option<String>,
}

/// Build a deterministic ordered plan from a validated configuration.
#[must_use]
pub fn build_plan(config: &NetplanConfig) -> Vec<Operation> {
    let mut operations = Vec::new();
    if let Some(identity) = &config.identity {
        for (field, value) in [
            ("computer_name", identity.computer_name.as_ref()),
            ("workgroup", identity.workgroup.as_ref()),
            ("dns_suffix", identity.dns_suffix.as_ref()),
        ] {
            if let Some(value) = value {
                operations.push(Operation {
                    id: format!("identity.{field}"),
                    capability: "identity.apply".into(),
                    summary: format!("Set {field} to {value}"),
                    risk: OperationRisk::Connectivity,
                    target: None,
                });
            }
        }
    }
    for (index, adapter) in config.adapters.iter().enumerate() {
        let target = selector_summary(&adapter.selector);
        if let Some(enabled) = adapter.enabled {
            operations.push(Operation {
                id: format!("adapter.{index}.enabled"),
                capability: "adapter.state.apply".into(),
                summary: if enabled {
                    "Enable adapter"
                } else {
                    "Disable adapter"
                }
                .into(),
                risk: OperationRisk::Connectivity,
                target: Some(target.clone()),
            });
        }
        if let Some(mac) = &adapter.mac_address {
            operations.push(Operation {
                id: format!("adapter.{index}.mac"),
                capability: "adapter.mac.apply".into(),
                summary: format!("Set adapter MAC address to {mac}"),
                risk: OperationRisk::Connectivity,
                target: Some(target.clone()),
            });
        }
        if let Some(ipv4) = &adapter.ipv4 {
            let summary = match ipv4 {
                Ipv4Config::Dhcp { .. } => "Configure IPv4 using DHCP".into(),
                Ipv4Config::Static { addresses, .. } => {
                    format!("Configure static IPv4 addresses: {addresses:?}")
                }
            };
            operations.push(Operation {
                id: format!("adapter.{index}.ipv4"),
                capability: "adapter.ipv4.apply".into(),
                summary,
                risk: OperationRisk::Connectivity,
                target: Some(target),
            });
        }
    }
    for (index, wifi) in config.wifi.iter().enumerate() {
        operations.push(Operation {
            id: format!("wifi.{index}.profile"),
            capability: "wifi.profile.apply".into(),
            summary: format!("Install Wi-Fi profile for SSID {:?}", wifi.ssid),
            risk: OperationRisk::Connectivity,
            target: wifi.selector.as_ref().map(selector_summary),
        });
    }
    for (index, share) in config.smb.shares.iter().enumerate() {
        operations.push(Operation {
            id: format!("smb.share.{index}"),
            capability: "smb.share.apply".into(),
            summary: format!("Share {:?} as {:?}", share.path, share.name),
            risk: OperationRisk::Low,
            target: Some(share.name.clone()),
        });
    }
    for (index, mapping) in config.smb.mappings.iter().enumerate() {
        operations.push(Operation {
            id: format!("smb.mapping.{index}"),
            capability: "smb.mapping.apply".into(),
            summary: format!("Map SMB share {:?}", mapping.remote),
            risk: OperationRisk::Low,
            target: mapping.local.clone(),
        });
    }
    for (index, hook) in config.hooks.iter().enumerate() {
        operations.push(Operation {
            id: format!("hook.{index}"),
            capability: "hook.execute".into(),
            summary: format!("Execute {:?} at {:?}", hook.program, hook.stage),
            risk: OperationRisk::Destructive,
            target: None,
        });
    }
    operations
}

fn selector_summary(selector: &crate::config::InterfaceSelector) -> String {
    if let Some(index) = selector.if_index {
        return format!("if_index={index}");
    }
    if let Some(name) = &selector.name {
        return format!("name={name:?}");
    }
    if let Some(guid) = &selector.guid {
        return format!("guid={guid}");
    }
    if let Some(mac) = &selector.mac_address {
        return format!("mac={mac}");
    }
    selector.description_contains.as_ref().map_or_else(
        || "unknown".into(),
        |value| format!("description~={value:?}"),
    )
}

#[cfg(test)]
mod tests {
    use crate::{ConfigFormat, NetplanConfig};

    use super::*;

    #[test]
    fn planner_preserves_safe_dependency_order() {
        let config = NetplanConfig::parse(
            br#"{
              "version": 1,
              "identity": {"computer_name": "PE-LAB"},
              "adapters": [{
                "selector": {"if_index": 7},
                "enabled": true,
                "ipv4": {"mode": "dhcp"}
              }]
            }"#,
            ConfigFormat::Json,
        );
        assert!(config.is_ok(), "{config:?}");
        let Some(config) = config.ok() else {
            panic!("configuration should parse");
        };
        let ids: Vec<_> = build_plan(&config).into_iter().map(|op| op.id).collect();
        assert_eq!(
            ids,
            [
                "identity.computer_name",
                "adapter.0.enabled",
                "adapter.0.ipv4"
            ]
        );
    }
}
