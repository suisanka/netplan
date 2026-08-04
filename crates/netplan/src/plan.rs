//! Deterministic configuration planning.

use serde::{Deserialize, Serialize};

use crate::config::{
    DriverOperation, HookStage, Ipv4Config, NetplanConfig, ServiceState, WifiAction,
};

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
#[allow(clippy::too_many_lines)]
pub fn build_plan(config: &NetplanConfig) -> Vec<Operation> {
    let mut operations = Vec::new();
    push_hooks(config, HookStage::BeforeApply, &mut operations);
    if let Some(identity) = &config.identity {
        for (field, value) in [
            ("computer_name", identity.computer_name.as_ref()),
            ("workgroup", identity.workgroup.as_ref()),
            ("dns_suffix", identity.dns_suffix.as_ref()),
        ] {
            if let Some(value) = value {
                operations.push(Operation {
                    id: format!("identity.{field}"),
                    capability: format!("identity.{field}.apply"),
                    summary: format!("Set {field} to {value}"),
                    risk: OperationRisk::Connectivity,
                    target: None,
                });
            }
        }
    }
    for (index, adapter) in config.adapters.iter().enumerate() {
        let target = selector_summary(&adapter.selector);
        if adapter.enabled == Some(true) {
            push_adapter_state(index, true, &target, &mut operations);
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
                Ipv4Config::Dhcp { dns_from_dhcp } => {
                    format!("Configure IPv4 using DHCP (DNS from DHCP: {dns_from_dhcp})")
                }
                Ipv4Config::Static {
                    addresses,
                    gateways,
                    dns,
                    wins,
                } => format!(
                    "Configure static IPv4 addresses {addresses:?}, gateways {gateways:?}, DNS {dns:?}, WINS {wins:?}"
                ),
            };
            operations.push(Operation {
                id: format!("adapter.{index}.ipv4"),
                capability: "adapter.ipv4.apply".into(),
                summary,
                risk: OperationRisk::Connectivity,
                target: Some(target.clone()),
            });
        }
        if adapter.enabled == Some(false) {
            push_adapter_state(index, false, &target, &mut operations);
        }
    }
    for (index, wifi) in config.wifi.iter().enumerate() {
        operations.push(Operation {
            id: format!("wifi.profile.{index}"),
            capability: "wifi.profile.apply".into(),
            summary: format!(
                "Install Wi-Fi profile {:?} for SSID {:?}",
                wifi.name.as_deref().unwrap_or(&wifi.ssid),
                wifi.ssid
            ),
            risk: OperationRisk::Connectivity,
            target: wifi.selector.as_ref().map(selector_summary),
        });
    }
    for (index, action) in config.wifi_actions.iter().enumerate() {
        let (name, capability, summary, risk, selector) = match action {
            WifiAction::Scan { selector } => (
                "scan",
                "wifi.scan",
                "Scan for available Wi-Fi networks".into(),
                OperationRisk::ReadOnly,
                selector.as_ref(),
            ),
            WifiAction::Connect { selector, profile } => (
                "connect",
                "wifi.connect",
                format!("Connect using Wi-Fi profile {profile:?}"),
                OperationRisk::Connectivity,
                selector.as_ref(),
            ),
            WifiAction::Disconnect { selector } => (
                "disconnect",
                "wifi.disconnect",
                "Disconnect Wi-Fi interface".into(),
                OperationRisk::Connectivity,
                selector.as_ref(),
            ),
        };
        operations.push(Operation {
            id: format!("wifi.action.{index}.{name}"),
            capability: capability.into(),
            summary,
            risk,
            target: selector.map(selector_summary),
        });
    }
    for (index, service) in config.services.iter().enumerate() {
        operations.push(Operation {
            id: format!("service.{index}.state"),
            capability: "service.apply".into(),
            summary: format!(
                "{} Windows service {:?}",
                match service.state {
                    ServiceState::Running => "Start",
                    ServiceState::Stopped => "Stop",
                },
                service.name
            ),
            risk: OperationRisk::Low,
            target: Some(service.name.clone()),
        });
    }
    for (index, account) in config
        .smb
        .accounts
        .iter()
        .enumerate()
        .filter(|(_, account)| account.kind == crate::config::SmbAccountKind::Local)
    {
        operations.push(Operation {
            id: format!("smb.account.{index}"),
            capability: "smb.account.apply".into(),
            summary: format!(
                "Ensure SMB account {:?} for user {:?}",
                account.id, account.username
            ),
            risk: OperationRisk::Low,
            target: Some(account.id.clone()),
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
    if let Some(firewall) = &config.firewall {
        operations.push(Operation {
            id: "firewall.enabled".into(),
            capability: "firewall.apply".into(),
            summary: if firewall.enabled {
                "Enable Windows firewall"
            } else {
                "Disable Windows firewall"
            }
            .into(),
            risk: OperationRisk::Low,
            target: None,
        });
    }
    for (index, driver) in config.drivers.iter().enumerate() {
        let (name, capability, summary, target) = match driver {
            DriverOperation::Install {
                inf_path,
                hardware_id,
                force,
                restart,
            } => (
                "install",
                if *force {
                    "driver.force_install"
                } else {
                    "driver.install"
                },
                format!("Install driver INF {inf_path:?} (force: {force}, restart: {restart:?})"),
                hardware_id.clone(),
            ),
            DriverOperation::RestartAdapter { selector } => (
                "restart_adapter",
                "adapter.restart",
                "Restart network adapter".into(),
                Some(selector_summary(selector)),
            ),
        };
        operations.push(Operation {
            id: format!("driver.{index}.{name}"),
            capability: capability.into(),
            summary,
            risk: OperationRisk::Destructive,
            target,
        });
    }
    push_hooks(config, HookStage::AfterApply, &mut operations);
    push_hooks(config, HookStage::AfterRollback, &mut operations);
    operations
}

fn push_adapter_state(index: usize, enabled: bool, target: &str, operations: &mut Vec<Operation>) {
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
        target: Some(target.to_owned()),
    });
}

fn push_hooks(config: &NetplanConfig, stage: HookStage, operations: &mut Vec<Operation>) {
    for (index, hook) in config
        .hooks
        .iter()
        .enumerate()
        .filter(|(_, hook)| hook.stage == stage)
    {
        let stage_name = match stage {
            HookStage::BeforeApply => "before_apply",
            HookStage::AfterApply => "after_apply",
            HookStage::AfterRollback => "after_rollback",
        };
        operations.push(Operation {
            id: format!("hook.{index}.{stage_name}"),
            capability: "hook.execute".into(),
            summary: format!("Execute {:?} at {stage:?}", hook.program),
            risk: OperationRisk::Destructive,
            target: None,
        });
    }
}

fn selector_summary(selector: &crate::config::InterfaceSelector) -> String {
    let mut parts = Vec::new();
    if let Some(index) = selector.if_index {
        parts.push(format!("if_index={index}"));
    }
    if let Some(name) = &selector.name {
        parts.push(format!("name={name:?}"));
    }
    if let Some(guid) = &selector.guid {
        parts.push(format!("guid={guid}"));
    }
    if let Some(mac) = &selector.mac_address {
        parts.push(format!("mac={mac}"));
    }
    if let Some(value) = &selector.description_contains {
        parts.push(format!("description~={value:?}"));
    }
    parts.join(", ")
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

    #[test]
    fn planner_configures_ipv4_before_disabling_an_adapter() {
        let config = NetplanConfig::parse(
            br#"{
              "version": 1,
              "adapters": [{
                "selector": {"if_index": 7},
                "enabled": false,
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
        assert_eq!(ids, ["adapter.0.ipv4", "adapter.0.enabled"]);
    }

    #[test]
    fn planner_covers_every_porting_capability_in_execution_order() {
        let config = NetplanConfig::parse(
            br"
version: 1
identity: { computer_name: PE-LAB }
adapters:
  - selector: { if_index: 7 }
    enabled: true
    mac_address: 02-11-22-33-44-55
    ipv4: { mode: dhcp }
wifi:
  - { name: lab, ssid: Lab, authentication: open }
wifi_actions:
  - { action: scan }
  - { action: connect, profile: lab }
  - { action: disconnect }
smb:
  accounts:
    - { id: lab, kind: local, username: lab-user }
  shares:
    - { name: lab, path: 'X:\lab', accounts: [lab] }
  mappings:
    - { remote: '\\server\share', account: lab }
firewall: { enabled: true }
services:
  - { name: LanmanServer, state: running }
drivers:
  - { action: install, inf_path: 'X:\drivers\net.inf' }
  - { action: restart_adapter, selector: { if_index: 7 } }
hooks:
  - { stage: before_apply, program: 'X:\before.exe' }
  - { stage: after_apply, program: 'X:\after.exe' }
  - { stage: after_rollback, program: 'X:\rollback.exe' }
",
            ConfigFormat::Yaml,
        );
        assert!(config.is_ok(), "{config:?}");
        let Some(config) = config.ok() else {
            panic!("configuration should parse");
        };
        let ids: Vec<_> = build_plan(&config).into_iter().map(|op| op.id).collect();
        assert_eq!(
            ids,
            [
                "hook.0.before_apply",
                "identity.computer_name",
                "adapter.0.enabled",
                "adapter.0.mac",
                "adapter.0.ipv4",
                "wifi.profile.0",
                "wifi.action.0.scan",
                "wifi.action.1.connect",
                "wifi.action.2.disconnect",
                "service.0.state",
                "smb.account.0",
                "smb.share.0",
                "smb.mapping.0",
                "firewall.enabled",
                "driver.0.install",
                "driver.1.restart_adapter",
                "hook.1.after_apply",
                "hook.2.after_rollback",
            ]
        );
    }
}
