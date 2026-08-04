//! Human-readable and machine-readable one-shot CLI output.

use std::fmt::{Display, Formatter, Write as _};

use netplan::protocol::{ErrorCode, JobState, Response, ValidationIssue};
use netplan::{
    AdapterInfo, Capability, CapabilityState, Operation, OperationRisk, WifiInterfaceStatus,
    WifiNetwork,
};

use crate::jsonrpc;
use crate::service::LifecycleResult;

const HUMAN_OUTPUT_WIDTH: usize = 88;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CliError {
    code: &'static str,
    message: String,
}

impl CliError {
    fn daemon(code: ErrorCode, message: String) -> Self {
        Self {
            code: error_code_name(code),
            message,
        }
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self {
            code: "cli_error",
            message,
        }
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        Self::from(message.to_owned())
    }
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        if self.code == "cli_error" {
            formatter.write_str(&self.message)
        } else {
            write!(formatter, "{}: {}", self.code, self.message)
        }
    }
}

impl OutputFormat {
    pub(crate) const fn from_json(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }
}

pub(crate) fn render(response: Response, format: OutputFormat) -> Result<String, CliError> {
    match format {
        OutputFormat::Human => render_human(response),
        OutputFormat::Json => match response {
            Response::Error { code, message } => Err(CliError::daemon(code, message)),
            response => {
                let value = jsonrpc::response_value(response).map_err(CliError::from)?;
                serde_json::to_string_pretty(&value)
                    .map_err(|error| CliError::from(error.to_string()))
            }
        },
    }
}

pub(crate) fn render_lifecycle(
    result: &LifecycleResult,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Human => Ok(key_values(
            "PE Netplan daemon",
            &[
                ("Action", result.action.into()),
                ("Mode", lifecycle_mode_name(result.mode).into()),
                ("Installed", yes_no(result.installed).into()),
                ("State", result.state.into()),
                ("Details", result.message.clone()),
            ],
        )),
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({
            "action": result.action,
            "mode": result.mode,
            "installed": result.installed,
            "state": result.state,
            "message": result.message
        }))
        .map_err(|error| CliError::from(error.to_string())),
    }
}

pub(crate) fn render_error(error: &CliError, format: OutputFormat) -> String {
    match format {
        OutputFormat::Human => format!("netplan: {error}"),
        OutputFormat::Json => match serde_json::to_string(&serde_json::json!({
            "error": { "code": error.code, "message": error.message }
        })) {
            Ok(rendered) => rendered,
            Err(_) => "{\"error\":{\"message\":\"output serialization failed\"}}".into(),
        },
    }
}

#[allow(clippy::too_many_lines)]
fn render_human(response: Response) -> Result<String, CliError> {
    match response {
        Response::Pong {
            daemon_version,
            protocol_version,
        } => Ok(key_values(
            "PE Netplan daemon is ready",
            &[
                ("Daemon version", daemon_version),
                ("Protocol version", protocol_version.to_string()),
            ],
        )),
        Response::DaemonStatus {
            daemon_version,
            protocol_version,
            started_at_unix_ms,
            uptime_ms,
            total_jobs,
            queued_jobs,
            running_jobs,
            succeeded_jobs,
            failed_jobs,
            rolled_back_jobs,
        } => Ok([
            key_values(
                "Daemon",
                &[
                    ("Version", daemon_version),
                    ("Protocol", protocol_version.to_string()),
                    ("Started (Unix ms)", started_at_unix_ms.to_string()),
                    ("Uptime", format_duration(uptime_ms)),
                ],
            ),
            key_values(
                "Jobs",
                &[
                    ("Total", total_jobs.to_string()),
                    ("Queued", queued_jobs.to_string()),
                    ("Running", running_jobs.to_string()),
                    ("Succeeded", succeeded_jobs.to_string()),
                    ("Failed", failed_jobs.to_string()),
                    ("Rolled back", rolled_back_jobs.to_string()),
                ],
            ),
        ]
        .join("\n\n")),
        Response::Capabilities(capabilities) => Ok(render_capabilities(&capabilities)),
        Response::Adapters(adapters) => Ok(render_adapters(&adapters)),
        Response::NetworkStatus {
            captured_at_unix_ms,
            adapters,
            wifi_interfaces,
            wifi_error,
        } => {
            let mut sections = vec![key_values(
                "Network status",
                &[("Captured (Unix ms)", captured_at_unix_ms.to_string())],
            )];
            sections.push(render_adapters(&adapters));
            sections.push(render_wifi_interfaces(&wifi_interfaces));
            if let Some(error) = wifi_error {
                sections.push(key_values("Wi-Fi warning", &[("Details", error)]));
            }
            Ok(sections.join("\n\n"))
        }
        Response::WifiStatus(interfaces) => Ok(render_wifi_interfaces(&interfaces)),
        Response::WifiNetworks {
            refreshed,
            networks,
        } => Ok(render_wifi_networks(refreshed, &networks)),
        Response::ShutdownAccepted => Ok("PE Netplan daemon is stopping".into()),
        Response::Validation { valid, issues } => Ok(render_validation(valid, &issues)),
        Response::Plan(operations) => Ok(render_operations("Plan", &operations)),
        Response::Apply {
            job_id,
            state,
            operations,
        } => Ok([
            key_values(
                "Apply job accepted",
                &[("Job ID", job_id), ("State", job_state_name(state).into())],
            ),
            render_operations("Planned operations", &operations),
        ]
        .join("\n\n")),
        Response::JobStatus {
            job_id,
            state,
            message,
        } => Ok(key_values(
            "Job status",
            &[
                ("Job ID", job_id),
                ("State", job_state_name(state).into()),
                ("Message", option_text(message.as_deref())),
            ],
        )),
        Response::Jobs { jobs, total } => {
            let displayed = jobs.len();
            let records = jobs
                .into_iter()
                .map(|job| {
                    record(
                        &job.job_id,
                        &[
                            ("State", job_state_name(job.state).into()),
                            ("Created (ms)", job.created_at_unix_ms.to_string()),
                            ("Updated (ms)", job.updated_at_unix_ms.to_string()),
                            ("Message", option_text(job.message.as_deref())),
                        ],
                    )
                })
                .collect();
            Ok(format!(
                "{}\n\n{}",
                key_values(
                    "Jobs",
                    &[
                        ("Matching", total.to_string()),
                        ("Displayed", displayed.to_string()),
                    ],
                ),
                record_list("Job details", records, "No jobs matched the query.")
            ))
        }
        Response::Error { code, message } => Err(CliError::daemon(code, message)),
    }
}

fn render_capabilities(capabilities: &[Capability]) -> String {
    if capabilities.is_empty() {
        return "Capabilities (0)\n  No capabilities reported.".into();
    }
    let name_width = capabilities
        .iter()
        .map(|capability| capability.name.chars().count())
        .max()
        .unwrap_or(0)
        .min(36);
    let mut output = format!("Capabilities ({})", capabilities.len());
    for capability in capabilities {
        let name = clean_cell(&capability.name);
        let _ = write!(
            output,
            "\n  {name:<name_width$}  {}",
            capability_state_name(capability.state)
        );
        if let Some(reason) = capability
            .reason
            .as_deref()
            .filter(|reason| !reason.is_empty())
        {
            push_wrapped_lines(&mut output, reason, "\n    ", "\n    ", 4);
        }
    }
    output
}

fn render_adapters(adapters: &[AdapterInfo]) -> String {
    let records = adapters
        .iter()
        .map(|adapter| {
            record(
                &format!("[{}] {}", adapter.if_index, adapter.name),
                &[
                    ("Status", adapter.status.clone()),
                    (
                        "Kind",
                        if adapter.hardware {
                            "physical"
                        } else {
                            "virtual"
                        }
                        .into(),
                    ),
                    ("MAC", option_text(adapter.mac_address.as_deref())),
                    ("IPv4", format_addresses(&adapter.ipv4)),
                    ("IPv6", format_addresses(&adapter.ipv6)),
                    ("Description", option_text(adapter.description.as_deref())),
                ],
            )
        })
        .collect();
    record_list(
        &format!("Adapters ({})", adapters.len()),
        records,
        "No adapters reported.",
    )
}

fn render_wifi_interfaces(interfaces: &[WifiInterfaceStatus]) -> String {
    let records = interfaces
        .iter()
        .map(|interface| {
            record(
                &format!("[{}] {}", interface.if_index, interface.name),
                &[
                    ("State", interface.state.clone()),
                    ("SSID", option_text(interface.ssid.as_deref())),
                    (
                        "Signal",
                        interface
                            .signal_quality
                            .map_or_else(|| "-".into(), |signal| format!("{signal}%")),
                    ),
                    (
                        "Security",
                        wifi_security(
                            interface.security_enabled,
                            interface.authentication.as_deref(),
                            interface.cipher.as_deref(),
                        ),
                    ),
                    ("Profile", option_text(interface.profile_name.as_deref())),
                    (
                        "RX/TX",
                        wifi_rates(interface.rx_rate_kbps, interface.tx_rate_kbps),
                    ),
                ],
            )
        })
        .collect();
    record_list(
        &format!("Wi-Fi interfaces ({})", interfaces.len()),
        records,
        "No Wi-Fi interfaces reported.",
    )
}

fn render_wifi_networks(refreshed: bool, networks: &[WifiNetwork]) -> String {
    let records = networks
        .iter()
        .map(|network| {
            let mut flags = Vec::new();
            if network.connected {
                flags.push("connected");
            }
            if network.profile_name.is_some() {
                flags.push("saved");
            }
            if !network.connectable {
                flags.push("blocked");
            }
            record(
                if network.ssid.is_empty() {
                    "<hidden network>"
                } else {
                    &network.ssid
                },
                &[
                    ("Signal", format!("{}%", network.signal_quality)),
                    (
                        "Security",
                        if network.security_enabled {
                            format!("{}/{}", network.authentication, network.cipher)
                        } else {
                            "open".into()
                        },
                    ),
                    (
                        "Interface",
                        format!(
                            "{} [{}]",
                            network.interface_name, network.interface_if_index
                        ),
                    ),
                    (
                        "Flags",
                        if flags.is_empty() {
                            "-".into()
                        } else {
                            flags.join(", ")
                        },
                    ),
                ],
            )
        })
        .collect();
    format!(
        "{}\n\n{}",
        key_values(
            "Wi-Fi networks",
            &[
                ("Scan refreshed", yes_no(refreshed).into()),
                ("Networks", networks.len().to_string()),
            ],
        ),
        record_list("Network details", records, "No Wi-Fi networks reported.")
    )
}

fn render_validation(valid: bool, issues: &[ValidationIssue]) -> String {
    if valid {
        return key_values(
            "Configuration validation",
            &[("Status", "valid".into()), ("Issues", "0".into())],
        );
    }
    let records = issues
        .iter()
        .map(|issue| {
            record(
                issue.path.as_deref().unwrap_or("<document>"),
                &[("Message", issue.message.clone())],
            )
        })
        .collect();
    format!(
        "{}\n\n{}",
        key_values(
            "Configuration validation",
            &[
                ("Status", "invalid".into()),
                ("Issues", issues.len().to_string()),
            ],
        ),
        record_list("Diagnostics", records, "No diagnostics reported."),
    )
}

fn render_operations(title: &str, operations: &[Operation]) -> String {
    let records = operations
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            record(
                &format!("{}. {}", index + 1, operation.summary),
                &[
                    ("Risk", operation_risk_name(operation.risk).into()),
                    ("Capability", operation.capability.clone()),
                    ("Target", option_text(operation.target.as_deref())),
                ],
            )
        })
        .collect();
    record_list(
        &format!("{title} ({})", operations.len()),
        records,
        "No operations required.",
    )
}

fn key_values(title: &str, values: &[(&str, String)]) -> String {
    let width = values
        .iter()
        .map(|(key, _)| key.chars().count())
        .max()
        .unwrap_or(0);
    let mut output = String::from(title);
    for (key, value) in values {
        let first_prefix = format!("\n  {key:<width$}  ");
        let continuation = format!("\n  {:width$}  ", "");
        push_wrapped_lines(
            &mut output,
            value,
            &first_prefix,
            &continuation,
            first_prefix.chars().count().saturating_sub(1),
        );
    }
    output
}

fn record(title: &str, values: &[(&str, String)]) -> String {
    let title = wrap_text(&clean_cell(title), HUMAN_OUTPUT_WIDTH.saturating_sub(2)).join("\n");
    key_values(&title, values)
}

fn record_list(title: &str, records: Vec<String>, empty: &str) -> String {
    if records.is_empty() {
        return format!("{title}\n  {empty}");
    }
    let mut output = String::from(title);
    for record in records {
        output.push_str("\n\n");
        for (index, line) in record.lines().enumerate() {
            if index > 0 {
                output.push('\n');
            }
            output.push_str("  ");
            output.push_str(line);
        }
    }
    output
}

fn push_wrapped_lines(
    output: &mut String,
    value: &str,
    first_prefix: &str,
    continuation_prefix: &str,
    prefix_width: usize,
) {
    let line_width = HUMAN_OUTPUT_WIDTH.saturating_sub(prefix_width).max(20);
    let lines = wrap_text(value, line_width);
    for (index, line) in lines.iter().enumerate() {
        output.push_str(if index == 0 {
            first_prefix
        } else {
            continuation_prefix
        });
        output.push_str(line);
    }
}

fn wrap_text(value: &str, width: usize) -> Vec<String> {
    let value = value.replace('\r', "");
    let mut output = Vec::new();
    for source_line in value.split('\n') {
        let mut line = String::new();
        for word in source_line.split_whitespace() {
            let separator = usize::from(!line.is_empty());
            if line.chars().count() + separator + word.chars().count() <= width {
                if separator == 1 {
                    line.push(' ');
                }
                line.push_str(word);
                continue;
            }
            if !line.is_empty() {
                output.push(std::mem::take(&mut line));
            }
            let mut chunk = String::new();
            for character in word.chars() {
                if chunk.chars().count() == width {
                    output.push(std::mem::take(&mut chunk));
                }
                chunk.push(character);
            }
            line = chunk;
        }
        if !line.is_empty() {
            output.push(line);
        } else if source_line.is_empty() {
            output.push(String::new());
        }
    }
    if output.is_empty() {
        output.push("-".into());
    }
    output
}

fn clean_cell(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

fn option_text(value: Option<&str>) -> String {
    value
        .filter(|value| !value.is_empty())
        .unwrap_or("-")
        .into()
}

fn format_addresses(addresses: &[netplan::IpAddressInfo]) -> String {
    let addresses = addresses
        .iter()
        .map(|address| format!("{}/{}", address.address, address.prefix_length))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        "-".into()
    } else {
        addresses.join("\n")
    }
}

fn wifi_security(
    enabled: Option<bool>,
    authentication: Option<&str>,
    cipher: Option<&str>,
) -> String {
    match enabled {
        Some(false) => "open".into(),
        Some(true) => format!(
            "{}/{}",
            authentication.unwrap_or("secured"),
            cipher.unwrap_or("unknown")
        ),
        None => "-".into(),
    }
}

fn wifi_rates(rx_rate_kbps: Option<u32>, tx_rate_kbps: Option<u32>) -> String {
    match (rx_rate_kbps, tx_rate_kbps) {
        (None, None) => "-".into(),
        (rx, tx) => format!(
            "{}/{} kbps",
            rx.map_or_else(|| "-".into(), |value| value.to_string()),
            tx.map_or_else(|| "-".into(), |value| value.to_string())
        ),
    }
}

fn format_duration(milliseconds: u64) -> String {
    if milliseconds < 1_000 {
        return format!("{milliseconds} ms");
    }
    let total_seconds = milliseconds / 1_000;
    let days = total_seconds / 86_400;
    let hours = total_seconds % 86_400 / 3_600;
    let minutes = total_seconds % 3_600 / 60;
    let seconds = total_seconds % 60;
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{seconds}s"));
    }
    parts.join(" ")
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn lifecycle_mode_name(mode: &str) -> &str {
    match mode {
        "windows-service" => "Windows service",
        "background-process" => "Background process",
        _ => mode,
    }
}

const fn capability_state_name(state: CapabilityState) -> &'static str {
    match state {
        CapabilityState::Unavailable => "unavailable",
        CapabilityState::ReadOnly => "read-only",
        CapabilityState::DryRun => "dry-run",
        CapabilityState::Available => "available",
    }
}

const fn job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::RolledBack => "rolled-back",
    }
}

const fn operation_risk_name(risk: OperationRisk) -> &'static str {
    match risk {
        OperationRisk::ReadOnly => "read-only",
        OperationRisk::Low => "low",
        OperationRisk::Connectivity => "connectivity",
        OperationRisk::Destructive => "destructive",
    }
}

const fn error_code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidRequest => "invalid_request",
        ErrorCode::InvalidConfig => "invalid_config",
        ErrorCode::Unsupported => "unsupported",
        ErrorCode::PermissionDenied => "permission_denied",
        ErrorCode::NotFound => "not_found",
        ErrorCode::Internal => "internal",
    }
}

#[cfg(test)]
mod tests {
    use netplan::IpAddressInfo;
    use serde_json::json;

    use super::*;

    #[test]
    fn json_output_preserves_the_existing_machine_shape() {
        let rendered = render(
            Response::Pong {
                daemon_version: "0.1.1".into(),
                protocol_version: 1,
            },
            OutputFormat::Json,
        );
        let value = rendered
            .as_deref()
            .map(serde_json::from_str::<serde_json::Value>);
        assert!(matches!(
            value,
            Ok(Ok(value)) if value == json!({"daemon_version": "0.1.1", "protocol_version": 1})
        ));
    }

    #[test]
    fn human_output_is_readable_and_not_json() {
        let rendered = render(
            Response::Pong {
                daemon_version: "0.1.1".into(),
                protocol_version: 1,
            },
            OutputFormat::Human,
        );
        assert!(matches!(
            rendered,
            Ok(output)
                if output.starts_with("PE Netplan daemon is ready")
                    && output.contains("Daemon version")
                    && !output.trim_start().starts_with('{')
        ));
    }

    #[test]
    fn json_errors_are_machine_readable_and_keep_a_nonempty_message() {
        let rendered = render_error(
            &CliError::from("daemon unavailable".to_owned()),
            OutputFormat::Json,
        );
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&rendered);
        assert!(matches!(
            parsed,
            Ok(value)
                if value["error"]["code"] == "cli_error"
                    && value["error"]["message"] == "daemon unavailable"
        ));
    }

    #[test]
    fn daemon_errors_keep_their_stable_code_in_json_mode() {
        let error = render(
            Response::Error {
                code: ErrorCode::PermissionDenied,
                message: "access denied".into(),
            },
            OutputFormat::Json,
        );
        let Err(error) = error else {
            panic!("daemon rejection was rendered as success");
        };
        let rendered = render_error(&error, OutputFormat::Json);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&rendered);
        assert!(matches!(
            parsed,
            Ok(value)
                if value["error"]["code"] == "permission_denied"
                    && value["error"]["message"] == "access denied"
        ));
    }

    #[test]
    fn adapter_cards_include_identity_and_addresses() {
        let rendered = render_human(Response::Adapters(vec![AdapterInfo {
            if_index: 7,
            name: "Ethernet".into(),
            description: Some("Test adapter".into()),
            guid: None,
            mac_address: Some("02-00-00-00-00-07".into()),
            status: "up".into(),
            hardware: true,
            ipv4: vec![IpAddressInfo {
                address: "192.0.2.7".into(),
                prefix_length: 24,
            }],
            ipv6: Vec::new(),
        }]));
        assert!(matches!(
            rendered,
            Ok(output)
                if output.contains("Adapters (1)")
                    && output.contains("Ethernet")
                    && output.contains("192.0.2.7/24")
                    && output.contains("Test adapter")
        ));
    }

    #[test]
    fn adapter_cards_keep_multiple_ipv6_addresses_inside_the_human_width() {
        let rendered = render_human(Response::Adapters(vec![AdapterInfo {
            if_index: 6,
            name: "Ethernet 2".into(),
            description: Some("Realtek Gaming 2.5GbE Family Controller".into()),
            guid: None,
            mac_address: Some("1C-86-0B-36-8B-31".into()),
            status: "up".into(),
            hardware: true,
            ipv4: vec![IpAddressInfo {
                address: "192.168.1.7".into(),
                prefix_length: 24,
            }],
            ipv6: vec![
                IpAddressInfo {
                    address: "2408:821b:2520:6890:70b:3eb5:3152:542e".into(),
                    prefix_length: 64,
                },
                IpAddressInfo {
                    address: "2408:821b:2520:6890:90f3:f16a:bc15:92f".into(),
                    prefix_length: 128,
                },
                IpAddressInfo {
                    address: "fe80::fdef:20b2:2635:2594".into(),
                    prefix_length: 64,
                },
            ],
        }]));
        let output = rendered.unwrap_or_default();
        assert!(output.contains("\n    IPv4"));
        assert!(output.contains("\n    IPv6"));
        assert!(
            output
                .lines()
                .all(|line| line.chars().count() <= HUMAN_OUTPUT_WIDTH),
            "human output exceeded {HUMAN_OUTPUT_WIDTH} columns:\n{output}"
        );
    }

    #[test]
    fn lifecycle_output_is_readable_and_json_remains_structured() {
        let result = LifecycleResult {
            action: "enable",
            mode: "windows-service",
            installed: true,
            state: "running",
            message: "installed for automatic startup and started".into(),
        };
        let human = render_lifecycle(&result, OutputFormat::Human);
        assert!(
            matches!(human, Ok(output) if output.contains("Windows service") && output.contains("running"))
        );

        let json = render_lifecycle(&result, OutputFormat::Json)
            .ok()
            .and_then(|output| serde_json::from_str::<serde_json::Value>(&output).ok());
        assert!(
            matches!(json, Some(value) if value["action"] == "enable" && value["installed"] == true)
        );
    }

    #[test]
    fn empty_sections_have_an_explicit_message() {
        assert_eq!(
            render_human(Response::Capabilities(Vec::new())),
            Ok("Capabilities (0)\n  No capabilities reported.".into())
        );
    }
}
