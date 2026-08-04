//! Human-readable and machine-readable one-shot CLI output.

use std::fmt::{Display, Formatter, Write as _};

use netplan::protocol::{ErrorCode, JobState, Response, ValidationIssue};
use netplan::{
    AdapterInfo, Capability, CapabilityState, Operation, OperationRisk, WifiInterfaceStatus,
    WifiNetwork,
};

use crate::jsonrpc;

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
            let rows = jobs
                .into_iter()
                .map(|job| {
                    vec![
                        job.job_id,
                        job_state_name(job.state).into(),
                        job.created_at_unix_ms.to_string(),
                        job.updated_at_unix_ms.to_string(),
                        option_text(job.message.as_deref()),
                    ]
                })
                .collect::<Vec<_>>();
            Ok(format!(
                "{}\n\n{}",
                key_values(
                    "Jobs",
                    &[
                        ("Matching", total.to_string()),
                        ("Displayed", rows.len().to_string()),
                    ],
                ),
                table(
                    &["JOB ID", "STATE", "CREATED MS", "UPDATED MS", "MESSAGE"],
                    &rows,
                    "No jobs matched the query.",
                )
            ))
        }
        Response::Error { code, message } => Err(CliError::daemon(code, message)),
    }
}

fn render_capabilities(capabilities: &[Capability]) -> String {
    let rows = capabilities
        .iter()
        .map(|capability| {
            vec![
                capability.name.clone(),
                capability_state_name(capability.state).into(),
                option_text(capability.reason.as_deref()),
            ]
        })
        .collect::<Vec<_>>();
    format!(
        "Capabilities ({})\n{}",
        capabilities.len(),
        table(
            &["CAPABILITY", "STATE", "DETAILS"],
            &rows,
            "  No capabilities reported.",
        )
    )
}

fn render_adapters(adapters: &[AdapterInfo]) -> String {
    let rows = adapters
        .iter()
        .map(|adapter| {
            vec![
                adapter.if_index.to_string(),
                adapter.name.clone(),
                adapter.status.clone(),
                if adapter.hardware {
                    "physical"
                } else {
                    "virtual"
                }
                .into(),
                option_text(adapter.mac_address.as_deref()),
                format_addresses(adapter),
                option_text(adapter.description.as_deref()),
            ]
        })
        .collect::<Vec<_>>();
    format!(
        "Adapters ({})\n{}",
        adapters.len(),
        table(
            &[
                "INDEX",
                "NAME",
                "STATUS",
                "KIND",
                "MAC",
                "ADDRESSES",
                "DESCRIPTION"
            ],
            &rows,
            "  No adapters reported.",
        )
    )
}

fn render_wifi_interfaces(interfaces: &[WifiInterfaceStatus]) -> String {
    let rows = interfaces
        .iter()
        .map(|interface| {
            vec![
                interface.if_index.to_string(),
                interface.name.clone(),
                interface.state.clone(),
                option_text(interface.ssid.as_deref()),
                interface
                    .signal_quality
                    .map_or_else(|| "-".into(), |signal| format!("{signal}%")),
                wifi_security(
                    interface.security_enabled,
                    interface.authentication.as_deref(),
                    interface.cipher.as_deref(),
                ),
                option_text(interface.profile_name.as_deref()),
                wifi_rates(interface.rx_rate_kbps, interface.tx_rate_kbps),
            ]
        })
        .collect::<Vec<_>>();
    format!(
        "Wi-Fi interfaces ({})\n{}",
        interfaces.len(),
        table(
            &[
                "INDEX", "NAME", "STATE", "SSID", "SIGNAL", "SECURITY", "PROFILE", "RX/TX"
            ],
            &rows,
            "  No Wi-Fi interfaces reported.",
        )
    )
}

fn render_wifi_networks(refreshed: bool, networks: &[WifiNetwork]) -> String {
    let rows = networks
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
            vec![
                network.ssid.clone(),
                format!("{}%", network.signal_quality),
                if network.security_enabled {
                    format!("{}/{}", network.authentication, network.cipher)
                } else {
                    "open".into()
                },
                format!(
                    "{} [{}]",
                    network.interface_name, network.interface_if_index
                ),
                if flags.is_empty() {
                    "-".into()
                } else {
                    flags.join(",")
                },
            ]
        })
        .collect::<Vec<_>>();
    format!(
        "{}\n{}",
        key_values(
            "Wi-Fi networks",
            &[
                ("Scan refreshed", yes_no(refreshed).into()),
                ("Networks", networks.len().to_string()),
            ],
        ),
        table(
            &["SSID", "SIGNAL", "SECURITY", "INTERFACE", "FLAGS"],
            &rows,
            "  No Wi-Fi networks reported.",
        )
    )
}

fn render_validation(valid: bool, issues: &[ValidationIssue]) -> String {
    if valid {
        return key_values(
            "Configuration validation",
            &[("Status", "valid".into()), ("Issues", "0".into())],
        );
    }
    let rows = issues
        .iter()
        .map(|issue| vec![option_text(issue.path.as_deref()), issue.message.clone()])
        .collect::<Vec<_>>();
    format!(
        "{}\n{}",
        key_values(
            "Configuration validation",
            &[
                ("Status", "invalid".into()),
                ("Issues", issues.len().to_string()),
            ],
        ),
        table(&["PATH", "MESSAGE"], &rows, "  No diagnostics reported."),
    )
}

fn render_operations(title: &str, operations: &[Operation]) -> String {
    let rows = operations
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            vec![
                (index + 1).to_string(),
                operation_risk_name(operation.risk).into(),
                operation.capability.clone(),
                option_text(operation.target.as_deref()),
                operation.summary.clone(),
            ]
        })
        .collect::<Vec<_>>();
    format!(
        "{title} ({})\n{}",
        operations.len(),
        table(
            &["#", "RISK", "CAPABILITY", "TARGET", "OPERATION"],
            &rows,
            "  No operations required.",
        )
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
        let _ = write!(
            output,
            "\n  {key:<width$}  {}",
            clean_cell(value),
            width = width
        );
    }
    output
}

fn table(headers: &[&str], rows: &[Vec<String>], empty: &str) -> String {
    if rows.is_empty() {
        return empty.into();
    }
    let mut widths = headers
        .iter()
        .map(|header| header.chars().count())
        .collect::<Vec<_>>();
    for row in rows {
        for (index, value) in row.iter().take(widths.len()).enumerate() {
            widths[index] = widths[index].max(clean_cell(value).chars().count());
        }
    }
    let mut output = String::new();
    push_table_row(
        &mut output,
        &headers.iter().map(ToString::to_string).collect::<Vec<_>>(),
        &widths,
    );
    output.push('\n');
    push_table_row(
        &mut output,
        &widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>(),
        &widths,
    );
    for row in rows {
        output.push('\n');
        push_table_row(&mut output, row, &widths);
    }
    output
}

fn push_table_row(output: &mut String, cells: &[String], widths: &[usize]) {
    for (index, width) in widths.iter().enumerate() {
        if index > 0 {
            output.push_str("  ");
        }
        let cell = cells.get(index).map_or("", String::as_str);
        let cell = clean_cell(cell);
        if index + 1 == widths.len() {
            output.push_str(&cell);
        } else {
            let _ = write!(output, "{cell:<width$}");
        }
    }
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

fn format_addresses(adapter: &AdapterInfo) -> String {
    let addresses = adapter
        .ipv4
        .iter()
        .chain(&adapter.ipv6)
        .map(|address| format!("{}/{}", address.address, address.prefix_length))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        "-".into()
    } else {
        addresses.join(", ")
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
    fn adapter_table_includes_identity_and_addresses() {
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
    fn empty_tables_have_an_explicit_message() {
        assert_eq!(
            render_human(Response::Capabilities(Vec::new())),
            Ok("Capabilities (0)\n  No capabilities reported.".into())
        );
    }
}
