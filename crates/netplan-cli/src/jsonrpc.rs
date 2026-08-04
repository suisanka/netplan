//! Newline-delimited JSON-RPC 2.0 gateway.

use std::time::Duration;

use netplan::protocol::{ConfigAction, ErrorCode, JobState, Request, Response};
use netplan::{AdapterInfo, Client, ConfigFormat};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::call_with_autostart;

type RpcError = (i64, String, Option<Value>);

const RPC_CONTRACT: &str = include_str!("../../../schemas/jsonrpc.json");

const RPC_METHODS: &[&str] = &[
    "netplan.ping",
    "netplan.daemon.status",
    "netplan.capabilities",
    "netplan.capability.get",
    "netplan.adapters.list",
    "netplan.adapter.get",
    "netplan.status",
    "netplan.wifi.status",
    "netplan.wifi.scan",
    "netplan.config.validate",
    "netplan.config.plan",
    "netplan.config.inspect",
    "netplan.config.apply",
    "netplan.config.describe",
    "netplan.config.example",
    "netplan.job.get",
    "netplan.job.list",
    "netplan.job.wait",
    "netplan.rpc.discover",
];

#[derive(Debug)]
enum RpcCommand {
    Call(Request),
    CapabilityGet {
        name: String,
    },
    AdapterGet(AdapterSelectorParams),
    ConfigInspect {
        document: Vec<u8>,
        format: ConfigFormat,
    },
    ConfigDescribe,
    ConfigExample {
        format: ExampleFormat,
    },
    JobWait(JobWaitParams),
    Discover,
}

#[derive(Clone, Copy, Debug)]
enum ExampleFormat {
    Yaml,
    Json,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcRequest {
    jsonrpc: String,
    #[serde(default, deserialize_with = "deserialize_rpc_id")]
    id: RpcId,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug)]
struct RpcId {
    present: bool,
    value: Value,
}

impl Default for RpcId {
    fn default() -> Self {
        Self {
            present: false,
            value: Value::Null,
        }
    }
}

fn deserialize_rpc_id<'de, D>(deserializer: D) -> Result<RpcId, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(|value| RpcId {
        present: true,
        value,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigParams {
    document: String,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    dry_run: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobParams {
    job_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobListParams {
    #[serde(default)]
    state: Option<JobState>,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobWaitParams {
    job_id: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    interval_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NameParams {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterSelectorParams {
    #[serde(default)]
    if_index: Option<u32>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    guid: Option<String>,
    #[serde(default)]
    mac_address: Option<String>,
    #[serde(default)]
    description_contains: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExampleParams {
    #[serde(default)]
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WifiStatusParams {
    #[serde(default)]
    if_index: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WifiScanParams {
    #[serde(default)]
    if_index: Option<u32>,
    #[serde(default)]
    refresh: Option<bool>,
    #[serde(default)]
    timeout_ms: Option<u32>,
}

pub async fn serve(client: Client, no_autostart: bool) -> Result<(), String> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await.map_err(|error| error.to_string())? {
        let line = line.strip_prefix('\u{feff}').unwrap_or(&line);
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Result<RpcRequest, _> = serde_json::from_str(line);
        let output = match parsed {
            Ok(request) => handle(&client, request, no_autostart).await,
            Err(error) => Some(error_response(
                &Value::Null,
                -32700,
                "Parse error",
                Some(json!(error.to_string())),
            )),
        };
        if let Some(output) = output {
            let mut bytes = serde_json::to_vec(&output).map_err(|error| error.to_string())?;
            bytes.push(b'\n');
            stdout
                .write_all(&bytes)
                .await
                .map_err(|error| error.to_string())?;
            stdout.flush().await.map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

async fn handle(client: &Client, rpc: RpcRequest, no_autostart: bool) -> Option<Value> {
    let notification = !rpc.id.present;
    let id_value = rpc.id.value;
    if !matches!(id_value, Value::Null | Value::String(_) | Value::Number(_)) {
        return Some(error_response(
            &Value::Null,
            -32600,
            "Invalid Request",
            Some(json!("id must be a string, number, or null")),
        ));
    }
    if rpc.jsonrpc != "2.0" {
        return (!notification).then(|| error_response(&id_value, -32600, "Invalid Request", None));
    }
    let command = match map_command(&rpc.method, rpc.params) {
        Ok(command) => command,
        Err((code, message, data)) => {
            return (!notification).then(|| error_response(&id_value, code, &message, data));
        }
    };
    let result = execute_command(client, command, no_autostart).await;
    if notification {
        return None;
    }
    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id_value, "result": result}),
        Err((code, message, data)) => error_response(&id_value, code, &message, data),
    })
}

fn map_command(method: &str, params: Value) -> Result<RpcCommand, RpcError> {
    match method {
        "netplan.capability.get" => {
            let params: NameParams = parse_params(params)?;
            require_non_empty("name", &params.name)?;
            Ok(RpcCommand::CapabilityGet { name: params.name })
        }
        "netplan.adapter.get" => {
            let params: AdapterSelectorParams = parse_params(params)?;
            validate_adapter_selector(&params)?;
            Ok(RpcCommand::AdapterGet(params))
        }
        "netplan.config.inspect" => {
            let params: ConfigParams = parse_params(params)?;
            let format = parse_config_format(params.format.as_deref().unwrap_or("auto"))?;
            Ok(RpcCommand::ConfigInspect {
                document: params.document.into_bytes(),
                format,
            })
        }
        "netplan.config.describe" => {
            no_params(&params)?;
            Ok(RpcCommand::ConfigDescribe)
        }
        "netplan.config.example" => {
            let params: ExampleParams = parse_optional_params(params)?;
            let format = match params.format.as_deref().unwrap_or("yaml") {
                "yaml" | "yml" => ExampleFormat::Yaml,
                "json" => ExampleFormat::Json,
                value => {
                    return Err(invalid_params(format!(
                        "example format must be yaml or json, not {value:?}"
                    )));
                }
            };
            Ok(RpcCommand::ConfigExample { format })
        }
        "netplan.job.wait" => {
            let params: JobWaitParams = parse_params(params)?;
            require_non_empty("job_id", &params.job_id)?;
            validate_range(
                "timeout_ms",
                params.timeout_ms.unwrap_or(30_000),
                1,
                300_000,
            )?;
            validate_range("interval_ms", params.interval_ms.unwrap_or(100), 25, 5_000)?;
            Ok(RpcCommand::JobWait(params))
        }
        "netplan.rpc.discover" => {
            no_params(&params)?;
            Ok(RpcCommand::Discover)
        }
        _ => map_request(method, params).map(RpcCommand::Call),
    }
}

fn map_request(method: &str, params: Value) -> Result<Request, RpcError> {
    match method {
        "netplan.ping" => no_params(&params).map(|()| Request::Ping),
        "netplan.daemon.status" => no_params(&params).map(|()| Request::DaemonStatus),
        "netplan.capabilities" => no_params(&params).map(|()| Request::Capabilities),
        "netplan.adapters.list" => no_params(&params).map(|()| Request::ListAdapters),
        "netplan.status" => no_params(&params).map(|()| Request::NetworkStatus),
        "netplan.wifi.status" => {
            let params: WifiStatusParams = parse_optional_params(params)?;
            Ok(Request::WifiStatus {
                if_index: params.if_index,
            })
        }
        "netplan.wifi.scan" => {
            let params: WifiScanParams = parse_optional_params(params)?;
            let timeout_ms = params.timeout_ms.unwrap_or(4_000);
            validate_range("timeout_ms", u64::from(timeout_ms), 250, 15_000)?;
            Ok(Request::WifiScan {
                if_index: params.if_index,
                refresh: params.refresh.unwrap_or(true),
                timeout_ms,
            })
        }
        "netplan.config.validate" => config_rpc_request(ConfigAction::Validate, params, true),
        "netplan.config.plan" => config_rpc_request(ConfigAction::Plan, params, true),
        "netplan.config.apply" => config_rpc_request(ConfigAction::Apply, params, true),
        "netplan.job.get" => {
            let params: JobParams = parse_params(params)?;
            require_non_empty("job_id", &params.job_id)?;
            Ok(Request::JobStatus {
                job_id: params.job_id,
            })
        }
        "netplan.job.list" => {
            let params: JobListParams = parse_optional_params(params)?;
            let limit = params.limit.unwrap_or(100);
            validate_range("limit", u64::from(limit), 1, 1_000)?;
            Ok(Request::ListJobs {
                state: params.state,
                limit,
            })
        }
        _ => Err((-32601, "Method not found".into(), None)),
    }
}

fn no_params(params: &Value) -> Result<(), RpcError> {
    if params.is_null()
        || params.as_object().is_some_and(serde_json::Map::is_empty)
        || params.as_array().is_some_and(Vec::is_empty)
    {
        Ok(())
    } else {
        Err((
            -32602,
            "Invalid params".into(),
            Some(json!("method accepts no parameters")),
        ))
    }
}

fn config_rpc_request(
    action: ConfigAction,
    params: Value,
    default_dry_run: bool,
) -> Result<Request, RpcError> {
    let params: ConfigParams = parse_params(params)?;
    let format = parse_config_format(params.format.as_deref().unwrap_or("auto"))?;
    Ok(Request::Config {
        action,
        format,
        document: params.document.into_bytes(),
        dry_run: params.dry_run.unwrap_or(default_dry_run),
    })
}

fn parse_config_format(value: &str) -> Result<ConfigFormat, RpcError> {
    Ok(match value {
        "auto" => ConfigFormat::Auto,
        "yaml" | "yml" => ConfigFormat::Yaml,
        "json" => ConfigFormat::Json,
        value => {
            return Err(invalid_params(format!(
                "unknown configuration format {value:?}"
            )));
        }
    })
}

fn parse_params<T>(params: Value) -> Result<T, RpcError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(params).map_err(|error| {
        (
            -32602,
            "Invalid params".into(),
            Some(json!(error.to_string())),
        )
    })
}

fn parse_optional_params<T>(params: Value) -> Result<T, RpcError>
where
    T: for<'de> Deserialize<'de>,
{
    if params.is_null() || params.as_array().is_some_and(Vec::is_empty) {
        parse_params(json!({}))
    } else {
        parse_params(params)
    }
}

fn invalid_params(message: impl Into<String>) -> RpcError {
    (-32602, "Invalid params".into(), Some(json!(message.into())))
}

fn require_non_empty(field: &str, value: &str) -> Result<(), RpcError> {
    if value.trim().is_empty() {
        Err(invalid_params(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn validate_range(field: &str, value: u64, minimum: u64, maximum: u64) -> Result<(), RpcError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(invalid_params(format!(
            "{field} must be between {minimum} and {maximum}"
        )))
    }
}

fn validate_adapter_selector(params: &AdapterSelectorParams) -> Result<(), RpcError> {
    if params.if_index.is_none()
        && params.name.is_none()
        && params.guid.is_none()
        && params.mac_address.is_none()
        && params.description_contains.is_none()
    {
        return Err(invalid_params("at least one adapter selector is required"));
    }
    for (field, value) in [
        ("name", params.name.as_deref()),
        ("guid", params.guid.as_deref()),
        ("mac_address", params.mac_address.as_deref()),
        (
            "description_contains",
            params.description_contains.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            require_non_empty(field, value)?;
        }
    }
    if params
        .mac_address
        .as_deref()
        .is_some_and(|value| normalize_mac(value).is_none())
    {
        return Err(invalid_params(
            "mac_address must contain exactly 12 hexadecimal digits",
        ));
    }
    Ok(())
}

async fn execute_command(
    client: &Client,
    command: RpcCommand,
    no_autostart: bool,
) -> Result<Value, RpcError> {
    match command {
        RpcCommand::Call(request) => {
            let response = call_daemon(client, &request, no_autostart).await?;
            response_rpc_value(response)
        }
        RpcCommand::CapabilityGet { name } => get_capability(client, name, no_autostart).await,
        RpcCommand::AdapterGet(selector) => get_adapter(client, selector, no_autostart).await,
        RpcCommand::ConfigInspect { document, format } => {
            inspect_config(client, document, format, no_autostart).await
        }
        RpcCommand::ConfigDescribe => Ok(config_description()),
        RpcCommand::ConfigExample { format } => Ok(config_example(format)),
        RpcCommand::JobWait(params) => wait_for_job(client, params, no_autostart).await,
        RpcCommand::Discover => rpc_contract(),
    }
}

async fn get_capability(
    client: &Client,
    name: String,
    no_autostart: bool,
) -> Result<Value, RpcError> {
    let response = call_daemon(client, &Request::Capabilities, no_autostart).await?;
    let Response::Capabilities(capabilities) = response else {
        return Err(unexpected_daemon_response(response, "capabilities"));
    };
    capabilities
        .into_iter()
        .find(|capability| capability.name.eq_ignore_ascii_case(&name))
        .map(|capability| json!(capability))
        .ok_or_else(|| {
            (
                -32004,
                "Capability not found".into(),
                Some(json!({"name": name})),
            )
        })
}

async fn get_adapter(
    client: &Client,
    selector: AdapterSelectorParams,
    no_autostart: bool,
) -> Result<Value, RpcError> {
    let response = call_daemon(client, &Request::ListAdapters, no_autostart).await?;
    let Response::Adapters(adapters) = response else {
        return Err(unexpected_daemon_response(response, "adapter inventory"));
    };
    let matches: Vec<_> = adapters
        .into_iter()
        .filter(|adapter| adapter_matches(adapter, &selector))
        .collect();
    match matches.as_slice() {
        [] => Err((
            -32004,
            "Adapter not found".into(),
            Some(json!({"selector": selector_value(&selector)})),
        )),
        [adapter] => Ok(json!(adapter)),
        _ => Err((
            -32009,
            "Adapter selector is ambiguous".into(),
            Some(json!({
                "selector": selector_value(&selector),
                "matches": matches.iter().map(|adapter| json!({
                    "if_index": adapter.if_index,
                    "name": adapter.name,
                    "guid": adapter.guid
                })).collect::<Vec<_>>()
            })),
        )),
    }
}

async fn inspect_config(
    client: &Client,
    document: Vec<u8>,
    format: ConfigFormat,
    no_autostart: bool,
) -> Result<Value, RpcError> {
    let validation = call_daemon(
        client,
        &Request::Config {
            action: ConfigAction::Validate,
            format,
            document: document.clone(),
            dry_run: true,
        },
        no_autostart,
    )
    .await?;
    let Response::Validation { valid, issues } = validation else {
        return Err(unexpected_daemon_response(validation, "validation result"));
    };
    if !valid {
        return Ok(json!({
            "valid": false,
            "issues": issues,
            "operations": [],
            "required_capabilities": []
        }));
    }
    let plan = call_daemon(
        client,
        &Request::Config {
            action: ConfigAction::Plan,
            format,
            document,
            dry_run: true,
        },
        no_autostart,
    )
    .await?;
    let Response::Plan(operations) = plan else {
        return Err(unexpected_daemon_response(plan, "configuration plan"));
    };
    let required_capabilities = required_capabilities(&operations);
    Ok(json!({
        "valid": true,
        "issues": issues,
        "operations": operations,
        "required_capabilities": required_capabilities
    }))
}

async fn call_daemon(
    client: &Client,
    request: &Request,
    no_autostart: bool,
) -> Result<Response, RpcError> {
    call_with_autostart(client, request, no_autostart)
        .await
        .map_err(|message| (-32000, message, None))
}

async fn wait_for_job(
    client: &Client,
    params: JobWaitParams,
    no_autostart: bool,
) -> Result<Value, RpcError> {
    let timeout_ms = params.timeout_ms.unwrap_or(30_000);
    let interval = Duration::from_millis(params.interval_ms.unwrap_or(100));
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(job_wait_timeout(&params.job_id, timeout_ms));
        }
        let response = tokio::time::timeout(
            remaining,
            call_daemon(
                client,
                &Request::JobStatus {
                    job_id: params.job_id.clone(),
                },
                no_autostart,
            ),
        )
        .await
        .map_err(|_| job_wait_timeout(&params.job_id, timeout_ms))??;
        match response {
            Response::JobStatus {
                job_id,
                state,
                message,
            } if is_terminal_job_state(state) => {
                return Ok(json!({"job_id": job_id, "state": state, "message": message}));
            }
            Response::JobStatus { .. } => {}
            response => return Err(unexpected_daemon_response(response, "job status")),
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(job_wait_timeout(&params.job_id, timeout_ms));
        }
        tokio::time::sleep(interval.min(remaining)).await;
    }
}

fn job_wait_timeout(job_id: &str, timeout_ms: u64) -> RpcError {
    (
        -32002,
        "Job wait timed out".into(),
        Some(json!({"job_id": job_id, "timeout_ms": timeout_ms})),
    )
}

const fn is_terminal_job_state(state: JobState) -> bool {
    matches!(
        state,
        JobState::Succeeded | JobState::Failed | JobState::RolledBack
    )
}

fn response_rpc_value(response: Response) -> Result<Value, RpcError> {
    match response {
        Response::Error { code, message } => Err(daemon_error(code, message)),
        response => response_value(response).map_err(|message| (-32010, message, None)),
    }
}

fn unexpected_daemon_response(response: Response, expected: &str) -> RpcError {
    match response {
        Response::Error { code, message } => daemon_error(code, message),
        response => (
            -32010,
            "Unexpected daemon response".into(),
            Some(json!({"expected": expected, "received": format!("{response:?}")})),
        ),
    }
}

fn daemon_error(code: ErrorCode, message: String) -> RpcError {
    let rpc_code = if code == ErrorCode::NotFound {
        -32004
    } else {
        -32010
    };
    (
        rpc_code,
        message,
        Some(json!({"daemon_code": error_code_name(code)})),
    )
}

fn adapter_matches(adapter: &AdapterInfo, selector: &AdapterSelectorParams) -> bool {
    selector
        .if_index
        .is_none_or(|if_index| adapter.if_index == if_index)
        && selector
            .name
            .as_deref()
            .is_none_or(|name| adapter.name.eq_ignore_ascii_case(name))
        && selector.guid.as_deref().is_none_or(|guid| {
            adapter
                .guid
                .as_deref()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(guid))
        })
        && selector.mac_address.as_deref().is_none_or(|mac_address| {
            adapter
                .mac_address
                .as_deref()
                .and_then(normalize_mac)
                .zip(normalize_mac(mac_address))
                .is_some_and(|(candidate, expected)| candidate == expected)
        })
        && selector
            .description_contains
            .as_deref()
            .is_none_or(|needle| {
                adapter.description.as_deref().is_some_and(|description| {
                    description.to_lowercase().contains(&needle.to_lowercase())
                })
            })
}

fn normalize_mac(value: &str) -> Option<String> {
    let mut normalized = String::with_capacity(12);
    for character in value.chars() {
        if character.is_ascii_hexdigit() {
            normalized.push(character.to_ascii_lowercase());
        } else if !matches!(character, ':' | '-') {
            return None;
        }
    }
    (normalized.len() == 12).then_some(normalized)
}

fn selector_value(selector: &AdapterSelectorParams) -> Value {
    json!({
        "if_index": selector.if_index,
        "name": selector.name,
        "guid": selector.guid,
        "mac_address": selector.mac_address,
        "description_contains": selector.description_contains
    })
}

fn required_capabilities(operations: &[netplan::Operation]) -> Vec<String> {
    let mut capabilities = Vec::new();
    for operation in operations {
        if !capabilities.contains(&operation.capability) {
            capabilities.push(operation.capability.clone());
        }
    }
    capabilities
}

fn config_description() -> Value {
    json!({
        "schema_version": 1,
        "formats": ["auto", "yaml", "json"],
        "apply_dry_run_default": true,
        "selector_fields": ["if_index", "name", "guid", "mac_address", "description_contains"],
        "secret_sources": ["env", "literal"],
        "terminal_job_states": ["succeeded", "failed", "rolled_back"],
        "top_level_sections": [
            "protect", "identity", "adapters", "wifi", "wifi_actions", "smb",
            "firewall", "services", "drivers", "hooks"
        ]
    })
}

fn rpc_contract() -> Result<Value, RpcError> {
    let mut contract: Value = serde_json::from_str(RPC_CONTRACT).map_err(|error| {
        (
            -32010,
            "Bundled JSON-RPC contract is invalid".into(),
            Some(json!(error.to_string())),
        )
    })?;
    {
        let Some(contract) = contract.as_object_mut() else {
            return Err((
                -32010,
                "Bundled JSON-RPC contract is not an object".into(),
                None,
            ));
        };
        contract.insert("gateway_version".into(), json!(env!("CARGO_PKG_VERSION")));
        contract.insert(
            "daemon_protocol_version".into(),
            json!(netplan::PROTOCOL_VERSION),
        );
        contract.insert("config_schema_version".into(), json!(1));
        contract.insert("method_names".into(), json!(RPC_METHODS));
    }
    Ok(contract)
}

fn config_example(format: ExampleFormat) -> Value {
    let (format_name, document) = match format {
        ExampleFormat::Yaml => (
            "yaml",
            "version: 1\nprotect:\n  management_interfaces:\n    - name: REPLACE_WITH_MANAGEMENT_ADAPTER\nadapters:\n  - selector:\n      name: REPLACE_WITH_TARGET_ADAPTER\n    ipv4:\n      mode: dhcp\n      dns_from_dhcp: true\n",
        ),
        ExampleFormat::Json => (
            "json",
            "{\n  \"version\": 1,\n  \"protect\": {\n    \"management_interfaces\": [\n      { \"name\": \"REPLACE_WITH_MANAGEMENT_ADAPTER\" }\n    ]\n  },\n  \"adapters\": [\n    {\n      \"selector\": { \"name\": \"REPLACE_WITH_TARGET_ADAPTER\" },\n      \"ipv4\": { \"mode\": \"dhcp\", \"dns_from_dhcp\": true }\n    }\n  ]\n}\n",
        ),
    };
    json!({
        "format": format_name,
        "document": document,
        "dry_run_recommended": true,
        "note": "Replace both adapter placeholders after inspecting netplan.adapters.list."
    })
}

pub(crate) fn response_value(response: Response) -> Result<Value, String> {
    match response {
        Response::Pong {
            daemon_version,
            protocol_version,
        } => Ok(json!({
            "daemon_version": daemon_version,
            "protocol_version": protocol_version
        })),
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
        } => Ok(json!({
            "daemon_version": daemon_version,
            "protocol_version": protocol_version,
            "started_at_unix_ms": started_at_unix_ms,
            "uptime_ms": uptime_ms,
            "total_jobs": total_jobs,
            "queued_jobs": queued_jobs,
            "running_jobs": running_jobs,
            "succeeded_jobs": succeeded_jobs,
            "failed_jobs": failed_jobs,
            "rolled_back_jobs": rolled_back_jobs
        })),
        Response::Capabilities(capabilities) => Ok(json!(capabilities)),
        Response::Adapters(adapters) => Ok(json!(adapters)),
        Response::NetworkStatus {
            captured_at_unix_ms,
            adapters,
            wifi_interfaces,
            wifi_error,
        } => Ok(json!({
            "captured_at_unix_ms": captured_at_unix_ms,
            "adapters": adapters,
            "wifi_interfaces": wifi_interfaces,
            "wifi_error": wifi_error
        })),
        Response::WifiStatus(interfaces) => Ok(json!({"interfaces": interfaces})),
        Response::WifiNetworks {
            refreshed,
            networks,
        } => Ok(json!({"refreshed": refreshed, "networks": networks})),
        Response::Validation { valid, issues } => Ok(json!({"valid": valid, "issues": issues})),
        Response::Plan(operations) => Ok(json!({"operations": operations})),
        Response::Apply {
            job_id,
            state,
            operations,
        } => Ok(json!({"job_id": job_id, "state": state, "operations": operations})),
        Response::JobStatus {
            job_id,
            state,
            message,
        } => Ok(json!({"job_id": job_id, "state": state, "message": message})),
        Response::Jobs { jobs, total } => Ok(json!({"jobs": jobs, "total": total})),
        Response::Error { code, message } => Err(format!("{}: {message}", error_code_name(code))),
    }
}

fn error_code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidRequest => "invalid_request",
        ErrorCode::InvalidConfig => "invalid_config",
        ErrorCode::Unsupported => "unsupported",
        ErrorCode::PermissionDenied => "permission_denied",
        ErrorCode::NotFound => "not_found",
        ErrorCode::Internal => "internal",
    }
}

fn error_response(id: &Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({"code": code, "message": message});
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_method_maps_to_typed_flatbuffer_request() {
        let request = map_request(
            "netplan.config.plan",
            json!({"document": "version: 1", "format": "yaml"}),
        );
        assert!(matches!(
            request,
            Ok(Request::Config {
                action: ConfigAction::Plan,
                format: ConfigFormat::Yaml,
                dry_run: true,
                ..
            })
        ));
    }

    #[test]
    fn unknown_method_uses_standard_json_rpc_error() {
        assert!(matches!(
            map_request("netplan.nope", Value::Null),
            Err((-32601, _, _))
        ));
    }

    #[test]
    fn daemon_status_maps_to_typed_flatbuffer_request() {
        assert!(matches!(
            map_request("netplan.daemon.status", Value::Null),
            Ok(Request::DaemonStatus)
        ));
    }

    #[test]
    fn status_and_wifi_methods_map_to_typed_flatbuffer_requests() {
        assert!(matches!(
            map_request("netplan.status", Value::Null),
            Ok(Request::NetworkStatus)
        ));
        assert!(matches!(
            map_request("netplan.wifi.status", json!({"if_index": 7})),
            Ok(Request::WifiStatus { if_index: Some(7) })
        ));
        assert!(matches!(
            map_request(
                "netplan.wifi.scan",
                json!({"if_index": 7, "refresh": false, "timeout_ms": 800})
            ),
            Ok(Request::WifiScan {
                if_index: Some(7),
                refresh: false,
                timeout_ms: 800
            })
        ));
        assert!(matches!(
            map_request("netplan.wifi.scan", json!({"timeout_ms": 249})),
            Err((-32602, _, _))
        ));
    }

    #[test]
    fn job_list_validates_filter_and_limit() {
        assert!(matches!(
            map_request("netplan.job.list", json!({"state": "running", "limit": 25})),
            Ok(Request::ListJobs {
                state: Some(JobState::Running),
                limit: 25
            })
        ));
        assert!(matches!(
            map_request("netplan.job.list", json!({"limit": 0})),
            Err((-32602, _, _))
        ));
        assert!(matches!(
            map_request("netplan.job.list", Value::Null),
            Ok(Request::ListJobs {
                state: None,
                limit: 100
            })
        ));
    }

    #[test]
    fn job_get_rejects_an_empty_identifier() {
        assert!(matches!(
            map_request("netplan.job.get", json!({"job_id": "  "})),
            Err((-32602, _, _))
        ));
    }

    #[test]
    fn adapter_selector_is_required_and_matches_all_supplied_fields() {
        assert!(matches!(
            map_command("netplan.adapter.get", json!({})),
            Err((-32602, _, _))
        ));
        assert!(matches!(
            map_command("netplan.adapter.get", json!({"mac_address": "not-a-mac"})),
            Err((-32602, _, _))
        ));
        let adapter = AdapterInfo {
            if_index: 7,
            name: "Ethernet".into(),
            description: Some("Realtek PCIe Controller".into()),
            guid: Some("{ABCDEF00-0000-0000-0000-000000000007}".into()),
            mac_address: Some("02-00-00-00-00-07".into()),
            status: "up".into(),
            hardware: true,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        };
        let selector = AdapterSelectorParams {
            if_index: Some(7),
            name: Some("ethernet".into()),
            guid: None,
            mac_address: Some("02:00:00:00:00:07".into()),
            description_contains: Some("PCIE".into()),
        };
        assert!(adapter_matches(&adapter, &selector));
        let mismatched = AdapterSelectorParams {
            name: Some("Wi-Fi".into()),
            ..selector
        };
        assert!(!adapter_matches(&adapter, &mismatched));
    }

    #[test]
    fn job_wait_rejects_unbounded_polling_and_recognizes_terminal_states() {
        assert!(matches!(
            map_command(
                "netplan.job.wait",
                json!({"job_id": "job-1", "timeout_ms": 300_001})
            ),
            Err((-32602, _, _))
        ));
        assert!(!is_terminal_job_state(JobState::Queued));
        assert!(!is_terminal_job_state(JobState::Running));
        assert!(is_terminal_job_state(JobState::Succeeded));
        assert!(is_terminal_job_state(JobState::Failed));
        assert!(is_terminal_job_state(JobState::RolledBack));
    }

    #[test]
    fn configuration_examples_are_schema_valid() {
        for (example_format, config_format) in [
            (ExampleFormat::Yaml, ConfigFormat::Yaml),
            (ExampleFormat::Json, ConfigFormat::Json),
        ] {
            let example = config_example(example_format);
            let Some(document) = example.get("document").and_then(Value::as_str) else {
                panic!("example did not contain a document");
            };
            assert!(
                netplan::NetplanConfig::parse(document.as_bytes(), config_format).is_ok(),
                "invalid {config_format:?} example"
            );
        }
    }

    #[test]
    fn required_capabilities_are_unique_and_stable() {
        let operations = vec![
            netplan::Operation {
                id: "one".into(),
                capability: "network.ipv4".into(),
                summary: "first".into(),
                risk: netplan::OperationRisk::Connectivity,
                target: None,
            },
            netplan::Operation {
                id: "two".into(),
                capability: "network.ipv4".into(),
                summary: "second".into(),
                risk: netplan::OperationRisk::Connectivity,
                target: None,
            },
            netplan::Operation {
                id: "three".into(),
                capability: "wifi.profile".into(),
                summary: "third".into(),
                risk: netplan::OperationRisk::Connectivity,
                target: None,
            },
        ];
        assert_eq!(
            required_capabilities(&operations),
            vec!["network.ipv4", "wifi.profile"]
        );
    }

    #[test]
    fn rpc_contract_defines_every_method_and_resolves_every_type_reference() {
        let contract = match rpc_contract() {
            Ok(contract) => contract,
            Err(error) => panic!("bundled contract failed to load: {error:?}"),
        };
        assert_eq!(
            contract.get("gateway_version").and_then(Value::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            contract
                .get("daemon_protocol_version")
                .and_then(Value::as_u64),
            Some(u64::from(netplan::PROTOCOL_VERSION))
        );
        let Some(methods) = contract.get("methods").and_then(Value::as_array) else {
            panic!("contract methods must be an array");
        };
        let method_names = methods
            .iter()
            .map(|method| {
                let Some(name) = method.get("name").and_then(Value::as_str) else {
                    panic!("contract method is missing a string name: {method}");
                };
                assert!(method.get("params_required").is_some());
                assert!(method.get("params").is_some());
                assert!(method.get("result").is_some());
                name
            })
            .collect::<Vec<_>>();
        assert_eq!(method_names, RPC_METHODS);
        assert_eq!(contract.get("method_names"), Some(&json!(RPC_METHODS)));
        assert_local_refs_resolve(&contract, &contract);
    }

    fn assert_local_refs_resolve(root: &Value, value: &Value) {
        match value {
            Value::Object(object) => {
                if let Some(Value::String(reference)) = object.get("$ref") {
                    let Some(pointer) = reference.strip_prefix('#') else {
                        panic!("contract contains a non-local reference: {reference}");
                    };
                    assert!(
                        root.pointer(pointer).is_some(),
                        "unresolved contract reference: {reference}"
                    );
                }
                for child in object.values() {
                    assert_local_refs_resolve(root, child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    assert_local_refs_resolve(root, child);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn explicit_null_id_is_not_a_notification() {
        let parsed: Result<RpcRequest, _> = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": null,
            "method": "netplan.ping"
        }));
        let request = match parsed {
            Ok(request) => request,
            Err(error) => panic!("unexpected JSON-RPC parse failure: {error}"),
        };
        assert!(request.id.present);
        assert!(request.id.value.is_null());
    }

    #[test]
    fn omitted_id_is_a_notification() {
        let parsed: Result<RpcRequest, _> = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "method": "netplan.ping"
        }));
        let request = match parsed {
            Ok(request) => request,
            Err(error) => panic!("unexpected JSON-RPC parse failure: {error}"),
        };
        assert!(!request.id.present);
    }

    #[test]
    fn powershell_utf8_bom_can_be_removed_before_parsing() {
        let line = "\u{feff}{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"netplan.ping\"}";
        let line = line.strip_prefix('\u{feff}').unwrap_or(line);
        let parsed: Result<RpcRequest, _> = serde_json::from_str(line);
        assert!(parsed.is_ok(), "{parsed:?}");
    }
}
