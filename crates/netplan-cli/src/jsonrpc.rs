//! Newline-delimited JSON-RPC 2.0 gateway.

use netplan::protocol::{ConfigAction, ErrorCode, Request, Response};
use netplan::{Client, ConfigFormat};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::call_with_autostart;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
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

pub async fn serve(client: Client, no_autostart: bool) -> Result<(), String> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await.map_err(|error| error.to_string())? {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Result<RpcRequest, _> = serde_json::from_str(&line);
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
    let id = rpc.id.clone();
    let notification = id.is_none();
    let id_value = id.unwrap_or(Value::Null);
    if rpc.jsonrpc != "2.0" {
        return (!notification).then(|| error_response(&id_value, -32600, "Invalid Request", None));
    }
    let request = match map_request(&rpc.method, rpc.params) {
        Ok(request) => request,
        Err((code, message, data)) => {
            return (!notification).then(|| error_response(&id_value, code, &message, data));
        }
    };
    let response = call_with_autostart(client, &request, no_autostart).await;
    if notification {
        return None;
    }
    Some(match response {
        Ok(response) => match response_value(response) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id_value, "result": result}),
            Err(message) => error_response(&id_value, -32010, &message, None),
        },
        Err(message) => error_response(&id_value, -32000, &message, None),
    })
}

fn map_request(method: &str, params: Value) -> Result<Request, (i64, String, Option<Value>)> {
    match method {
        "netplan.ping" => no_params(&params).map(|()| Request::Ping),
        "netplan.capabilities" => no_params(&params).map(|()| Request::Capabilities),
        "netplan.adapters.list" => no_params(&params).map(|()| Request::ListAdapters),
        "netplan.config.validate" => config_rpc_request(ConfigAction::Validate, params, true),
        "netplan.config.plan" => config_rpc_request(ConfigAction::Plan, params, true),
        "netplan.config.apply" => config_rpc_request(ConfigAction::Apply, params, true),
        "netplan.job.get" => {
            let params: JobParams = parse_params(params)?;
            Ok(Request::JobStatus {
                job_id: params.job_id,
            })
        }
        _ => Err((-32601, "Method not found".into(), None)),
    }
}

fn no_params(params: &Value) -> Result<(), (i64, String, Option<Value>)> {
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
) -> Result<Request, (i64, String, Option<Value>)> {
    let params: ConfigParams = parse_params(params)?;
    let format = match params.format.as_deref().unwrap_or("auto") {
        "auto" => ConfigFormat::Auto,
        "yaml" | "yml" => ConfigFormat::Yaml,
        "json" => ConfigFormat::Json,
        value => {
            return Err((
                -32602,
                "Invalid params".into(),
                Some(json!(format!("unknown configuration format {value:?}"))),
            ));
        }
    };
    Ok(Request::Config {
        action,
        format,
        document: params.document.into_bytes(),
        dry_run: params.dry_run.unwrap_or(default_dry_run),
    })
}

fn parse_params<T>(params: Value) -> Result<T, (i64, String, Option<Value>)>
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

pub(crate) fn response_value(response: Response) -> Result<Value, String> {
    match response {
        Response::Pong {
            daemon_version,
            protocol_version,
        } => Ok(json!({
            "daemon_version": daemon_version,
            "protocol_version": protocol_version
        })),
        Response::Capabilities(capabilities) => Ok(json!(capabilities)),
        Response::Adapters(adapters) => Ok(json!(adapters)),
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
}
