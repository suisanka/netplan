//! Verified `FlatBuffers` IPC encoding and size-prefixed framing.

use flatbuffers::FlatBufferBuilder;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::PROTOCOL_VERSION;
use crate::config::ConfigFormat;
use crate::error::{Error, Result};
use crate::model::{AdapterInfo, Capability, CapabilityState, IpAddressInfo};
use crate::plan::{Operation, OperationRisk};

#[allow(
    clippy::all,
    clippy::expect_used,
    clippy::unwrap_used,
    missing_docs,
    unsafe_code,
    unused_imports
)]
#[rustfmt::skip]
mod ipc_generated;

use ipc_generated::penetplan::ipc as wire;

/// Maximum accepted `FlatBuffers` frame size.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// A decoded request or response with its correlation identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame<T> {
    /// Correlation identifier supplied by the client.
    pub request_id: u64,
    /// Typed payload.
    pub payload: T,
}

/// Configuration operation requested from the daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigAction {
    /// Decode and validate only.
    Validate,
    /// Produce a deterministic operation plan.
    Plan,
    /// Submit an apply job.
    Apply,
}

/// Requests accepted by `netpland`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// Health and version probe.
    Ping,
    /// Query image capabilities.
    Capabilities,
    /// Enumerate network adapters.
    ListAdapters,
    /// Validate, plan, or apply a configuration document.
    Config {
        /// Requested action.
        action: ConfigAction,
        /// Document encoding.
        format: ConfigFormat,
        /// UTF-8 YAML or JSON bytes.
        document: Vec<u8>,
        /// Refuse system mutations when true.
        dry_run: bool,
    },
    /// Get the current state of an apply job.
    JobStatus {
        /// Job identifier returned by an apply request.
        job_id: String,
    },
}

/// Configuration validation diagnostic.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidationIssue {
    /// Optional field path.
    pub path: Option<String>,
    /// Human-readable diagnostic.
    pub message: String,
}

/// Apply job state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Waiting for execution.
    Queued,
    /// Currently running.
    Running,
    /// Completed successfully.
    Succeeded,
    /// Failed without completing.
    Failed,
    /// Failed and restored the captured state.
    RolledBack,
}

/// Stable daemon error code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Request does not match the protocol.
    InvalidRequest,
    /// Configuration is invalid.
    InvalidConfig,
    /// Required capability is unavailable.
    Unsupported,
    /// Caller is not authorized.
    PermissionDenied,
    /// Requested object does not exist.
    NotFound,
    /// Unexpected daemon failure.
    Internal,
}

/// Responses returned by `netpland`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    /// Successful ping.
    Pong {
        /// Daemon package version.
        daemon_version: String,
        /// Daemon protocol version.
        protocol_version: u32,
    },
    /// Platform capability report.
    Capabilities(Vec<Capability>),
    /// Adapter inventory.
    Adapters(Vec<AdapterInfo>),
    /// Configuration validation result.
    Validation {
        /// Whether the document is valid.
        valid: bool,
        /// Diagnostics; empty when valid.
        issues: Vec<ValidationIssue>,
    },
    /// Deterministic plan.
    Plan(Vec<Operation>),
    /// Apply job accepted by the daemon.
    Apply {
        /// Job identifier.
        job_id: String,
        /// Initial job state.
        state: JobState,
        /// Planned operations.
        operations: Vec<Operation>,
    },
    /// Current apply job state.
    JobStatus {
        /// Job identifier.
        job_id: String,
        /// Current state.
        state: JobState,
        /// Optional diagnostic.
        message: Option<String>,
    },
    /// Typed daemon rejection.
    Error {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable diagnostic.
        message: String,
    },
}

/// Encode one request as a size-prefixed `FlatBuffers` frame.
#[must_use]
pub fn encode_request(request_id: u64, request: &Request) -> Vec<u8> {
    let payload = match request {
        Request::Ping => wire::PayloadT::PingRequest(Box::default()),
        Request::Capabilities => wire::PayloadT::CapabilitiesRequest(Box::default()),
        Request::ListAdapters => wire::PayloadT::ListAdaptersRequest(Box::default()),
        Request::Config {
            action,
            format,
            document,
            dry_run,
        } => wire::PayloadT::ConfigRequest(Box::new(wire::ConfigRequestT {
            action: config_action_to_wire(*action),
            format: config_format_to_wire(*format),
            document: document.clone(),
            dry_run: *dry_run,
        })),
        Request::JobStatus { job_id } => {
            wire::PayloadT::JobStatusRequest(Box::new(wire::JobStatusRequestT {
                job_id: job_id.clone(),
            }))
        }
    };
    encode_envelope(request_id, payload)
}

/// Decode and verify one request frame.
///
/// # Errors
///
/// Returns an error when the frame length, file identifier, protocol version,
/// payload type, or typed fields are invalid.
pub fn decode_request(frame: &[u8]) -> Result<Frame<Request>> {
    let envelope = decode_envelope(frame)?;
    let payload = match envelope.payload {
        wire::PayloadT::PingRequest(_) => Request::Ping,
        wire::PayloadT::CapabilitiesRequest(_) => Request::Capabilities,
        wire::PayloadT::ListAdaptersRequest(_) => Request::ListAdapters,
        wire::PayloadT::ConfigRequest(config) => Request::Config {
            action: config_action_from_wire(config.action)?,
            format: config_format_from_wire(config.format)?,
            document: config.document,
            dry_run: config.dry_run,
        },
        wire::PayloadT::JobStatusRequest(request) => Request::JobStatus {
            job_id: request.job_id,
        },
        _ => return Err(Error::Protocol("frame does not contain a request".into())),
    };
    Ok(Frame {
        request_id: envelope.request_id,
        payload,
    })
}

/// Encode one response as a size-prefixed `FlatBuffers` frame.
#[must_use]
pub fn encode_response(request_id: u64, response: &Response) -> Vec<u8> {
    let payload = match response {
        Response::Pong {
            daemon_version,
            protocol_version,
        } => wire::PayloadT::PingResponse(Box::new(wire::PingResponseT {
            daemon_version: daemon_version.clone(),
            protocol_version: *protocol_version,
        })),
        Response::Capabilities(capabilities) => {
            wire::PayloadT::CapabilitiesResponse(Box::new(wire::CapabilitiesResponseT {
                capabilities: capabilities.iter().map(capability_to_wire).collect(),
            }))
        }
        Response::Adapters(adapters) => {
            wire::PayloadT::ListAdaptersResponse(Box::new(wire::ListAdaptersResponseT {
                adapters: adapters.iter().map(adapter_to_wire).collect(),
            }))
        }
        Response::Validation { valid, issues } => {
            wire::PayloadT::ValidateConfigResponse(Box::new(wire::ValidateConfigResponseT {
                valid: *valid,
                issues: issues
                    .iter()
                    .map(|issue| wire::ValidationIssueT {
                        path: issue.path.clone(),
                        message: issue.message.clone(),
                    })
                    .collect(),
            }))
        }
        Response::Plan(operations) => {
            wire::PayloadT::PlanConfigResponse(Box::new(wire::PlanConfigResponseT {
                operations: operations.iter().map(operation_to_wire).collect(),
            }))
        }
        Response::Apply {
            job_id,
            state,
            operations,
        } => wire::PayloadT::ApplyConfigResponse(Box::new(wire::ApplyConfigResponseT {
            job_id: job_id.clone(),
            state: job_state_to_wire(*state),
            operations: operations.iter().map(operation_to_wire).collect(),
        })),
        Response::JobStatus {
            job_id,
            state,
            message,
        } => wire::PayloadT::JobStatusResponse(Box::new(wire::JobStatusResponseT {
            job_id: job_id.clone(),
            state: job_state_to_wire(*state),
            message: message.clone(),
        })),
        Response::Error { code, message } => {
            wire::PayloadT::ErrorResponse(Box::new(wire::ErrorResponseT {
                code: error_code_to_wire(*code),
                message: message.clone(),
            }))
        }
    };
    encode_envelope(request_id, payload)
}

/// Decode and verify one response frame.
///
/// # Errors
///
/// Returns an error when the frame length, file identifier, protocol version,
/// payload type, or typed fields are invalid.
pub fn decode_response(frame: &[u8]) -> Result<Frame<Response>> {
    let envelope = decode_envelope(frame)?;
    let payload = match envelope.payload {
        wire::PayloadT::PingResponse(response) => Response::Pong {
            daemon_version: response.daemon_version,
            protocol_version: response.protocol_version,
        },
        wire::PayloadT::CapabilitiesResponse(response) => Response::Capabilities(
            response
                .capabilities
                .into_iter()
                .map(capability_from_wire)
                .collect::<Result<_>>()?,
        ),
        wire::PayloadT::ListAdaptersResponse(response) => Response::Adapters(
            response
                .adapters
                .into_iter()
                .map(adapter_from_wire)
                .collect(),
        ),
        wire::PayloadT::ValidateConfigResponse(response) => Response::Validation {
            valid: response.valid,
            issues: response
                .issues
                .into_iter()
                .map(|issue| ValidationIssue {
                    path: issue.path,
                    message: issue.message,
                })
                .collect(),
        },
        wire::PayloadT::PlanConfigResponse(response) => Response::Plan(
            response
                .operations
                .into_iter()
                .map(operation_from_wire)
                .collect::<Result<_>>()?,
        ),
        wire::PayloadT::ApplyConfigResponse(response) => Response::Apply {
            job_id: response.job_id,
            state: job_state_from_wire(response.state)?,
            operations: response
                .operations
                .into_iter()
                .map(operation_from_wire)
                .collect::<Result<_>>()?,
        },
        wire::PayloadT::JobStatusResponse(response) => Response::JobStatus {
            job_id: response.job_id,
            state: job_state_from_wire(response.state)?,
            message: response.message,
        },
        wire::PayloadT::ErrorResponse(response) => Response::Error {
            code: error_code_from_wire(response.code)?,
            message: response.message,
        },
        _ => return Err(Error::Protocol("frame does not contain a response".into())),
    };
    Ok(Frame {
        request_id: envelope.request_id,
        payload,
    })
}

/// Read one bounded size-prefixed `FlatBuffers` frame.
///
/// # Errors
///
/// Returns an error when the stream cannot be read or declares a zero-length
/// or oversized frame.
pub async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).await?;
    let body_len = u32::from_le_bytes(prefix) as usize;
    if body_len == 0 || body_len > MAX_FRAME_SIZE {
        return Err(Error::Protocol(format!(
            "frame body length {body_len} exceeds the allowed range"
        )));
    }
    let mut frame = Vec::with_capacity(body_len + prefix.len());
    frame.extend_from_slice(&prefix);
    frame.resize(body_len + prefix.len(), 0);
    reader.read_exact(&mut frame[prefix.len()..]).await?;
    Ok(frame)
}

/// Write one previously encoded frame.
///
/// # Errors
///
/// Returns an error when the frame length is invalid or the stream cannot be
/// written and flushed.
pub async fn write_frame<W>(writer: &mut W, frame: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    validate_frame_length(frame)?;
    writer.write_all(frame).await?;
    writer.flush().await?;
    Ok(())
}

fn encode_envelope(request_id: u64, payload: wire::PayloadT) -> Vec<u8> {
    let mut builder = FlatBufferBuilder::new();
    let envelope = wire::EnvelopeT {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        payload,
    }
    .pack(&mut builder);
    wire::finish_size_prefixed_envelope_buffer(&mut builder, envelope);
    builder.finished_data().to_vec()
}

fn decode_envelope(frame: &[u8]) -> Result<wire::EnvelopeT> {
    validate_frame_length(frame)?;
    if !flatbuffers::buffer_has_identifier(frame, "PNET", true) {
        return Err(Error::Protocol("missing PNET file identifier".into()));
    }
    let envelope = wire::size_prefixed_root_as_envelope(frame)
        .map_err(|error| Error::Protocol(error.to_string()))?
        .unpack();
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(Error::Protocol(format!(
            "unsupported protocol version {}; expected {PROTOCOL_VERSION}",
            envelope.protocol_version
        )));
    }
    Ok(envelope)
}

fn validate_frame_length(frame: &[u8]) -> Result<()> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| Error::Protocol("frame is missing its size prefix".into()))?;
    let body_len = u32::from_le_bytes(prefix) as usize;
    if body_len == 0 || body_len > MAX_FRAME_SIZE || body_len + 4 != frame.len() {
        return Err(Error::Protocol(format!(
            "invalid frame length: declared {body_len}, actual {}",
            frame.len().saturating_sub(4)
        )));
    }
    Ok(())
}

fn config_action_to_wire(value: ConfigAction) -> wire::ConfigAction {
    match value {
        ConfigAction::Validate => wire::ConfigAction::Validate,
        ConfigAction::Plan => wire::ConfigAction::Plan,
        ConfigAction::Apply => wire::ConfigAction::Apply,
    }
}

fn config_action_from_wire(value: wire::ConfigAction) -> Result<ConfigAction> {
    match value {
        wire::ConfigAction::Validate => Ok(ConfigAction::Validate),
        wire::ConfigAction::Plan => Ok(ConfigAction::Plan),
        wire::ConfigAction::Apply => Ok(ConfigAction::Apply),
        _ => Err(Error::Protocol("unknown configuration action".into())),
    }
}

fn config_format_to_wire(value: ConfigFormat) -> wire::ConfigFormat {
    match value {
        ConfigFormat::Auto => wire::ConfigFormat::Auto,
        ConfigFormat::Yaml => wire::ConfigFormat::Yaml,
        ConfigFormat::Json => wire::ConfigFormat::Json,
    }
}

fn config_format_from_wire(value: wire::ConfigFormat) -> Result<ConfigFormat> {
    match value {
        wire::ConfigFormat::Auto => Ok(ConfigFormat::Auto),
        wire::ConfigFormat::Yaml => Ok(ConfigFormat::Yaml),
        wire::ConfigFormat::Json => Ok(ConfigFormat::Json),
        _ => Err(Error::Protocol("unknown configuration format".into())),
    }
}

fn capability_to_wire(value: &Capability) -> wire::CapabilityT {
    wire::CapabilityT {
        name: value.name.clone(),
        state: match value.state {
            CapabilityState::Unavailable => wire::CapabilityState::Unavailable,
            CapabilityState::ReadOnly => wire::CapabilityState::ReadOnly,
            CapabilityState::DryRun => wire::CapabilityState::DryRun,
            CapabilityState::Available => wire::CapabilityState::Available,
        },
        reason: value.reason.clone(),
    }
}

fn capability_from_wire(value: wire::CapabilityT) -> Result<Capability> {
    let state = match value.state {
        wire::CapabilityState::Unavailable => CapabilityState::Unavailable,
        wire::CapabilityState::ReadOnly => CapabilityState::ReadOnly,
        wire::CapabilityState::DryRun => CapabilityState::DryRun,
        wire::CapabilityState::Available => CapabilityState::Available,
        _ => return Err(Error::Protocol("unknown capability state".into())),
    };
    Ok(Capability {
        name: value.name,
        state,
        reason: value.reason,
    })
}

fn adapter_to_wire(value: &AdapterInfo) -> wire::AdapterT {
    wire::AdapterT {
        if_index: value.if_index,
        name: value.name.clone(),
        description: value.description.clone(),
        guid: value.guid.clone(),
        mac_address: value.mac_address.clone(),
        status: Some(value.status.clone()),
        hardware: value.hardware,
        ipv4: Some(value.ipv4.iter().map(ip_address_to_wire).collect()),
        ipv6: Some(value.ipv6.iter().map(ip_address_to_wire).collect()),
    }
}

fn adapter_from_wire(value: wire::AdapterT) -> AdapterInfo {
    AdapterInfo {
        if_index: value.if_index,
        name: value.name,
        description: value.description,
        guid: value.guid,
        mac_address: value.mac_address,
        status: value.status.unwrap_or_else(|| "unknown".into()),
        hardware: value.hardware,
        ipv4: value
            .ipv4
            .unwrap_or_default()
            .into_iter()
            .map(ip_address_from_wire)
            .collect(),
        ipv6: value
            .ipv6
            .unwrap_or_default()
            .into_iter()
            .map(ip_address_from_wire)
            .collect(),
    }
}

fn ip_address_to_wire(value: &IpAddressInfo) -> wire::IpAddressT {
    wire::IpAddressT {
        address: value.address.clone(),
        prefix_length: value.prefix_length,
    }
}

fn ip_address_from_wire(value: wire::IpAddressT) -> IpAddressInfo {
    IpAddressInfo {
        address: value.address,
        prefix_length: value.prefix_length,
    }
}

fn operation_to_wire(value: &Operation) -> wire::OperationT {
    wire::OperationT {
        id: value.id.clone(),
        capability: value.capability.clone(),
        summary: value.summary.clone(),
        risk: match value.risk {
            OperationRisk::ReadOnly => wire::OperationRisk::ReadOnly,
            OperationRisk::Low => wire::OperationRisk::Low,
            OperationRisk::Connectivity => wire::OperationRisk::Connectivity,
            OperationRisk::Destructive => wire::OperationRisk::Destructive,
        },
        target: value.target.clone(),
    }
}

fn operation_from_wire(value: wire::OperationT) -> Result<Operation> {
    let risk = match value.risk {
        wire::OperationRisk::ReadOnly => OperationRisk::ReadOnly,
        wire::OperationRisk::Low => OperationRisk::Low,
        wire::OperationRisk::Connectivity => OperationRisk::Connectivity,
        wire::OperationRisk::Destructive => OperationRisk::Destructive,
        _ => return Err(Error::Protocol("unknown operation risk".into())),
    };
    Ok(Operation {
        id: value.id,
        capability: value.capability,
        summary: value.summary,
        risk,
        target: value.target,
    })
}

fn job_state_to_wire(value: JobState) -> wire::JobState {
    match value {
        JobState::Queued => wire::JobState::Queued,
        JobState::Running => wire::JobState::Running,
        JobState::Succeeded => wire::JobState::Succeeded,
        JobState::Failed => wire::JobState::Failed,
        JobState::RolledBack => wire::JobState::RolledBack,
    }
}

fn job_state_from_wire(value: wire::JobState) -> Result<JobState> {
    match value {
        wire::JobState::Queued => Ok(JobState::Queued),
        wire::JobState::Running => Ok(JobState::Running),
        wire::JobState::Succeeded => Ok(JobState::Succeeded),
        wire::JobState::Failed => Ok(JobState::Failed),
        wire::JobState::RolledBack => Ok(JobState::RolledBack),
        _ => Err(Error::Protocol("unknown job state".into())),
    }
}

fn error_code_to_wire(value: ErrorCode) -> wire::ErrorCode {
    match value {
        ErrorCode::InvalidRequest => wire::ErrorCode::InvalidRequest,
        ErrorCode::InvalidConfig => wire::ErrorCode::InvalidConfig,
        ErrorCode::Unsupported => wire::ErrorCode::Unsupported,
        ErrorCode::PermissionDenied => wire::ErrorCode::PermissionDenied,
        ErrorCode::NotFound => wire::ErrorCode::NotFound,
        ErrorCode::Internal => wire::ErrorCode::Internal,
    }
}

fn error_code_from_wire(value: wire::ErrorCode) -> Result<ErrorCode> {
    match value {
        wire::ErrorCode::InvalidRequest => Ok(ErrorCode::InvalidRequest),
        wire::ErrorCode::InvalidConfig => Ok(ErrorCode::InvalidConfig),
        wire::ErrorCode::Unsupported => Ok(ErrorCode::Unsupported),
        wire::ErrorCode::PermissionDenied => Ok(ErrorCode::PermissionDenied),
        wire::ErrorCode::NotFound => Ok(ErrorCode::NotFound),
        wire::ErrorCode::Internal => Ok(ErrorCode::Internal),
        _ => Err(Error::Protocol("unknown daemon error code".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_is_typed_and_correlated() {
        let request = Request::Config {
            action: ConfigAction::Plan,
            format: ConfigFormat::Yaml,
            document: b"version: 1".to_vec(),
            dry_run: true,
        };
        let encoded = encode_request(42, &request);
        let decoded = decode_request(&encoded);
        assert_eq!(
            decoded.ok(),
            Some(Frame {
                request_id: 42,
                payload: request
            })
        );
    }

    #[test]
    fn response_round_trip_preserves_adapter_data() {
        let response = Response::Adapters(vec![AdapterInfo {
            if_index: 7,
            name: "Ethernet".into(),
            description: Some("Test NIC".into()),
            guid: Some("{00000000-0000-0000-0000-000000000007}".into()),
            mac_address: Some("02-00-00-00-00-07".into()),
            status: "up".into(),
            hardware: true,
            ipv4: vec![IpAddressInfo {
                address: "192.0.2.10".into(),
                prefix_length: 24,
            }],
            ipv6: Vec::new(),
        }]);
        let encoded = encode_response(9, &response);
        let decoded = decode_response(&encoded);
        assert_eq!(decoded.ok().map(|frame| frame.payload), Some(response));
    }

    #[test]
    fn corrupt_identifier_is_rejected_before_dispatch() {
        let mut encoded = encode_request(1, &Request::Ping);
        if encoded.len() > 7 {
            encoded[4..8].fill(0);
        }
        assert!(matches!(decode_request(&encoded), Err(Error::Protocol(_))));
    }

    #[tokio::test]
    async fn frame_reader_rejects_oversized_prefix() {
        let size = u32::try_from(MAX_FRAME_SIZE + 1).unwrap_or(u32::MAX);
        let mut input = &size.to_le_bytes()[..];
        assert!(matches!(
            read_frame(&mut input).await,
            Err(Error::Protocol(_))
        ));
    }
}
