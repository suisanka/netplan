//! Error types exposed by the SDK.

use thiserror::Error;

/// Result type used by PE Netplan APIs.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by configuration, IPC, and daemon operations.
#[derive(Debug, Error)]
pub enum Error {
    /// A configuration document could not be decoded.
    #[error("invalid {format} configuration: {message}")]
    Decode {
        /// Human-readable format name.
        format: &'static str,
        /// Parser diagnostic.
        message: String,
    },
    /// A decoded configuration violates semantic constraints.
    #[error("configuration validation failed: {0}")]
    Validation(String),
    /// An IPC frame is malformed or violates the protocol.
    #[error("invalid IPC frame: {0}")]
    Protocol(String),
    /// Local IPC failed.
    #[error("IPC I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The daemon rejected a request.
    #[error("daemon error: {0}")]
    Daemon(String),
}
