//! Async `FlatBuffers` client for `netpland`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Error, Result};
use crate::protocol::{
    Frame, Request, Response, decode_response, encode_request, read_frame, write_frame,
};

/// Default Windows named pipe used by `netpland`.
pub const DEFAULT_WINDOWS_ENDPOINT: &str = r"\\.\pipe\pe-netplan-netpland-v1";

/// Default Unix-domain socket used for development and tests.
pub const DEFAULT_UNIX_ENDPOINT: &str = "/tmp/pe-netplan-netpland-v1.sock";

/// Client for the daemon's private `FlatBuffers` endpoint.
#[derive(Clone, Debug)]
pub struct Client {
    endpoint: String,
    next_request_id: Arc<AtomicU64>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(default_endpoint())
    }
}

impl Client {
    /// Create a client for an explicit named pipe or Unix socket path.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Return the configured local endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Send one typed request and await its correlated response.
    ///
    /// # Errors
    ///
    /// Returns an error when the local IPC connection fails, the response is
    /// invalid, or its correlation identifier does not match the request.
    pub async fn call(&self, request: &Request) -> Result<Response> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let encoded = encode_request(request_id, request);
        let response = call_endpoint(&self.endpoint, &encoded).await?;
        let Frame {
            request_id: response_id,
            payload,
        } = decode_response(&response)?;
        if response_id != request_id {
            return Err(Error::Protocol(format!(
                "response id {response_id} does not match request id {request_id}"
            )));
        }
        Ok(payload)
    }

    /// Send an already encoded `FlatBuffers` request.
    ///
    /// The response remains encoded. Both buffers are verified at their respective
    /// SDK boundaries, allowing FFI callers to use the canonical schema directly.
    ///
    /// # Errors
    ///
    /// Returns an error when either frame fails protocol verification or local
    /// IPC cannot complete the call.
    pub async fn call_frame(&self, request: &[u8]) -> Result<Vec<u8>> {
        // Verification also rejects response frames presented as requests.
        crate::protocol::decode_request(request)?;
        let response = call_endpoint(&self.endpoint, request).await?;
        crate::protocol::decode_response(&response)?;
        Ok(response)
    }
}

/// Return the platform default endpoint, honoring `NETPLAN_ENDPOINT` when set.
#[must_use]
pub fn default_endpoint() -> String {
    std::env::var("NETPLAN_ENDPOINT").unwrap_or_else(|_| {
        if cfg!(windows) {
            DEFAULT_WINDOWS_ENDPOINT.into()
        } else {
            DEFAULT_UNIX_ENDPOINT.into()
        }
    })
}

#[cfg(windows)]
async fn call_endpoint(endpoint: &str, encoded: &[u8]) -> Result<Vec<u8>> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut pipe = ClientOptions::new().open(endpoint)?;
    write_frame(&mut pipe, encoded).await?;
    read_frame(&mut pipe).await
}

#[cfg(unix)]
async fn call_endpoint(endpoint: &str, encoded: &[u8]) -> Result<Vec<u8>> {
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(endpoint).await?;
    write_frame(&mut stream, encoded).await?;
    read_frame(&mut stream).await
}

#[cfg(not(any(windows, unix)))]
async fn call_endpoint(_endpoint: &str, _encoded: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "local IPC is unsupported on this platform",
    )))
}
