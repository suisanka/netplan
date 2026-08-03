//! `netpland` daemon entry point.

#![deny(clippy::expect_used, clippy::unwrap_used)]

mod platform;

use std::collections::HashMap;
use std::sync::Arc;

use clap::Parser;
use netplan::client::default_endpoint;
use netplan::protocol::{
    ConfigAction, ErrorCode, JobState, Request, Response, ValidationIssue, decode_request,
    encode_response, read_frame, write_frame,
};
use netplan::{NetplanConfig, build_plan};
use platform::Platform;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "netpland", version, about = "PE Netplan privileged daemon")]
struct Args {
    /// Named pipe on Windows or Unix-domain socket during development.
    #[arg(long, default_value_t = default_endpoint())]
    endpoint: String,
}

#[derive(Clone, Debug)]
struct JobRecord {
    state: JobState,
    message: Option<String>,
}

struct Daemon<P> {
    platform: P,
    jobs: RwLock<HashMap<String, JobRecord>>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let daemon = Arc::new(Daemon {
        platform: platform::current(),
        jobs: RwLock::new(HashMap::new()),
    });
    serve(args.endpoint, daemon).await
}

impl<P: Platform> Daemon<P> {
    async fn dispatch(&self, request: Request) -> Response {
        match request {
            Request::Ping => Response::Pong {
                daemon_version: env!("CARGO_PKG_VERSION").into(),
                protocol_version: netplan::PROTOCOL_VERSION,
            },
            Request::Capabilities => Response::Capabilities(self.platform.capabilities()),
            Request::ListAdapters => match self.platform.adapters() {
                Ok(adapters) => Response::Adapters(adapters),
                Err(error) => Response::Error {
                    code: ErrorCode::Internal,
                    message: error.to_string(),
                },
            },
            Request::Config {
                action,
                format,
                document,
                dry_run,
            } => match NetplanConfig::parse(&document, format) {
                Ok(config) => match action {
                    ConfigAction::Validate => Response::Validation {
                        valid: true,
                        issues: Vec::new(),
                    },
                    ConfigAction::Plan => Response::Plan(build_plan(&config)),
                    ConfigAction::Apply if dry_run => {
                        let job_id = Uuid::new_v4().to_string();
                        let operations = build_plan(&config);
                        self.jobs.write().await.insert(
                            job_id.clone(),
                            JobRecord {
                                state: JobState::Succeeded,
                                message: Some(
                                    "dry-run completed; no system state was changed".into(),
                                ),
                            },
                        );
                        Response::Apply {
                            job_id,
                            state: JobState::Succeeded,
                            operations,
                        }
                    }
                    ConfigAction::Apply => Response::Error {
                        code: ErrorCode::Unsupported,
                        message:
                            "live apply is disabled until protected-interface Windows tests pass"
                                .into(),
                    },
                },
                Err(error) if action == ConfigAction::Validate => Response::Validation {
                    valid: false,
                    issues: vec![ValidationIssue {
                        path: None,
                        message: error.to_string(),
                    }],
                },
                Err(error) => Response::Error {
                    code: ErrorCode::InvalidConfig,
                    message: error.to_string(),
                },
            },
            Request::JobStatus { job_id } => {
                let jobs = self.jobs.read().await;
                match jobs.get(&job_id) {
                    Some(job) => Response::JobStatus {
                        job_id,
                        state: job.state,
                        message: job.message.clone(),
                    },
                    None => Response::Error {
                        code: ErrorCode::NotFound,
                        message: format!("job {job_id:?} does not exist"),
                    },
                }
            }
        }
    }
}

async fn handle_connection<S, P>(mut stream: S, daemon: Arc<Daemon<P>>) -> netplan::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    P: Platform,
{
    let request_bytes = read_frame(&mut stream).await?;
    let request = decode_request(&request_bytes)?;
    let response = daemon.dispatch(request.payload).await;
    let response_bytes = encode_response(request.request_id, &response);
    write_frame(&mut stream, &response_bytes).await
}

#[cfg(unix)]
async fn serve<P: Platform>(endpoint: String, daemon: Arc<Daemon<P>>) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    use std::path::Path;

    use tokio::net::UnixListener;

    let path = Path::new(&endpoint);
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("refusing to replace non-socket endpoint {endpoint:?}"),
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let daemon = Arc::clone(&daemon);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, daemon).await {
                eprintln!("netpland connection error: {error}");
            }
        });
    }
}

#[cfg(windows)]
async fn serve<P: Platform>(endpoint: String, daemon: Arc<Daemon<P>>) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut first = true;
    loop {
        let mut options = ServerOptions::new();
        options
            .reject_remote_clients(true)
            .first_pipe_instance(first);
        let server = options.create(&endpoint)?;
        first = false;
        server.connect().await?;
        let daemon = Arc::clone(&daemon);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(server, daemon).await {
                eprintln!("netpland connection error: {error}");
            }
        });
    }
}

#[cfg(not(any(unix, windows)))]
async fn serve<P: Platform>(_endpoint: String, _daemon: Arc<Daemon<P>>) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "local IPC is unsupported on this platform",
    ))
}
