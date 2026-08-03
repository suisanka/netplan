//! `netplan` command-line and JSON-RPC entry point.

#![deny(clippy::expect_used, clippy::unwrap_used)]

mod jsonrpc;

use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use netplan::client::default_endpoint;
use netplan::protocol::{ConfigAction, Request, Response};
use netplan::{Client, ConfigFormat, Error};
use tokio::process::Command;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FormatArg {
    Auto,
    Yaml,
    Json,
}

impl From<FormatArg> for ConfigFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Auto => Self::Auto,
            FormatArg::Yaml => Self::Yaml,
            FormatArg::Json => Self::Json,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "netplan",
    version,
    about = "PE Netplan CLI and JSON-RPC gateway"
)]
struct Args {
    /// Daemon named pipe or Unix-domain socket.
    #[arg(long, global = true, default_value_t = default_endpoint())]
    endpoint: String,
    /// Do not start a sibling `netpland` when the endpoint is absent.
    #[arg(long, global = true)]
    no_autostart: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Probe daemon health and protocol compatibility.
    Ping,
    /// Print platform capability states.
    Capabilities,
    /// List network adapters.
    Adapters,
    /// Validate a YAML or JSON configuration.
    Validate {
        /// Configuration path.
        path: PathBuf,
        /// Override document format.
        #[arg(long, value_enum, default_value = "auto")]
        format: FormatArg,
    },
    /// Build a deterministic operation plan.
    Plan {
        /// Configuration path.
        path: PathBuf,
        /// Override document format.
        #[arg(long, value_enum, default_value = "auto")]
        format: FormatArg,
    },
    /// Submit a configuration job. Dry-run is the safe default.
    Apply {
        /// Configuration path.
        path: PathBuf,
        /// Override document format.
        #[arg(long, value_enum, default_value = "auto")]
        format: FormatArg,
        /// Request live mutation instead of a dry-run.
        #[arg(long)]
        live: bool,
    },
    /// Query an apply job.
    Job {
        /// Job identifier returned by `apply`.
        job_id: String,
    },
    /// Serve newline-delimited JSON-RPC 2.0 over stdin/stdout.
    Rpc,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("netplan: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    let client = Client::new(args.endpoint.clone());
    if matches!(args.command, Commands::Rpc) {
        return jsonrpc::serve(client, args.no_autostart).await;
    }
    let request = match args.command {
        Commands::Ping => Request::Ping,
        Commands::Capabilities => Request::Capabilities,
        Commands::Adapters => Request::ListAdapters,
        Commands::Validate { path, format } => {
            config_request(&path, ConfigAction::Validate, format.into(), true)?
        }
        Commands::Plan { path, format } => {
            config_request(&path, ConfigAction::Plan, format.into(), true)?
        }
        Commands::Apply { path, format, live } => {
            config_request(&path, ConfigAction::Apply, format.into(), !live)?
        }
        Commands::Job { job_id } => Request::JobStatus { job_id },
        Commands::Rpc => return Err("internal command dispatch error".into()),
    };
    let response = call_with_autostart(&client, &request, args.no_autostart).await?;
    let value = jsonrpc::response_value(response)?;
    let rendered = serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn config_request(
    path: &Path,
    action: ConfigAction,
    format: ConfigFormat,
    dry_run: bool,
) -> Result<Request, String> {
    let document = std::fs::read(path)
        .map_err(|error| format!("failed to read configuration {}: {error}", path.display()))?;
    Ok(Request::Config {
        action,
        format,
        document,
        dry_run,
    })
}

pub(crate) async fn call_with_autostart(
    client: &Client,
    request: &Request,
    no_autostart: bool,
) -> Result<Response, String> {
    match client.call(request).await {
        Ok(response) => return Ok(response),
        Err(error) if no_autostart || !is_endpoint_absent(&error) => {
            return Err(error.to_string());
        }
        Err(_) => {}
    }

    spawn_daemon(client.endpoint())?;
    let mut last_error = None;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        match client.call(request).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.map_or_else(
        || "daemon did not create its endpoint".into(),
        |error| format!("daemon did not become ready: {error}"),
    ))
}

fn is_endpoint_absent(error: &Error) -> bool {
    matches!(
        error,
        Error::Io(io_error)
            if matches!(
                io_error.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
            )
    )
}

fn spawn_daemon(endpoint: &str) -> Result<(), String> {
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    let sibling_name = if cfg!(windows) {
        "netpland.exe"
    } else {
        "netpland"
    };
    let sibling = current.with_file_name(sibling_name);
    let program = if sibling.is_file() {
        sibling
    } else {
        PathBuf::from(sibling_name)
    };
    Command::new(program)
        .arg("--endpoint")
        .arg(endpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false)
        .spawn()
        .map_err(|error| format!("failed to start netpland: {error}"))?;
    Ok(())
}
