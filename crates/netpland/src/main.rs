//! `netpland` daemon entry point.

#![deny(clippy::expect_used, clippy::unwrap_used)]

mod platform;

#[cfg(windows)]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use netplan::client::default_endpoint;
use netplan::protocol::{
    ConfigAction, ErrorCode, JobState, JobSummary, Request, Response, ValidationIssue,
    decode_request, encode_response, read_frame, write_frame,
};
use netplan::{NetplanConfig, build_plan};
use platform::{Platform, PlatformErrorKind};
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
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

struct Daemon<P> {
    platform: Arc<P>,
    jobs: Arc<RwLock<HashMap<String, JobRecord>>>,
    started_at_unix_ms: u64,
    started_at: Instant,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let daemon = Arc::new(Daemon::new(Arc::new(platform::current())));
    serve(args.endpoint, daemon).await
}

impl<P: Platform> Daemon<P> {
    fn new(platform: Arc<P>) -> Self {
        Self {
            platform,
            jobs: Arc::new(RwLock::new(HashMap::new())),
            started_at_unix_ms: now_unix_ms(),
            started_at: Instant::now(),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn dispatch(&self, request: Request) -> Response {
        match request {
            Request::Ping => Response::Pong {
                daemon_version: env!("CARGO_PKG_VERSION").into(),
                protocol_version: netplan::PROTOCOL_VERSION,
            },
            Request::DaemonStatus => self.daemon_status().await,
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
                        let now = now_unix_ms();
                        self.jobs.write().await.insert(
                            job_id.clone(),
                            JobRecord {
                                state: JobState::Succeeded,
                                message: Some(
                                    "dry-run completed; no system state was changed".into(),
                                ),
                                created_at_unix_ms: now,
                                updated_at_unix_ms: now,
                            },
                        );
                        Response::Apply {
                            job_id,
                            state: JobState::Succeeded,
                            operations,
                        }
                    }
                    ConfigAction::Apply => match self.platform.preflight(&config) {
                        Ok(()) => self.apply_live(config).await,
                        Err(error) => Response::Error {
                            code: platform_error_code(error.kind),
                            message: error.message,
                        },
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
            Request::ListJobs { state, limit } => self.list_jobs(state, limit).await,
            Request::NetworkStatus => match self.platform.adapters() {
                Ok(adapters) => match self.platform.wifi_status(None) {
                    Ok(wifi_interfaces) => Response::NetworkStatus {
                        captured_at_unix_ms: now_unix_ms(),
                        adapters,
                        wifi_interfaces,
                        wifi_error: None,
                    },
                    Err(error) => Response::NetworkStatus {
                        captured_at_unix_ms: now_unix_ms(),
                        adapters,
                        wifi_interfaces: Vec::new(),
                        wifi_error: Some(error.message),
                    },
                },
                Err(error) => Response::Error {
                    code: ErrorCode::Internal,
                    message: error.to_string(),
                },
            },
            Request::WifiStatus { if_index } => match self.platform.wifi_status(if_index) {
                Ok(interfaces) => Response::WifiStatus(interfaces),
                Err(error) => platform_error_response(error),
            },
            Request::WifiScan {
                if_index,
                refresh,
                timeout_ms,
            } => {
                if (250..=15_000).contains(&timeout_ms) {
                    self.wifi_scan(if_index, refresh, timeout_ms).await
                } else {
                    Response::Error {
                        code: ErrorCode::InvalidRequest,
                        message: "Wi-Fi scan timeout_ms must be between 250 and 15000".into(),
                    }
                }
            }
        }
    }

    async fn wifi_scan(&self, if_index: Option<u32>, refresh: bool, timeout_ms: u32) -> Response {
        let platform = Arc::clone(&self.platform);
        let result = tokio::task::spawn_blocking(move || {
            platform.wifi_scan(
                if_index,
                refresh,
                std::time::Duration::from_millis(u64::from(timeout_ms)),
            )
        })
        .await;
        match result {
            Ok(Ok((refreshed, networks))) => Response::WifiNetworks {
                refreshed,
                networks,
            },
            Ok(Err(error)) => platform_error_response(error),
            Err(error) => Response::Error {
                code: ErrorCode::Internal,
                message: format!("Wi-Fi scan task failed: {error}"),
            },
        }
    }

    async fn daemon_status(&self) -> Response {
        let jobs = self.jobs.read().await;
        let mut queued_jobs = 0_u32;
        let mut running_jobs = 0_u32;
        let mut succeeded_jobs = 0_u32;
        let mut failed_jobs = 0_u32;
        let mut rolled_back_jobs = 0_u32;
        for job in jobs.values() {
            let counter = match job.state {
                JobState::Queued => &mut queued_jobs,
                JobState::Running => &mut running_jobs,
                JobState::Succeeded => &mut succeeded_jobs,
                JobState::Failed => &mut failed_jobs,
                JobState::RolledBack => &mut rolled_back_jobs,
            };
            *counter = counter.saturating_add(1);
        }
        Response::DaemonStatus {
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: netplan::PROTOCOL_VERSION,
            started_at_unix_ms: self.started_at_unix_ms,
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            total_jobs: u32::try_from(jobs.len()).unwrap_or(u32::MAX),
            queued_jobs,
            running_jobs,
            succeeded_jobs,
            failed_jobs,
            rolled_back_jobs,
        }
    }

    async fn list_jobs(&self, state: Option<JobState>, limit: u32) -> Response {
        let jobs = self.jobs.read().await;
        let mut summaries: Vec<_> = jobs
            .iter()
            .filter(|(_, job)| state.is_none_or(|state| job.state == state))
            .map(|(job_id, job)| JobSummary {
                job_id: job_id.clone(),
                state: job.state,
                message: job.message.clone(),
                created_at_unix_ms: job.created_at_unix_ms,
                updated_at_unix_ms: job.updated_at_unix_ms,
            })
            .collect();
        summaries.sort_by(|left, right| {
            right
                .created_at_unix_ms
                .cmp(&left.created_at_unix_ms)
                .then_with(|| left.job_id.cmp(&right.job_id))
        });
        let total = u32::try_from(summaries.len()).unwrap_or(u32::MAX);
        let limit = if limit == 0 { 100 } else { limit.min(1_000) };
        summaries.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Response::Jobs {
            jobs: summaries,
            total,
        }
    }

    async fn apply_live(&self, config: NetplanConfig) -> Response {
        let job_id = Uuid::new_v4().to_string();
        let operations = build_plan(&config);
        let now = now_unix_ms();
        self.jobs.write().await.insert(
            job_id.clone(),
            JobRecord {
                state: JobState::Running,
                message: Some("live apply is running".into()),
                created_at_unix_ms: now,
                updated_at_unix_ms: now,
            },
        );
        let platform = Arc::clone(&self.platform);
        let jobs = Arc::clone(&self.jobs);
        let background_job_id = job_id.clone();
        tokio::spawn(async move {
            let execution = tokio::task::spawn_blocking(move || platform.apply(&config)).await;
            let (state, message) = match execution {
                Ok(Ok(report)) => (JobState::Succeeded, Some(report.message)),
                Ok(Err(error)) => (
                    if error.rolled_back {
                        JobState::RolledBack
                    } else {
                        JobState::Failed
                    },
                    Some(error.message),
                ),
                Err(error) => (
                    JobState::Failed,
                    Some(format!("platform execution task failed: {error}")),
                ),
            };
            if let Some(job) = jobs.write().await.get_mut(&background_job_id) {
                job.state = state;
                job.message = message;
                job.updated_at_unix_ms = now_unix_ms();
            }
        });
        Response::Apply {
            job_id,
            state: JobState::Running,
            operations,
        }
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

const fn platform_error_code(kind: PlatformErrorKind) -> ErrorCode {
    match kind {
        PlatformErrorKind::InvalidConfig => ErrorCode::InvalidConfig,
        PlatformErrorKind::Unsupported => ErrorCode::Unsupported,
        PlatformErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        PlatformErrorKind::NotFound => ErrorCode::NotFound,
        PlatformErrorKind::Internal => ErrorCode::Internal,
    }
}

fn platform_error_response(error: platform::PlatformError) -> Response {
    Response::Error {
        code: platform_error_code(error.kind),
        message: error.message,
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
struct PipeSecurity {
    descriptor: windows::Win32::Security::PSECURITY_DESCRIPTOR,
    attributes: windows::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl PipeSecurity {
    fn administrators_and_system() -> std::io::Result<Self> {
        use std::mem::size_of;

        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
        use windows::core::{BOOL, PCWSTR};

        let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: The SDDL is NUL-terminated and the output pointer is writable. The returned
        // LocalAlloc allocation remains owned by this wrapper until after pipe creation.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|error| std::io::Error::other(format!("named-pipe ACL failed: {error}")))?;
        let n_length = u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| std::io::Error::other("SECURITY_ATTRIBUTES size exceeds u32"))?;
        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: n_length,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: BOOL(0),
            },
        })
    }

    fn as_raw(&mut self) -> *mut std::ffi::c_void {
        (&raw mut self.attributes).cast()
    }
}

#[cfg(windows)]
impl Drop for PipeSecurity {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};

        if !self.descriptor.0.is_null() {
            // SAFETY: This is the allocation returned by the SDDL conversion function and is
            // released exactly once after all CreateNamedPipe calls have copied the descriptor.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.descriptor.0))) };
        }
    }
}

#[cfg(windows)]
async fn serve<P: Platform>(endpoint: String, daemon: Arc<Daemon<P>>) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut first = true;
    let mut security = PipeSecurity::administrators_and_system()?;
    loop {
        let mut options = ServerOptions::new();
        options
            .reject_remote_clients(true)
            .first_pipe_instance(first);
        // SAFETY: `security` owns a live SECURITY_ATTRIBUTES and security descriptor for the
        // duration of this call. CreateNamedPipe copies the descriptor into the pipe object.
        let server =
            unsafe { options.create_with_security_attributes_raw(&endpoint, security.as_raw())? };
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use netplan::{
        AdapterInfo, Capability, CapabilityState, ConfigFormat, Result, WifiInterfaceStatus,
        WifiNetwork,
    };
    use platform::{ApplyReport, PlatformError, PlatformResult};

    use super::*;

    struct MockPlatform {
        hook_state: CapabilityState,
        apply_result: PlatformResult<ApplyReport>,
        applied: AtomicBool,
    }

    impl Platform for MockPlatform {
        fn capabilities(&self) -> Vec<Capability> {
            vec![Capability {
                name: "hook.execute".into(),
                state: self.hook_state,
                reason: (self.hook_state != CapabilityState::Available)
                    .then(|| "mock hook backend is unavailable".into()),
            }]
        }

        fn adapters(&self) -> Result<Vec<AdapterInfo>> {
            Ok(Vec::new())
        }

        fn apply(&self, _config: &NetplanConfig) -> PlatformResult<ApplyReport> {
            self.applied.store(true, Ordering::SeqCst);
            self.apply_result.clone()
        }
    }

    struct StatusPlatform;

    impl Platform for StatusPlatform {
        fn capabilities(&self) -> Vec<Capability> {
            Vec::new()
        }

        fn adapters(&self) -> Result<Vec<AdapterInfo>> {
            Ok(vec![AdapterInfo {
                if_index: 7,
                name: "Wi-Fi".into(),
                description: None,
                guid: None,
                mac_address: None,
                status: "up".into(),
                hardware: true,
                ipv4: Vec::new(),
                ipv6: Vec::new(),
            }])
        }

        fn wifi_status(&self, _if_index: Option<u32>) -> PlatformResult<Vec<WifiInterfaceStatus>> {
            Ok(vec![WifiInterfaceStatus {
                if_index: 7,
                name: "Wi-Fi".into(),
                guid: None,
                state: "connected".into(),
                profile_name: Some("Lab".into()),
                ssid: Some("Lab".into()),
                ssid_hex: Some("4C6162".into()),
                signal_quality: Some(80),
                security_enabled: Some(true),
                authentication: Some("wpa2_personal".into()),
                cipher: Some("ccmp".into()),
                rx_rate_kbps: Some(100_000),
                tx_rate_kbps: Some(100_000),
            }])
        }

        fn wifi_scan(
            &self,
            _if_index: Option<u32>,
            _refresh: bool,
            _timeout: std::time::Duration,
        ) -> PlatformResult<(bool, Vec<WifiNetwork>)> {
            Ok((
                true,
                vec![WifiNetwork {
                    interface_if_index: 7,
                    interface_name: "Wi-Fi".into(),
                    ssid: "Lab".into(),
                    ssid_hex: "4C6162".into(),
                    profile_name: Some("Lab".into()),
                    signal_quality: 80,
                    security_enabled: true,
                    authentication: "wpa2_personal".into(),
                    cipher: "ccmp".into(),
                    connectable: true,
                    not_connectable_reason: None,
                    connected: true,
                    bss_count: 1,
                }],
            ))
        }

        fn apply(&self, _config: &NetplanConfig) -> PlatformResult<ApplyReport> {
            Ok(ApplyReport {
                message: "unused".into(),
            })
        }
    }

    fn live_hook_request() -> Request {
        Request::Config {
            action: ConfigAction::Apply,
            format: ConfigFormat::Yaml,
            document:
                b"version: 1\nhooks:\n  - stage: before_apply\n    program: 'X:\\\\hook.exe'\n"
                    .to_vec(),
            dry_run: false,
        }
    }

    fn daemon(platform: Arc<MockPlatform>) -> Daemon<MockPlatform> {
        Daemon::new(platform)
    }

    #[tokio::test]
    async fn live_apply_returns_typed_unsupported_before_mutation() {
        let platform = Arc::new(MockPlatform {
            hook_state: CapabilityState::DryRun,
            apply_result: Ok(ApplyReport {
                message: "should not run".into(),
            }),
            applied: AtomicBool::new(false),
        });
        let response = daemon(Arc::clone(&platform))
            .dispatch(live_hook_request())
            .await;
        assert!(matches!(
            response,
            Response::Error {
                code: ErrorCode::Unsupported,
                ..
            }
        ));
        assert!(!platform.applied.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn successful_live_apply_is_recorded_as_a_queryable_job() {
        let platform = Arc::new(MockPlatform {
            hook_state: CapabilityState::Available,
            apply_result: Ok(ApplyReport {
                message: "one operation applied".into(),
            }),
            applied: AtomicBool::new(false),
        });
        let daemon = daemon(Arc::clone(&platform));
        let response = daemon.dispatch(live_hook_request()).await;
        let Response::Apply { job_id, state, .. } = response else {
            panic!("expected apply response");
        };
        assert_eq!(state, JobState::Running);
        let status = wait_for_terminal_job(&daemon, &job_id).await;
        assert!(platform.applied.load(Ordering::SeqCst));
        assert!(matches!(
            status,
            Response::JobStatus {
                state: JobState::Succeeded,
                message: Some(message),
                ..
            } if message == "one operation applied"
        ));
    }

    #[tokio::test]
    async fn rollback_failure_state_is_preserved_in_the_job() {
        let platform = Arc::new(MockPlatform {
            hook_state: CapabilityState::Available,
            apply_result: Err(PlatformError {
                kind: PlatformErrorKind::Internal,
                message: "apply failed; completed mutations were restored".into(),
                rolled_back: true,
            }),
            applied: AtomicBool::new(false),
        });
        let daemon = daemon(platform);
        let response = daemon.dispatch(live_hook_request()).await;
        let Response::Apply { job_id, state, .. } = response else {
            panic!("expected apply response");
        };
        assert_eq!(state, JobState::Running);
        let status = wait_for_terminal_job(&daemon, &job_id).await;
        assert!(matches!(
            status,
            Response::JobStatus {
                state: JobState::RolledBack,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn daemon_status_reports_job_counts() {
        let platform = Arc::new(MockPlatform {
            hook_state: CapabilityState::Available,
            apply_result: Ok(ApplyReport {
                message: "unused".into(),
            }),
            applied: AtomicBool::new(false),
        });
        let daemon = daemon(platform);
        daemon.jobs.write().await.insert(
            "job-1".into(),
            JobRecord {
                state: JobState::Succeeded,
                message: None,
                created_at_unix_ms: 10,
                updated_at_unix_ms: 20,
            },
        );

        let response = daemon.dispatch(Request::DaemonStatus).await;
        assert!(matches!(
            response,
            Response::DaemonStatus {
                total_jobs: 1,
                succeeded_jobs: 1,
                running_jobs: 0,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn job_list_filters_orders_and_limits_results() {
        let platform = Arc::new(MockPlatform {
            hook_state: CapabilityState::Available,
            apply_result: Ok(ApplyReport {
                message: "unused".into(),
            }),
            applied: AtomicBool::new(false),
        });
        let daemon = daemon(platform);
        let mut jobs = daemon.jobs.write().await;
        jobs.insert(
            "older".into(),
            JobRecord {
                state: JobState::Succeeded,
                message: None,
                created_at_unix_ms: 10,
                updated_at_unix_ms: 11,
            },
        );
        jobs.insert(
            "newer".into(),
            JobRecord {
                state: JobState::Succeeded,
                message: Some("done".into()),
                created_at_unix_ms: 20,
                updated_at_unix_ms: 21,
            },
        );
        jobs.insert(
            "failed".into(),
            JobRecord {
                state: JobState::Failed,
                message: Some("failed".into()),
                created_at_unix_ms: 30,
                updated_at_unix_ms: 31,
            },
        );
        drop(jobs);

        let response = daemon
            .dispatch(Request::ListJobs {
                state: Some(JobState::Succeeded),
                limit: 1,
            })
            .await;
        assert!(matches!(
            response,
            Response::Jobs { jobs, total: 2 }
                if jobs.len() == 1 && jobs[0].job_id == "newer"
        ));
    }

    #[tokio::test]
    async fn network_status_combines_adapter_and_wifi_state() {
        let daemon = Daemon::new(Arc::new(StatusPlatform));
        let response = daemon.dispatch(Request::NetworkStatus).await;
        assert!(matches!(
            response,
            Response::NetworkStatus {
                adapters,
                wifi_interfaces,
                wifi_error: None,
                ..
            } if adapters.len() == 1 && wifi_interfaces.len() == 1
        ));
    }

    #[tokio::test]
    async fn wifi_scan_returns_networks_and_validates_timeout() {
        let daemon = Daemon::new(Arc::new(StatusPlatform));
        let response = daemon
            .dispatch(Request::WifiScan {
                if_index: Some(7),
                refresh: true,
                timeout_ms: 4_000,
            })
            .await;
        assert!(matches!(
            response,
            Response::WifiNetworks {
                refreshed: true,
                networks
            } if networks.len() == 1 && networks[0].ssid == "Lab"
        ));

        let invalid = daemon
            .dispatch(Request::WifiScan {
                if_index: None,
                refresh: true,
                timeout_ms: 0,
            })
            .await;
        assert!(matches!(
            invalid,
            Response::Error {
                code: ErrorCode::InvalidRequest,
                ..
            }
        ));
    }

    async fn wait_for_terminal_job(daemon: &Daemon<MockPlatform>, job_id: &str) -> Response {
        let terminal_status = async {
            loop {
                let response = daemon
                    .dispatch(Request::JobStatus {
                        job_id: job_id.to_owned(),
                    })
                    .await;
                if !matches!(
                    response,
                    Response::JobStatus {
                        state: JobState::Running | JobState::Queued,
                        ..
                    }
                ) {
                    return response;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };
        match tokio::time::timeout(std::time::Duration::from_secs(5), terminal_status).await {
            Ok(response) => response,
            Err(error) => {
                panic!(
                    "background apply did not reach a terminal state within five seconds: {error}"
                )
            }
        }
    }
}
