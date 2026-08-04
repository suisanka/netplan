# SDK and native integration

English | [简体中文](zh-CN/INTEGRATION.md)

## Rust

The `netplan` crate owns the configuration model, planner, verified protocol codec, and
async daemon client:

```rust,no_run
use netplan::Client;
use netplan::protocol::{Request, Response};

# async fn example() -> netplan::Result<()> {
let client = Client::default();
let response = client.call(&Request::Ping).await?;
assert!(matches!(response, Response::Pong { .. }));
# Ok(())
# }
```

`Client::call` assigns and verifies correlation identifiers. `Client::call_frame` is
the lower-level entry point for already encoded size-prefixed frames.

An apply response can be `running`. Keep its `job_id` and call
`Request::JobStatus { job_id }` until it reaches `succeeded`, `failed`, or
`rolled_back`. `Request::ListJobs { state, limit }` returns newest-first summaries,
including creation/update timestamps, and `Request::DaemonStatus` reports uptime and
per-state counters. Jobs are daemon-memory state and do not survive a daemon restart.

Read-only runtime queries use `Request::NetworkStatus`,
`Request::WifiStatus { if_index }`, and
`Request::WifiScan { if_index, refresh, timeout_ms }`. `NetworkStatus` preserves adapter
state even if the optional Native Wi-Fi component is unavailable. A Wi-Fi scan response
contains `refreshed` plus a sorted network list; `false` means cached results were read
without observing a scan-complete notification.

The default endpoint is `\\.\pipe\pe-netplan-netpland-v1` on Windows. Tests and Unix
development use `/tmp/pe-netplan-netpland-v1.sock`. `NETPLAN_ENDPOINT` overrides the
default for either client.

## C ABI

Include `include/netplan.h`, load `netplan.dll`, and follow this ownership sequence:

1. Call `netplan_client_create`; pass `NULL` to select the default endpoint.
2. Build a size-prefixed `Envelope` from `schemas/ipc.fbs` with file identifier `PNET`.
3. Call `netplan_client_call`.
4. Decode the verified response envelope and correlate `request_id`.
5. Release the returned allocation exactly once with `netplan_buffer_free`.
6. Destroy the client exactly once with `netplan_client_destroy`.

`netplan_client_call` returning `NETPLAN_OK` means a verified response frame was
received. The frame may contain a typed `ErrorResponse`; daemon application errors are
data in the protocol rather than transport failures. Use `netplan_client_last_error`
after a nonzero C status.

The ABI version is returned by `netplan_abi_version`. All pointers and lengths are
validated at the Rust boundary, but ownership violations by a C caller remain undefined
behavior as documented in the header.

## Daemon protocol

- Local transport only: Windows named pipe or Unix-domain development socket.
- The Windows endpoint is administrator-only and rejects remote clients.
- Little-endian, size-prefixed FlatBuffers envelope.
- File identifier: `PNET`.
- Protocol version: `1`.
- Maximum frame body: 16 MiB.
- One request and one correlated response per connection.
- Status and job listing are native FlatBuffers calls; the daemon still does not parse
  JSON-RPC.

The v1 additions append union discriminators after the existing `ErrorResponse` value.
Existing discriminator values 0 through 13 remain unchanged; network/Wi-Fi status and
scan messages occupy the appended values 18 through 23.

The checked-in Rust bindings were generated with `flatc` 25.12.19:

```console
flatc --rust --gen-object-api --gen-name-strings -o crates/netplan/src/protocol schemas/ipc.fbs
```

The generated module intentionally carries lint exemptions plus `extern crate alloc`
at the file, namespace, and inner-module scopes. The compiler does not reproduce those
local header adjustments, so regeneration must preserve them and pass both native and
Windows-target Clippy checks.

## Windows runtime

The `x86_64-pc-windows-msvc` configuration uses VC-LTL5 `5.3.1`, whose link search
paths replace the MSVC runtime import libraries with the Windows-compatible VC-LTL
variants. VC-LTL is target-gated and is not linked into GNU or non-Windows builds. The
tagged-release workflow validates this target on Windows Server 2022 before publishing
the MSVC archive.

The CLI, daemon, and C DLL select mimalloc `0.1.52` as their Rust global allocator on
Windows. The SDK crate deliberately leaves allocator selection to its host process.
