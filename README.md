# PE Netplan

English | [简体中文](README.zh-CN.md)

PE Netplan is a Rust networking control plane for Windows and modified WinPE images.
Configuration uses one strict schema in either YAML or JSON.

The workspace produces four integration surfaces:

- `netpland.exe`: privileged daemon with local, typed `FlatBuffers` IPC only.
- `netplan.exe`: CLI and newline-delimited JSON-RPC 2.0 gateway.
- `netplan`: Rust SDK crate for direct typed daemon calls.
- `netplan.dll` and `netplan.h`: stable C ABI using raw verified IPC frames.

## Status

Version 0.1 implements strict configuration parsing, deterministic planning, verified
IPC, asynchronous jobs, JSON-RPC, Rust/C SDKs, and capability-gated Windows backends.
Apply is dry-run by default; `--live` enables native changes after validation,
capability preflight, and runtime protected-interface resolution.

Wi-Fi and SMB are capability-gated because PE images may omit their adapters, APIs, or
services. Query `netplan capabilities` instead of assuming a feature exists.

## Build

The pinned toolchain includes both GNU and MSVC Windows targets. Tagged releases gate
and publish both targets. The GNU build is cross-compiled on Linux:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo build --workspace --release --target x86_64-pc-windows-gnu
```

The MSVC build runs on Windows Server 2022 with VC-LTL5 `5.3.1`; VC-LTL is
intentionally target-gated. Both Windows targets select mimalloc `0.1.52` in the three
final delivery surfaces:

```console
cargo build --workspace --release --target x86_64-pc-windows-msvc
```

The Rust SDK does not install a global allocator in downstream applications. Only the
three final PE Netplan delivery surfaces select mimalloc.

## CLI

Start the daemon explicitly, or allow the CLI to start its sibling executable when the
local endpoint is absent:

```console
netpland.exe
netplan.exe ping
netplan.exe capabilities
netplan.exe adapters
netplan.exe status
netplan.exe wifi status
netplan.exe wifi scan
netplan.exe wifi scan --cached
netplan.exe validate examples\lab.yaml
netplan.exe plan examples\lab.yaml
netplan.exe apply examples\dhcp.json
netplan.exe apply examples\dhcp.json --live
netplan.exe job <job-id>
netplan.exe interactive
```

`status` returns one local snapshot containing adapter addresses and current Wi-Fi
connection state; it is not an Internet reachability test. `wifi scan` waits up to four
seconds for the Native Wi-Fi scan-complete notification and then returns the available
network list. Its `refreshed` field is `false` when the cached list was requested or no
completion notification arrived before the timeout. Use `--if-index` to select one
wireless interface and `--timeout-ms` to change the bounded 250–15000 ms wait.

Interactive mode accepts the same subcommands without repeating `netplan.exe`, supports
quoted Windows paths, and exits with `exit` or `quit`.

`apply` is a dry-run unless `--live` is present. Live jobs return immediately in
`running` state and are queried with `job`. Use `protect.management_interfaces` to name
interfaces that must never be modified; the daemon resolves both protected and target
selectors to actual interface indexes before any mutation.

See [lab.yaml](examples/lab.yaml) and [dhcp.json](examples/dhcp.json) for the YAML and
JSON forms of the same schema.

## External integration

Run `netplan rpc` to expose JSON-RPC 2.0 over stdin/stdout. Each input and output is one
JSON object per line:

```json
{"jsonrpc":"2.0","id":1,"method":"netplan.ping"}
{"jsonrpc":"2.0","id":2,"method":"netplan.daemon.status"}
{"jsonrpc":"2.0","id":3,"method":"netplan.job.list","params":{"limit":25}}
{"jsonrpc":"2.0","id":4,"method":"netplan.status"}
{"jsonrpc":"2.0","id":5,"method":"netplan.wifi.scan","params":{"timeout_ms":4000}}
```

The gateway also provides single-capability/adapter lookup, bounded job waiting,
configuration inspection, schema examples, and method discovery. The full method and
parameter contract is documented in [docs/JSONRPC.md](docs/JSONRPC.md).

Rust programs can depend on `crates/netplan` and use `netplan::Client`. Native programs
can include [include/netplan.h](include/netplan.h) and link `netplan.dll`; the C ABI
accepts and returns size-prefixed `PNET` FlatBuffers frames described by
[schemas/ipc.fbs](schemas/ipc.fbs). See [docs/INTEGRATION.md](docs/INTEGRATION.md).

## Safety model

- Only `netpland` owns privileged state changes.
- The Windows named pipe rejects remote clients and grants access only to `SYSTEM` and
  members of Administrators. Run the daemon elevated.
- Frames are bounded to 16 MiB and verified before dispatch.
- Configuration rejects unknown fields and invalid selectors.
- Hook configuration stores an executable and argument array, never shell text.
- Literal secrets are redacted from Rust debug output.
- Reversible live operations are rolled back in reverse order after failure and the job
  reports `rolled_back` only after state verification succeeds.
- Driver installation is explicitly irreversible; use dry-run and a tested image first.
- Missing image components return typed `Unsupported` errors before mutation.

PE Netplan is licensed under the [Mozilla Public License 2.0](LICENSE).

## Documentation

| Topic | English | 简体中文 |
| --- | --- | --- |
| Complete user guide | [User guide](docs/USER_GUIDE.md) | [使用指南](docs/zh-CN/USER_GUIDE.md) |
| JSON-RPC gateway | [JSON-RPC](docs/JSONRPC.md) | [JSON-RPC](docs/zh-CN/JSONRPC.md) |
| Rust SDK, C ABI, and IPC | [Integration](docs/INTEGRATION.md) | [集成指南](docs/zh-CN/INTEGRATION.md) |
| Tagged GitHub releases | [Release guide](docs/RELEASING.md) | [发布指南](docs/zh-CN/RELEASING.md) |
| Implementation and verification matrix | [Porting matrix](docs/PORTING.md) | [移植矩阵](docs/zh-CN/PORTING.md) |
