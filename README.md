# PE Netplan

PE Netplan is a Rust networking control plane for Windows and modified WinPE images.
Configuration uses one strict schema in either YAML or JSON.

The workspace produces four integration surfaces:

- `netpland.exe`: privileged daemon with local, typed `FlatBuffers` IPC only.
- `netplan.exe`: CLI and newline-delimited JSON-RPC 2.0 gateway.
- `netplan`: Rust SDK crate for direct typed daemon calls.
- `netplan.dll` and `netplan.h`: stable C ABI using raw verified IPC frames.

## Status

Version 0.1 implements strict configuration parsing, deterministic planning, verified
IPC, JSON-RPC, Rust/C SDKs, and native Windows adapter discovery. Apply is dry-run by
default. Live mutation deliberately fails closed until protected-interface rollback
tests pass on Windows and representative PE images.

Wi-Fi and SMB are capability-gated because PE images may omit their adapters, APIs, or
services. Query `netplan capabilities` instead of assuming a feature exists.

## Build

The pinned toolchain includes the GNU Windows target:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release --target x86_64-pc-windows-gnu
```

Cross-linking from macOS or Linux also requires a MinGW-w64 toolchain. The Windows
artifacts are written to `target/x86_64-pc-windows-gnu/release/`.

## CLI

Start the daemon explicitly, or allow the CLI to start its sibling executable when the
local endpoint is absent:

```console
netpland.exe
netplan.exe ping
netplan.exe capabilities
netplan.exe adapters
netplan.exe validate examples\lab.yaml
netplan.exe plan examples\lab.yaml
netplan.exe apply examples\dhcp.json
```

`apply` is a dry-run unless `--live` is present. Version 0.1 rejects `--live` before any
mutation. Use `protect.management_interfaces` to name interfaces that future live
backends must never modify.

See [lab.yaml](examples/lab.yaml) and [dhcp.json](examples/dhcp.json) for the YAML and
JSON forms of the same schema.

## External integration

Run `netplan rpc` to expose JSON-RPC 2.0 over stdin/stdout. Each input and output is one
JSON object per line:

```json
{"jsonrpc":"2.0","id":1,"method":"netplan.ping"}
```

The method and parameter contract is documented in [docs/JSONRPC.md](docs/JSONRPC.md).

Rust programs can depend on `crates/netplan` and use `netplan::Client`. Native programs
can include [include/netplan.h](include/netplan.h) and link `netplan.dll`; the C ABI
accepts and returns size-prefixed `PNET` FlatBuffers frames described by
[schemas/ipc.fbs](schemas/ipc.fbs). See [docs/INTEGRATION.md](docs/INTEGRATION.md).

## Safety model

- Only `netpland` owns privileged state changes.
- The named pipe rejects remote clients.
- Frames are bounded to 16 MiB and verified before dispatch.
- Configuration rejects unknown fields and invalid selectors.
- Hook configuration stores an executable and argument array, never shell text.
- Literal secrets are redacted from Rust debug output.
- Missing capabilities and live apply return explicit errors.

PE Netplan is licensed under the [Mozilla Public License 2.0](LICENSE).
