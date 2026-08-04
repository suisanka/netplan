# PE Netplan user guide

English | [简体中文](zh-CN/USER_GUIDE.md)

This guide covers building, deploying, operating, configuring, and integrating PE
Netplan 0.1. It describes the current repository state. There is no installer; tagged
GitHub releases provide GNU and MSVC binary archives.

## 1. What PE Netplan does

PE Netplan is a local Windows networking control plane designed for Windows 11 and
modified Windows PE images. It separates unprivileged input surfaces from privileged
system mutation:

| Component | Role |
| --- | --- |
| `netpland.exe` | Privileged daemon; the only component that mutates Windows state |
| `netplan.exe` | One-shot CLI, interactive CLI, and newline-delimited JSON-RPC gateway |
| `netplan` crate | Typed Rust configuration, planning, protocol, and async client API |
| `netplan.dll` | Low-level C ABI for sending verified FlatBuffers frames |

The daemon accepts only local size-prefixed FlatBuffers. JSON-RPC terminates inside
`netplan.exe`; it is never exposed by the privileged daemon.

Supported configuration areas are adapter state/MAC/IPv4, machine identity, native
Wi-Fi profiles and actions, SMB accounts/shares/mappings, Windows Firewall, services,
driver installation/restart, and shell-free hooks. Availability depends on the APIs,
services, and hardware present in the current Windows or PE image.

## 2. Build and deployment

### 2.1 Prerequisites

- Rust `1.97.1`; `rust-toolchain.toml` selects it automatically through rustup.
- A GNU Windows linker for `x86_64-pc-windows-gnu`, or Visual Studio 2022 Build Tools
  for `x86_64-pc-windows-msvc`.
- `cargo-audit` only when running the optional security gate.
- Administrator rights to run live Windows operations.

The MSVC target pins VC-LTL5 `5.3.1`. Tagged releases run target-level Clippy, tests,
and release builds on Windows Server 2022 before publishing either target.

### 2.2 Build

From the repository root:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo build --workspace --release --target x86_64-pc-windows-gnu
```

The GNU Windows artifacts are written under:

```text
target/x86_64-pc-windows-gnu/release/netpland.exe
target/x86_64-pc-windows-gnu/release/netplan.exe
target/x86_64-pc-windows-gnu/release/netplan.dll
```

Use `x86_64-pc-windows-msvc` in the build command and path for the MSVC/VC-LTL
variant.

For a CLI-only deployment, copy `netpland.exe` and `netplan.exe` into the same
directory. For native integration, also copy `netplan.dll`, `include/netplan.h`, and
`schemas/ipc.fbs`. The C DLL is optional for CLI/JSON-RPC use.

Pushing a version tag automatically gates both Windows targets, creates one ZIP plus
SHA-256 checksum per target, and publishes one GitHub Release. See
[RELEASING.md](RELEASING.md).

### 2.3 PE image requirements

PE Netplan probes features at runtime. A reduced image may need the corresponding
components added before a capability becomes available:

- IP Helper and the networking stack for adapter inventory.
- `netsh.exe` for adapter/IP/firewall changes.
- `wlanapi.dll`, `WlanSvc`, and wireless drivers for Wi-Fi.
- NetAPI/MPR and Server/Workstation services for SMB.
- Service Control Manager for service operations.
- `pnputil.exe`, or `newdev.dll` for forced driver updates.

Always run `netplan capabilities` on the target image. Do not infer support from a
stock Windows installation or a different PE build.

## 3. Start and connect to the daemon

The default Windows endpoint is:

```text
\\.\pipe\pe-netplan-netpland-v1
```

Start the daemon from an elevated terminal:

```console
netpland.exe
```

Then use the CLI from another terminal:

```console
netplan.exe ping
```

The Windows named pipe is local-only, rejects remote pipe clients, and grants access to
`SYSTEM` and Administrators. The CLI does not elevate itself. When the endpoint is
absent, the CLI normally tries to start a sibling `netpland.exe`; this succeeds only if
the caller already has the required rights and the daemon executable is beside the CLI
or available on `PATH`. Use `--no-autostart` when a service manager owns the daemon.

Both processes accept an explicit endpoint:

```console
netpland.exe --endpoint \\.\pipe\pe-netplan-lab
netplan.exe --endpoint \\.\pipe\pe-netplan-lab --no-autostart ping
```

`NETPLAN_ENDPOINT` changes the default endpoint for the CLI, Rust client, and daemon.
An explicit `--endpoint` takes precedence in the executables.

On Unix development hosts the default is
`/tmp/pe-netplan-netpland-v1.sock`. The portable backend supports parsing, planning,
protocol tests, and dry-run behavior; live Windows mutations and native inventory are
unavailable.

## 4. Safe first-run workflow

Use this sequence before any live mutation:

```console
netplan.exe ping
netplan.exe capabilities
netplan.exe adapters
netplan.exe status
netplan.exe validate examples\lab.yaml
netplan.exe plan examples\lab.yaml
netplan.exe apply examples\lab.yaml
```

The final command is still a dry-run. Review its operations and capability requirements,
replace every example selector/path, and protect the adapter carrying RDP, SSH, VPN, or
the tunnel agent. Only then request live apply:

```console
netplan.exe apply C:\PE-Netplan\machine.yaml --live
netplan.exe job <job-id>
```

Live apply is asynchronous and can initially return `running`. Jobs exist only in daemon
memory and disappear when `netpland` restarts.

## 5. CLI reference

One-shot commands print aligned human-readable summaries and tables by default. Add
`--json` for the complete machine-readable response. Errors are written to stderr and
return a nonzero exit code; with `--json`, stderr contains a JSON error object.

### 5.1 Global options

| Option | Meaning |
| --- | --- |
| `--endpoint <ENDPOINT>` | Override the named pipe or development Unix socket |
| `--no-autostart` | Never start a missing sibling daemon |
| `--json` | Print the complete stable JSON response instead of human output |
| `--help`, `--version` | Print command help or version |

Global options may appear before or after a subcommand.

```console
netplan.exe --json status
netplan.exe status --json
```

Both forms are equivalent. `rpc` always uses newline-delimited JSON-RPC regardless of
this option.

Successful JSON output keeps the command-specific shapes documented below. A CLI-level
failure writes this single object to stderr and exits nonzero:

```json
{"error":{"code":"cli_error","message":"diagnostic"}}
```

Typed daemon rejections use their stable code, such as `permission_denied`, instead of
`cli_error`.

### 5.2 Commands

| Command | Behavior |
| --- | --- |
| `ping` | Return daemon and protocol versions |
| `capabilities` | Return every capability with `available`, `read_only`, `dry_run`, or `unavailable` state and an optional reason |
| `adapters` | Return native adapter inventory |
| `status` | Return one timestamped adapter and Wi-Fi state snapshot |
| `wifi status [--if-index N]` | Return current native Wi-Fi interface/link state |
| `wifi scan [--if-index N] [--cached] [--timeout-ms N]` | Request or read nearby networks |
| `validate <PATH> [--format auto|yaml|json]` | Decode and validate a configuration |
| `plan <PATH> [--format auto|yaml|json]` | Produce deterministic ordered operations without mutation |
| `apply <PATH> [--format ...] [--live]` | Submit a dry-run or live job |
| `job <JOB_ID>` | Read one retained job |
| `interactive` | Start a prompt using the same typed requests |
| `rpc` | Serve newline-delimited JSON-RPC 2.0 on stdin/stdout |

`status` is a local state snapshot, not an Internet reachability test. A Wi-Fi status
failure is returned in `wifi_error` without discarding adapter data.

### 5.3 Interactive mode

```console
netplan.exe --no-autostart interactive
PE Netplan interactive mode. Type 'help' or 'exit'.
netplan> status
netplan> wifi scan --cached
netplan> validate "C:\PE Netplan\machine.yaml"
netplan> exit
```

Use `help`, `exit`, or `quit`. Single and double quotes are supported and Windows
backslashes are preserved. The endpoint and autostart policy are fixed when interactive
mode starts. Nested `interactive` and `rpc` commands are rejected. A UTF-8 BOM on the
first piped PowerShell command is accepted. Start with `interactive --json` to keep JSON
for every command, or append `--json` to one command inside the prompt.

## 6. Network and Wi-Fi status

The default `adapters` table summarizes identity, status, hardware kind, MAC, addresses,
and description. Use `adapters --json` for every structured field:

- `if_index`, friendly `name`, optional description/GUID/MAC;
- operational `status` and whether the interface is physical hardware;
- assigned IPv4/IPv6 addresses with prefix lengths.

The JSON form of `status` adds `captured_at_unix_ms`, `wifi_interfaces`, and an optional `wifi_error`.
Connected Wi-Fi interfaces include SSID display text and exact `ssid_hex`, signal
quality, profile name, authentication/cipher, security state, and RX/TX rates.

`wifi scan` defaults to a fresh scan and a 4000 ms completion wait. `--timeout-ms` is
bounded to 250–15000 ms. `--cached` skips the scan. The response contains:

```json
{
  "refreshed": true,
  "networks": []
}
```

`refreshed: false` means cached results were requested or no scan-complete notification
arrived before the timeout; it does not mean that no networks exist. A native scan
failure remains an error. With no `--if-index`, the status/scan CLI queries every Wi-Fi
interface. Windows privacy policy can deny access to Wi-Fi discovery APIs; PE Netplan
returns a typed `permission_denied` instead of silently returning an empty list. See
Microsoft's [WlanScan](https://learn.microsoft.com/windows/win32/api/wlanapi/nf-wlanapi-wlanscan)
and [WlanGetAvailableNetworkList](https://learn.microsoft.com/windows/win32/api/wlanapi/nf-wlanapi-wlangetavailablenetworklist)
documentation for OS-level behavior.

## 7. Configuration documents

Configuration is UTF-8 YAML or JSON with a strict schema. Unknown fields are rejected.
`--format auto` treats a document beginning with `{` or `[` after whitespace as JSON;
other documents are parsed as YAML. YAML and JSON represent the same data model.

The only supported schema version is `1`.

### 7.1 Top-level fields

| Field | Type | Default | Purpose |
| --- | --- | --- | --- |
| `version` | integer | required | Must be `1` |
| `protect` | object | empty | Interfaces that live apply must never mutate |
| `identity` | object/null | omitted | Computer name, workgroup, DNS suffix |
| `adapters` | array | `[]` | Adapter desired state |
| `wifi` | array | `[]` | Native Wi-Fi profiles |
| `wifi_actions` | array | `[]` | Scan/connect/disconnect actions during apply |
| `smb` | object | empty | Accounts, local shares, remote mappings |
| `firewall` | object/null | omitted | All-profile firewall state |
| `services` | array | `[]` | Service start/stop operations |
| `drivers` | array | `[]` | Driver install or adapter restart operations |
| `hooks` | array | `[]` | Direct executable hooks without a shell |

The complete sample is [examples/lab.yaml](../examples/lab.yaml); a minimal JSON DHCP
sample is [examples/dhcp.json](../examples/dhcp.json).

### 7.2 Interface selectors and protection

A selector must contain at least one field:

| Field | Match |
| --- | --- |
| `if_index` | Exact Windows interface index |
| `name` | Case-insensitive exact friendly name |
| `guid` | Case-insensitive exact adapter GUID; braces are equivalent |
| `mac_address` | Exact MAC; `:` and `-` separators are equivalent |
| `description_contains` | Case-insensitive description substring |

All supplied selector fields must match the same adapter. Zero matches is `not_found`;
multiple matches is invalid/ambiguous. Prefer `if_index` plus a second identity field for
reviewable machine-specific files.

Protect management interfaces before live apply:

```yaml
protect:
  management_interfaces:
    - if_index: 6
      description_contains: Realtek
```

The daemon resolves protected and target selectors to actual interface indexes before
mutation, preventing a differently written selector from bypassing protection.

### 7.3 Identity

```yaml
identity:
  computer_name: PE-LAB
  workgroup: WORKGROUP
  dns_suffix: lab.example
```

`computer_name` is a valid nonnumeric NetBIOS name up to 15 ASCII characters.
`workgroup` is at most 15 characters and excludes Windows-reserved punctuation.
`dns_suffix` is a valid DNS name up to 255 characters. Domain-joined machines fail
closed for workgroup changes.

### 7.4 Adapters and IPv4

```yaml
adapters:
  - selector: { if_index: 7 }
    enabled: true
    mac_address: 02-00-00-00-00-07
    ipv4:
      mode: static
      addresses: [192.0.2.10/24]
      gateways: [192.0.2.1]
      dns: [1.1.1.1, '2606:4700:4700::1111']
      wins: [192.0.2.2]
```

| Field | Meaning |
| --- | --- |
| `selector` | Required adapter selector |
| `enabled` | Optional desired administrative state |
| `mac_address` | Optional locally administered unicast MAC |
| `ipv4` | Optional DHCP or static object |

DHCP form:

```yaml
ipv4:
  mode: dhcp
  dns_from_dhcp: true
```

`dns_from_dhcp` defaults to `true`. Static mode requires at least one IPv4 CIDR in
`addresses`; gateways, DNS (IPv4 or IPv6), and WINS are ordered optional arrays.

### 7.5 Wi-Fi profiles and apply actions

```yaml
wifi:
  - selector: { if_index: 12 }
    name: pe-lab
    ssid: PE-Lab-WiFi
    authentication: wpa2_personal
    psk: { source: env, value: NETPLAN_WIFI_PSK }
    auto_connect: true
    hidden: false

wifi_actions:
  - action: scan
    selector: { if_index: 12 }
  - action: connect
    selector: { if_index: 12 }
    profile: pe-lab
```

Authentication values are `open`, `wpa2_personal`, and `wpa3_personal`. Open profiles
must omit `psk`; secured profiles require one. SSIDs contain 1–32 bytes. `name` defaults
to the SSID and must be unique case-insensitively. `auto_connect` and `hidden` default to
`false`.

Apply actions are tagged with `action: scan|connect|disconnect`. `connect.profile` must
reference a profile declared in the same document. A Wi-Fi profile/action selector may
be omitted only when exactly one Wi-Fi interface exists; multiple interfaces require an
explicit selector. This differs from the read-only CLI scan, which can aggregate all
interfaces.

### 7.6 Secrets

Use daemon environment variables whenever possible:

```yaml
password:
  source: env
  value: NETPLAN_SMB_PASSWORD
```

The variable is resolved inside `netpland`, so set it in the daemon's environment, not
only in a later CLI process. Literal form is supported for ephemeral PE workflows:

```yaml
password: { source: literal, value: temporary-secret }
```

Literal values are redacted from Rust debug output but remain plaintext in the
configuration file and process memory. Restrict file permissions and avoid committing
them. WPA2/WPA3 passphrases are 8–63 printable ASCII bytes; WPA2 also accepts a 64-digit
hexadecimal raw PSK, while WPA3 does not.

### 7.7 SMB

```yaml
smb:
  accounts:
    - id: local-diagnostics
      kind: local
      username: pe-diagnostics
      password: { source: env, value: NETPLAN_LOCAL_PASSWORD }
    - id: remote-server
      kind: credential
      username: 'LAB\reader'
      password: { source: env, value: NETPLAN_REMOTE_PASSWORD }
  shares:
    - name: diagnostics
      path: 'X:\diagnostics'
      description: PE diagnostics
      read_only: false
      accounts: [local-diagnostics]
  mappings:
    - remote: '\\fileserver\images'
      local: 'Z:'
      account: remote-server
```

Account `kind` is `credential` by default. `local` creates a missing local user and may
be referenced by a share ACL. Existing local-account passwords are never changed because
Windows cannot provide the previous password for lossless rollback. Credential accounts
are used only for remote mappings.

A share requires a unique name and an absolute local Windows path. Its `accounts` must
reference `kind: local` declarations. A mapping requires a UNC share path; `local` is an
optional drive letter. Use either `account` or inline `username`/`password`, never both.
Mappings cannot duplicate a drive letter. Do not stop `LanmanServer` while declaring
shares or `LanmanWorkstation` while declaring mappings.

`description` is optional, `read_only` defaults to `false`, and `accounts` defaults to
an empty array. An empty share account list grants Everyone read access when
`read_only: true` and full access otherwise; Built-in Administrators always receive full
access. Declare explicit local accounts unless public access is intentional.

### 7.8 Firewall and services

```yaml
firewall:
  enabled: true

services:
  - name: LanmanServer
    state: running
  - name: LanmanWorkstation
    state: stopped
```

Firewall state applies to all available profiles. Service states are `running` and
`stopped`; use the stable service name, not its localized display name. Duplicate
service operations are rejected.

### 7.9 Drivers

```yaml
drivers:
  - action: install
    inf_path: 'X:\drivers\net.inf'
    hardware_id: 'PCI\VEN_1234&DEV_5678'
    force: false
    restart: if_required
  - action: restart_adapter
    selector: { if_index: 7 }
```

`force` defaults to `false`. `restart` is `never` (default), `if_required`, or `always`;
values other than `never` require `hardware_id`. Forced installation uses the optional NewDev backend. Driver
installation is classified as irreversible: a failure later in the job cannot uninstall
the driver to recreate the exact previous state. Validate on a disposable image first.

### 7.10 Hooks

```yaml
hooks:
  - stage: before_apply
    program: 'X:\Windows\System32\ipconfig.exe'
    args: [/all]
    wait: true
```

Stages are `before_apply`, `after_apply`, and `after_rollback`. `wait` defaults to
`true`. `program` and every `args` entry are passed directly to process creation; no
shell parses them. If shell behavior is required, name `cmd.exe` or PowerShell
explicitly and pass an argument array, accepting the additional security risk.

## 8. Validate, plan, apply, and rollback

1. `validate` checks UTF-8, strict schema decoding, cross-references, and semantic rules.
2. `plan` returns deterministic operations with stable IDs, required capabilities,
   summaries, targets, and risk levels.
3. Dry-run `apply` records a successful in-memory job without changing Windows.
4. Live `apply --live` performs capability preflight and resolves selectors before the
   background job mutates state.
5. Reversible operations register snapshots and are rolled back in reverse order after
   failure. The terminal state is `rolled_back` only when every registered rollback and
   `after_rollback` hook succeeds. Otherwise the job is `failed` with a diagnostic.

Risk values are `read_only`, `low`, `connectivity`, and `destructive`. Review every
`connectivity`/`destructive` operation before live apply.

## 9. JSON-RPC gateway

Start the gateway:

```console
netplan.exe --no-autostart rpc
```

Send one UTF-8 JSON-RPC 2.0 object per line and read one response per line:

```json
{"jsonrpc":"2.0","id":1,"method":"netplan.status"}
{"jsonrpc":"2.0","id":2,"method":"netplan.wifi.scan","params":{"refresh":true,"timeout_ms":4000}}
{"jsonrpc":"2.0","id":3,"method":"netplan.config.inspect","params":{"format":"yaml","document":"version: 1\n"}}
```

Use `netplan.rpc.discover` to obtain the complete method, parameter, result, shared-type,
and error contract. The gateway supports health, daemon status, capabilities, adapter
lookup, network/Wi-Fi queries, configuration validation/planning/inspection/apply, job
get/list/wait, configuration metadata/examples, and method discovery. Notifications
omit `id` and produce no output.

The same machine-readable contract is shipped as
[schemas/jsonrpc.json](../schemas/jsonrpc.json); see [JSONRPC.md](JSONRPC.md).

## 10. Rust SDK

Inside this workspace, depend on the local crate:

```toml
[dependencies]
netplan = { path = "crates/netplan", version = "0.1.0" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use netplan::Client;
use netplan::protocol::{Request, Response};

#[tokio::main]
async fn main() -> netplan::Result<()> {
    let client = Client::default();
    match client.call(&Request::NetworkStatus).await? {
        Response::NetworkStatus { adapters, wifi_interfaces, wifi_error, .. } => {
            println!("{} adapters, {} Wi-Fi interfaces", adapters.len(), wifi_interfaces.len());
            if let Some(error) = wifi_error {
                eprintln!("Wi-Fi status unavailable: {error}");
            }
        }
        Response::Error { code, message } => eprintln!("daemon error {code:?}: {message}"),
        response => eprintln!("unexpected response: {response:?}"),
    }
    Ok(())
}
```

`Client::call` generates and verifies correlation IDs. `call_frame` accepts and returns
already encoded verified frames for lower-level integrations. See
[INTEGRATION.md](INTEGRATION.md).

## 11. C ABI

The C DLL is a frame transport API, not a high-level configuration API. A caller must
construct and decode the size-prefixed `PNET` FlatBuffers envelope defined in
`schemas/ipc.fbs`.

Required ownership sequence:

1. Call `netplan_client_create`; pass `NULL` for the default endpoint.
2. Build a verified-compatible request envelope with a request ID.
3. Call `netplan_client_call`.
4. Decode the response and verify its request ID.
5. Free the returned bytes exactly once with `netplan_buffer_free`.
6. Destroy the client exactly once with `netplan_client_destroy`.

Copy an error message with `netplan_client_last_error` after a nonzero transport status.
`NETPLAN_OK` means a verified frame was received; that frame may still contain a typed
daemon `ErrorResponse`. See [include/netplan.h](../include/netplan.h) and the complete
[integration guide](INTEGRATION.md).

## 12. Security and operational limits

- Only `netpland` performs live mutations; run it with the minimum deployment lifetime
  and protect every remote-management interface.
- Named-pipe ACLs do not make a bad live configuration safe. Review selectors and plans.
- Frames are bounded to 16 MiB and FlatBuffers-verified before dispatch.
- The daemon does not persist jobs or configuration.
- Hooks can execute arbitrary programs with daemon privileges.
- Literal secrets remain plaintext input even though debug formatting redacts them.
- Driver installation is not automatically reversible.
- Wi-Fi and SMB can legitimately be unavailable on reduced images.
- `status` does not test DNS, gateway, remote host, or Internet reachability.

## 13. Troubleshooting

| Symptom | Checks |
| --- | --- |
| `system cannot find the file` / endpoint absent | Start `netpland`, verify both processes use the same endpoint, or remove `--no-autostart` when the sibling executable is present |
| `permission_denied` opening the pipe | Run the client as an Administrator or review the daemon account/pipe ACL |
| Wi-Fi `permission_denied` | Review Windows Wi-Fi/location privacy policy and service state |
| `unsupported` | Run `capabilities`; add the missing image component/service or omit that operation |
| Wi-Fi `not_found` | Confirm a wireless adapter and driver exist and are visible to IP Helper/Native Wi-Fi |
| `refreshed: false` | Retry with a longer bounded timeout; the returned list may be cached |
| Selector ambiguous | Add `if_index`, GUID, or another exact field; all supplied fields must identify one adapter |
| Protected-interface rejection | Move the operation to a non-management adapter; do not remove protection during a remote session |
| Apply stays `running` | Query `job <id>` or JSON-RPC `netplan.job.wait`; inspect services/hardware operations that have native timeouts |
| Job ID disappears | `netpland` restarted; jobs are intentionally memory-only |
| JSON-RPC parse error | Send exactly one UTF-8 JSON object per line; do not send a JSON array or multi-line object |
| CLI autostart fails | Put `netpland.exe` beside `netplan.exe`, ensure it is executable/elevated, or start it explicitly |

When reporting a defect, include the PE Netplan version, Windows/PE build, target triple,
`ping`, `capabilities`, the failing command, and a redacted configuration/response. Never
include literal passwords or PSKs.
