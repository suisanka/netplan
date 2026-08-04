# Porting matrix

English | [简体中文](zh-CN/PORTING.md)

Version 0.1 completes the P0 implementation boundary below. “Implemented” means the
strict YAML/JSON contract, deterministic plan, capability preflight, Windows backend,
and rollback classification are present. Hardware-dependent rows retain their explicit
verification note rather than pretending unavailable test hardware was exercised.

| Capability | Windows implementation | Verification |
| --- | --- | --- |
| Adapter inventory | IP Helper and `GetIfEntry2`; index, name, GUID, MAC, physical/admin/operational state, IPv4/IPv6, gateways, DNS, WINS, DHCP and address origin | Windows 11 live |
| Adapter selection/protection | Non-empty index/name/GUID/MAC/description selectors use AND matching; protected and target selectors resolve to actual indexes before mutation | Alias-bypass rejection live |
| DHCP/static IPv4 | `netsh interface ipv4`; explicit cleanup of stale manual active-store addresses; logical-state verification after rollback | Static apply, DHCP restore, forced rollback live |
| DNS/gateway/WINS | Ordered native inventory plus `netsh` apply/restore | Build/plan; empty DNS/WINS and no-gateway live |
| Adapter state | Enable, disable and restart with reverse-order rollback | Disable/enable live |
| MAC override | Adapter-class `NetworkAddress` registry value plus adapter restart; previous value restored | Override and forced rollback live |
| Wi-Fi | Runtime-loaded Native Wi-Fi API; current interface/link status, ACM-completed available-network scans, open/WPA2/WPA3 profile XML, connect, disconnect, previous profile/connection rollback | GNU target Clippy/build and typed tests; physical WLAN scan still required |
| SMB accounts | NetAPI local-user create-if-absent; existing passwords are never changed because they cannot be captured for lossless rollback | Create and forced rollback live |
| SMB shares | NetAPI level 502 create/update and level 1501 ACL restore; Everyone or named local-account ACLs | Create and forced rollback live |
| SMB mappings | MPR add/cancel with in-memory credentials; conflicting drive mappings fail closed | API/capability verified; no remote SMB fixture was available |
| Machine identity | Native computer name, workgroup and primary DNS suffix APIs; domain-joined machines fail closed | Windows GNU build; live mutation intentionally skipped |
| Firewall | All-profile desired state with per-profile snapshot and rollback | Current-state no-op live |
| Services | SCM query/start/stop with terminal-state wait and rollback | SMB services no-op live |
| Driver install | PnPUtil normal install/restart; runtime-loaded NewDev force update; reboot-required handling | Capability/build only; no signed disposable driver fixture |
| Hooks | Direct executable plus argument array at before/after/after-rollback stages; no implicit shell | Success/failure and rollback live |

## Platform and protocol boundary

- `netpland` is the only privileged component. Its local Windows named pipe carries
  verified, size-prefixed `PNET` FlatBuffers and is restricted to `SYSTEM` and
  Administrators; remote pipe clients are rejected.
- `netplan` is the CLI and newline-delimited JSON-RPC 2.0 gateway. It never changes the
  daemon transport to JSON. The gateway includes discovery, targeted inventory lookup,
  configuration inspection, bounded job waiting, network/Wi-Fi status, Wi-Fi scanning,
  interactive CLI mode, and schema/example metadata.
- The `netplan` Rust crate provides the typed configuration, planner, protocol codec,
  and asynchronous client. `netplan.dll` exposes the same verified frames through a
  stable C ABI.
- Live apply is an asynchronous in-memory job. Dry-run remains the default. A terminal
  `rolled_back` state is emitted only when every registered rollback action and the
  after-rollback hooks succeed. Native FlatBuffers status/list requests expose daemon
  uptime, job counters, timestamps, filters, bounded newest-first results, adapter/Wi-Fi
  snapshots, and Wi-Fi scan results.
- Missing PE components are reported per operation as typed `Unsupported` errors before
  mutation. Stock WinPE and modified PE images are expected to expose different subsets.

## Release gates

- Native format, Clippy, unit tests, docs and package checks.
- `x86_64-pc-windows-gnu` strict Clippy and release build.
- `x86_64-pc-windows-msvc` strict Clippy, tests, and release build on Windows Server
  2022 with VC-LTL5. Both Windows targets must pass before a GitHub Release is created.
- Windows 11 FlatBuffers, JSON-RPC, Rust SDK/CLI, C DLL, protection, live apply and
  rollback smoke tests.

The local AutoIt reference tree is excluded by `.gitignore` and is not part of the
repository or any Cargo package.
