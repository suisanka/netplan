# JSON-RPC gateway

English | [简体中文](zh-CN/JSONRPC.md)

`netplan rpc` serves JSON-RPC 2.0 as newline-delimited JSON over stdin/stdout. The CLI
translates each request into the typed daemon protocol; `netpland` does not accept JSON.
On Windows, launch the gateway from an already elevated host. It deliberately does not
perform an automatic UAC relaunch because redirected stdin/stdout handles cannot be
preserved reliably across that process boundary.

Requests may omit `id` to send a notification. Responses preserve string, number, or
null identifiers. Empty parameters may be omitted, `{}`, or `[]` for parameterless
methods.

## Methods

| Method | Parameters | Result |
| --- | --- | --- |
| `netplan.ping` | none | daemon and protocol versions |
| `netplan.daemon.status` | none | version, uptime, start time, and job counters |
| `netplan.capabilities` | none | capability state array |
| `netplan.capability.get` | `{ "name": string }` | one capability, case-insensitive by name |
| `netplan.adapters.list` | none | native adapter inventory |
| `netplan.adapter.get` | adapter selector | exactly one matching adapter |
| `netplan.status` | none | timestamped adapter and current Wi-Fi state snapshot |
| `netplan.wifi.status` | optional `{ "if_index": integer }` | native Wi-Fi interface connection states |
| `netplan.wifi.scan` | optional Wi-Fi scan parameters | nearby native Wi-Fi networks and refresh state |
| `netplan.config.validate` | config parameters | validation result |
| `netplan.config.plan` | config parameters | deterministic operations |
| `netplan.config.inspect` | config parameters | validation, plan, and required capabilities |
| `netplan.config.apply` | config parameters | accepted dry-run/apply job |
| `netplan.config.describe` | none | schema metadata and safe defaults |
| `netplan.config.example` | optional `{ "format": "yaml" | "json" }` | schema-valid placeholder document |
| `netplan.job.get` | `{ "job_id": string }` | current job state |
| `netplan.job.list` | optional job filter | newest retained jobs and pre-limit total |
| `netplan.job.wait` | wait parameters | terminal job state or bounded timeout |
| `netplan.rpc.discover` | none | complete method/type contract plus runtime versions |

`netplan enable`, `disable`, `start`, and `stop` manage the local daemon process/service
and are intentionally not JSON-RPC methods. Use the CLI directly for lifecycle changes;
the private FlatBuffers shutdown frame is restricted by the daemon pipe ACL.

## Machine-readable contract

[schemas/jsonrpc.json](../schemas/jsonrpc.json) is the canonical contract consumed by
the gateway and shipped in release archives. Every entry in `methods` explicitly
contains:

- `name` and a human-readable `summary`;
- `params_required`;
- a JSON Schema for `params`;
- a JSON Schema for `result`.

Shared structures such as `AdapterInfo`, `WifiNetwork`, `Operation`, `JobSummary`, and
every parameter object are defined under `$defs`. All schemas use the declared JSON
Schema 2020-12 dialect. `errors` defines every stable JSON-RPC code emitted by the
gateway.

`netplan.rpc.discover` returns this contract with `gateway_version`,
`daemon_protocol_version`, and `config_schema_version` added at runtime. The
`method_names` array remains available for clients that only need feature detection;
`methods` contains the full definitions.

Configuration methods accept:

```json
{
  "document": "version: 1\nadapters: []\n",
  "format": "auto",
  "dry_run": true
}
```

- `document` is required and contains the complete YAML or JSON document.
- `format` is optional: `auto`, `yaml`, `yml`, or `json`.
- `dry_run` is optional and defaults to `true`. It is meaningful for apply requests.
- `netplan.config.inspect` first validates, then plans only when valid. Its
  `required_capabilities` array is unique and preserves operation order.
- `netplan.config.example` is valid but contains adapter placeholders. Resolve them with
  `netplan.adapters.list` and keep apply in dry-run until reviewed.

Adapter selectors accept one or more of these fields; all supplied fields must match:

```json
{
  "if_index": 7,
  "name": "Ethernet",
  "guid": "{00000000-0000-0000-0000-000000000007}",
  "mac_address": "02:00:00:00:00:07",
  "description_contains": "Realtek"
}
```

Names, GUIDs, MAC addresses, and description matching are case-insensitive. MAC `:` and
`-` separators are equivalent. Zero matches returns `-32004`; multiple matches returns
`-32009` with compact candidate identifiers.

Wi-Fi status and scanning use the enabled interfaces returned by `WlanEnumInterfaces`.
Omitting `if_index` queries all of them, scans the interfaces whose radio is on, and
merges results. Radio-off interfaces are skipped and make `refreshed` false. Supplying
`if_index` restricts the operation to that exact Native Wi-Fi interface; selecting a
radio-off interface returns typed `unsupported`. Wi-Fi status reports `radio_off`. A
scan accepts:

```json
{
  "if_index": 7,
  "refresh": true,
  "timeout_ms": 4000
}
```

All fields are optional. `refresh` defaults to `true`; `timeout_ms` defaults to 4000 and
is bounded to 250–15000. The daemon waits for the Native Wi-Fi scan-complete
notification, then obtains the available-network list. A timeout still returns the
cached list with `refreshed: false`; a native scan-failure notification returns a typed
daemon error. Network entries include exact hexadecimal SSID bytes alongside the lossy
display string, signal quality, security algorithms, connection/profile flags, and the
observing interface. `netplan.status` is a local state snapshot, not an Internet
reachability probe; a Wi-Fi query failure is reported in `wifi_error` without discarding
adapter state.

`netplan.job.list` accepts `state` (`queued`, `running`, `succeeded`, `failed`, or
`rolled_back`) and `limit` from 1 through 1000. Both are optional; the default limit is
100. `total` is the number matching the filter before the limit is applied.

A live apply normally returns `running` immediately. `netplan.job.wait` avoids client-side
polling boilerplate:

```json
{
  "job_id": "20cd9c2c-c217-42c5-9648-71e5555baa46",
  "timeout_ms": 30000,
  "interval_ms": 100
}
```

`timeout_ms` defaults to 30000 and is bounded to 1–300000. `interval_ms` defaults to 100
and is bounded to 25–5000. Timeout returns `-32002`. Jobs are still kept only in daemon
memory and are lost when `netpland` restarts.

`netplan.rpc.discover`, `netplan.config.describe`, and `netplan.config.example` are local
gateway metadata calls and do not require a running daemon. All other methods use the
typed FlatBuffers daemon endpoint.

A UTF-8 BOM is accepted only at the start of the first input line, which keeps Windows
PowerShell 5 pipelines interoperable without weakening later framing.

Example session:

```json
{"jsonrpc":"2.0","id":1,"method":"netplan.ping"}
{"jsonrpc":"2.0","id":2,"method":"netplan.daemon.status"}
{"jsonrpc":"2.0","id":3,"method":"netplan.status"}
{"jsonrpc":"2.0","id":4,"method":"netplan.wifi.scan","params":{"timeout_ms":4000}}
{"jsonrpc":"2.0","id":5,"method":"netplan.job.list","params":{"state":"running","limit":25}}
{"jsonrpc":"2.0","id":6,"method":"netplan.config.inspect","params":{"format":"json","document":"{\"version\":1}"}}
```

## Errors

The gateway uses the standard JSON-RPC codes `-32700`, `-32600`, `-32601`, and
`-32602`. Transport failures use `-32000`; wait timeout uses `-32002`; not found uses
`-32004`; ambiguous adapter selection uses `-32009`; other typed daemon rejections use
`-32010`. A daemon error includes its stable `daemon_code` in `error.data`.
Error responses never change the daemon protocol into JSON—the translation boundary is
entirely inside `netplan`.
