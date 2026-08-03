# JSON-RPC gateway

`netplan rpc` serves JSON-RPC 2.0 as newline-delimited JSON over stdin/stdout. The CLI
translates each request into the typed daemon protocol; `netpland` does not accept JSON.

Requests may omit `id` to send a notification. Responses preserve string, number, or
null identifiers. Empty parameters may be omitted, `{}`, or `[]` for parameterless
methods.

## Methods

| Method | Parameters | Result |
| --- | --- | --- |
| `netplan.ping` | none | daemon and protocol versions |
| `netplan.capabilities` | none | capability state array |
| `netplan.adapters.list` | none | native adapter inventory |
| `netplan.config.validate` | config parameters | validation result |
| `netplan.config.plan` | config parameters | deterministic operations |
| `netplan.config.apply` | config parameters | accepted dry-run/apply job |
| `netplan.job.get` | `{ "job_id": string }` | current job state |

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

Example session:

```json
{"jsonrpc":"2.0","id":1,"method":"netplan.ping"}
{"jsonrpc":"2.0","id":2,"method":"netplan.config.plan","params":{"format":"json","document":"{\"version\":1}"}}
```

## Errors

The gateway uses the standard JSON-RPC codes `-32700`, `-32600`, `-32601`, and
`-32602`. Transport failures use `-32000`; a typed daemon rejection uses `-32010`.
Error responses never change the daemon protocol into JSON—the translation boundary is
entirely inside `netplan`.
