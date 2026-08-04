# JSON-RPC 网关

[English](../JSONRPC.md) | 简体中文

`netplan rpc` 在 stdin/stdout 上提供换行分隔的 JSON-RPC 2.0。CLI 把每个请求转换为 typed
daemon protocol；`netpland` 本身不接受 JSON。
Windows 上应由已经提权的宿主启动 gateway。它不会自动触发 UAC 重启，因为跨进程提权
边界无法可靠保留重定向的 stdin/stdout handle。

省略 `id` 表示 notification。响应保留 string、number 或 null ID。无参数方法可以省略
`params`，也可以传 `{}` 或 `[]`。

## 方法

| 方法 | 参数 | 结果 |
| --- | --- | --- |
| `netplan.ping` | 无 | daemon 与 protocol 版本 |
| `netplan.daemon.status` | 无 | 版本、uptime、启动时间与 job counter |
| `netplan.capabilities` | 无 | capability 状态数组 |
| `netplan.capability.get` | `{ "name": string }` | 一个 capability，name 不区分大小写 |
| `netplan.adapters.list` | 无 | 原生 adapter inventory |
| `netplan.adapter.get` | adapter selector | 唯一匹配的 adapter |
| `netplan.status` | 无 | 带时间戳的 adapter 与当前 Wi-Fi 状态快照 |
| `netplan.wifi.status` | 可选 `{ "if_index": integer }` | Native Wi-Fi interface 连接状态 |
| `netplan.wifi.scan` | 可选 Wi-Fi scan 参数 | 附近 Native Wi-Fi 网络与 refresh 状态 |
| `netplan.config.validate` | 配置参数 | validation 结果 |
| `netplan.config.plan` | 配置参数 | 确定性 operation |
| `netplan.config.inspect` | 配置参数 | validation、plan 与所需 capability |
| `netplan.config.apply` | 配置参数 | 接受的 dry-run/live apply job |
| `netplan.config.describe` | 无 | schema metadata 与安全默认值 |
| `netplan.config.example` | 可选 `{ "format": "yaml" | "json" }` | 符合 schema 的 placeholder 文档 |
| `netplan.job.get` | `{ "job_id": string }` | 当前 job 状态 |
| `netplan.job.list` | 可选 job filter | 最新保留 job 与 limit 前总数 |
| `netplan.job.wait` | wait 参数 | terminal job 状态或有界 timeout |
| `netplan.rpc.discover` | 无 | 完整 method/type contract 与运行时版本 |

`netplan enable`、`disable`、`start` 与 `stop` 管理本机 daemon process/service，刻意不作为
JSON-RPC method 暴露。生命周期变更请直接使用 CLI；内部 FlatBuffers shutdown frame
仍受 daemon pipe ACL 约束。

## 机器可读契约

[schemas/jsonrpc.json](../../schemas/jsonrpc.json) 是网关直接使用、并随 release 压缩包
发布的权威契约。`methods` 中每一项都显式包含：

- `name` 与人类可读 `summary`；
- `params_required`；
- `params` 的 JSON Schema；
- `result` 的 JSON Schema。

`AdapterInfo`、`WifiNetwork`、`Operation`、`JobSummary` 以及全部参数 object 等共享结构
都定义在 `$defs` 中。所有 schema 使用契约声明的 JSON Schema 2020-12 dialect；`errors`
定义网关可能产生的全部稳定 JSON-RPC code。

`netplan.rpc.discover` 返回该契约，并在运行时加入 `gateway_version`、
`daemon_protocol_version` 与 `config_schema_version`。只需 feature detection 的旧客户端
仍可读取 `method_names`；`methods` 提供完整定义。

配置方法接受：

```json
{
  "document": "version: 1\nadapters: []\n",
  "format": "auto",
  "dry_run": true
}
```

- `document` 必填，包含完整 YAML 或 JSON 文档。
- `format` 可选：`auto`、`yaml`、`yml` 或 `json`。
- `dry_run` 可选，默认 `true`；对 apply request 有意义。
- `netplan.config.inspect` 先 validate，只在有效时 plan；`required_capabilities` 数组去重，
  并保持 operation 顺序。
- `netplan.config.example` 符合 schema，但包含 adapter placeholder。先用
  `netplan.adapters.list` 替换它们，并在审核前保持 dry-run。

Adapter selector 接受下列一个或多个字段；所有已提供字段都必须匹配：

```json
{
  "if_index": 7,
  "name": "Ethernet",
  "guid": "{00000000-0000-0000-0000-000000000007}",
  "mac_address": "02:00:00:00:00:07",
  "description_contains": "Realtek"
}
```

Name、GUID、MAC 与 description 匹配都不区分大小写；MAC 的 `:` 与 `-` 分隔符等价。
没有匹配返回 `-32004`；多个匹配返回 `-32009`，并附带精简候选 ID。

Wi-Fi status 与 scan 使用 `WlanEnumInterfaces` 返回的已启用接口。省略 `if_index` 时会
查询/扫描全部接口并合并扫描结果；提供时则只操作该精确 Native Wi-Fi interface。Scan 接受：

```json
{
  "if_index": 7,
  "refresh": true,
  "timeout_ms": 4000
}
```

所有字段均可选。`refresh` 默认 `true`；`timeout_ms` 默认 4000，并限制为 250–15000。
daemon 等待 Native Wi-Fi scan-complete 通知后读取 available-network list。Timeout 仍会
返回缓存列表，并设置 `refreshed: false`；原生 scan-failure 通知会返回 typed daemon
error。Network entry 同时包含精确十六进制 SSID bytes 与有损 display string，以及
signal quality、security algorithm、connection/profile flag 和观察到它的 interface。
`netplan.status` 是本机状态快照，不是 Internet reachability probe；Wi-Fi 查询失败写入
`wifi_error`，不会丢弃 adapter state。

`netplan.job.list` 接受 `state`（`queued`、`running`、`succeeded`、`failed` 或
`rolled_back`）与 1–1000 的 `limit`。两者均可选，默认 limit 为 100。`total` 是应用
limit 前符合 filter 的数量。

Live apply 通常先返回 `running`。`netplan.job.wait` 可以避免 client 自行编写 polling：

```json
{
  "job_id": "20cd9c2c-c217-42c5-9648-71e5555baa46",
  "timeout_ms": 30000,
  "interval_ms": 100
}
```

`timeout_ms` 默认 30000，范围 1–300000；`interval_ms` 默认 100，范围 25–5000。
Timeout 返回 `-32002`。Job 仍然只保存在 daemon 内存中，`netpland` 重启后丢失。

`netplan.rpc.discover`、`netplan.config.describe` 与 `netplan.config.example` 是本地网关
metadata call，不需要运行 daemon。其他方法都使用 typed FlatBuffers daemon endpoint。

只允许在第一行开头存在 UTF-8 BOM，方便 Windows PowerShell 5 管道互操作，同时不会
放宽后续 framing。

会话示例：

```json
{"jsonrpc":"2.0","id":1,"method":"netplan.ping"}
{"jsonrpc":"2.0","id":2,"method":"netplan.daemon.status"}
{"jsonrpc":"2.0","id":3,"method":"netplan.status"}
{"jsonrpc":"2.0","id":4,"method":"netplan.wifi.scan","params":{"timeout_ms":4000}}
{"jsonrpc":"2.0","id":5,"method":"netplan.job.list","params":{"state":"running","limit":25}}
{"jsonrpc":"2.0","id":6,"method":"netplan.config.inspect","params":{"format":"json","document":"{\"version\":1}"}}
```

## 错误

网关使用标准 JSON-RPC code `-32700`、`-32600`、`-32601`、`-32602`。Transport failure
使用 `-32000`；wait timeout 为 `-32002`；not found 为 `-32004`；adapter selector
ambiguous 为 `-32009`；其他 typed daemon rejection 为 `-32010`。Daemon error 的
`error.data` 包含稳定的 `daemon_code`。

错误响应不会把 daemon protocol 改成 JSON；翻译边界完全位于 `netplan` 内部。
