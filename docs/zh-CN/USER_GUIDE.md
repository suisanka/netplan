# PE Netplan 使用指南

[English](../USER_GUIDE.md) | 简体中文

本文完整说明 PE Netplan 0.1 的构建、部署、日常操作、配置与外部集成。内容以当前仓库
为准；项目不提供安装器，带 tag 的 GitHub Release 提供 GNU 与 MSVC 二进制压缩包。

## 1. PE Netplan 的作用

PE Netplan 是面向 Windows 11 和修改版 Windows PE 镜像的本机网络控制平面。它把非
特权输入接口与特权系统变更分开：

| 组件 | 作用 |
| --- | --- |
| `netpland.exe` | 特权 daemon；唯一能够变更 Windows 状态的组件 |
| `netplan.exe` | 单次 CLI、交互式 CLI 和换行分隔的 JSON-RPC 网关 |
| `netplan` crate | Typed Rust 配置、planner、protocol 和 async client API |
| `netplan.dll` | 发送已验证 FlatBuffers frame 的底层 C ABI |

daemon 只接受本机带 size prefix 的 FlatBuffers。JSON-RPC 在 `netplan.exe` 内终止，
不会暴露给特权 daemon。

配置范围包括适配器状态/MAC/IPv4、机器身份、Native Wi-Fi profile 与 action、SMB
账号/share/mapping、Windows Firewall、service、驱动安装/重启，以及不经过 shell 的
hook。功能是否可用取决于当前 Windows/PE 镜像里实际存在的 API、service 与硬件。

## 2. 构建与部署

### 2.1 前置条件

- Rust `1.97.1`；通过 rustup 时，`rust-toolchain.toml` 会自动选择该版本。
- `x86_64-pc-windows-gnu` 需要 GNU Windows linker；`x86_64-pc-windows-msvc` 需要
  Visual Studio 2022 Build Tools。
- 只有运行可选安全检查时才需要 `cargo-audit`。
- 访问受保护 Windows daemon 需要管理员凭据或同意 UAC。

MSVC target 固定 VC-LTL5 `5.3.1`。Tag release 会先在 Windows Server 2022 上运行
target-level Clippy、test 与 release build，两个 target 均成功后才发布。

### 2.2 构建命令

在仓库根目录运行：

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo build --workspace --release --target x86_64-pc-windows-gnu
```

GNU Windows 产物位于：

```text
target/x86_64-pc-windows-gnu/release/netpland.exe
target/x86_64-pc-windows-gnu/release/netplan.exe
target/x86_64-pc-windows-gnu/release/netplan.dll
```

构建 MSVC/VC-LTL 版本时，将 build command 与路径里的 target 改为
`x86_64-pc-windows-msvc`。

仅使用 CLI 时，把 `netpland.exe` 和 `netplan.exe` 复制到同一目录。Native 集成还需要
复制 `netplan.dll`、`include/netplan.h` 与 `schemas/ipc.fbs`。CLI/JSON-RPC 不依赖 C
DLL。

推送版本 tag 后会自动验证两个 Windows target，为每个 target 生成 ZIP 与 SHA-256
checksum，并发布同一个 GitHub Release。详见[发布指南](RELEASING.md)。

### 2.3 PE 镜像组件

PE Netplan 在运行时探测功能。裁剪后的镜像可能需要添加相应组件才能提供 capability：

- 适配器 inventory 需要 IP Helper 和网络协议栈。
- 适配器/IP/firewall 变更需要 `netsh.exe`。
- Wi-Fi 需要 `wlanapi.dll`、`WlanSvc` 和无线驱动。
- SMB 需要 NetAPI/MPR 以及 Server/Workstation service。
- Service 操作需要 Service Control Manager。
- 驱动操作需要 `pnputil.exe`；force update 还需要 `newdev.dll`。

始终在目标镜像执行 `netplan capabilities`。不要根据标准 Windows 或另一份 PE 镜像
推断支持状态。

## 3. 启动并连接 daemon

默认 Windows endpoint：

```text
\\.\pipe\pe-netplan-netpland-v1
```

如需持久运行，先把 `netplan.exe` 与 `netpland.exe` 放在最终目录，然后执行：

```console
netplan.exe enable
```

`enable` 会把 `netpland.exe` 作为 LocalSystem 账号的 `PE Netplan Daemon` Windows
service 安装，设置为自动启动并立即启动。之后可使用：

```console
netplan.exe start
netplan.exe stop
netplan.exe disable
```

`stop` 只停止 service，仍保留自动启动；之后执行普通 daemon 命令时，如果没有
`--no-autostart`，CLI 可能再次启动已安装 service。`disable` 会停止并卸载 service，但不
删除文件。SCM 保存 daemon 绝对路径，移动 release 目录后请重新执行 `enable`。安装与
卸载 service 只支持默认 endpoint。在普通终端运行时，CLI 会请求 UAC 提权，并在同一个
控制台里等待提权子进程完成。

临时前台运行时，可直接启动 daemon：

```console
netpland.exe
```

然后在另一个终端使用 CLI：

```console
netplan.exe ping
```

Windows named pipe 仅限本机，拒绝远程 pipe client，只允许 `SYSTEM` 与 Administrators。
单次命令与 interactive 模式会在访问 pipe 前自动请求 UAC。直接运行 `netpland.exe` 时，
它也会先检查 token；权限不足便通过 UAC `runas` 重新启动，不会等到创建 pipe 时再以
`Access denied` 退出。取消提示会返回明确的权限错误。Endpoint 不存在时，提权后的 CLI
优先启动已安装的 Windows service；没有安装 service 时才启动同目录下的 `netpland.exe`。
`--no-autostart` 会阻止两种 daemon 自动启动路径，但不会降低 pipe ACL。

`netplan rpc` 是例外：启动它的宿主必须已经提权。这里会拒绝自动 UAC 重启，因为跨提权
边界无法可靠保留外部程序重定向的 JSON-RPC stdin/stdout handle。

两个程序都可以使用自定义 endpoint：

```console
netpland.exe --endpoint \\.\pipe\pe-netplan-lab
netplan.exe --endpoint \\.\pipe\pe-netplan-lab --no-autostart ping
```

`NETPLAN_ENDPOINT` 会修改 CLI、Rust client 和 daemon 的默认 endpoint；可执行程序显式
提供的 `--endpoint` 优先。

Unix 开发环境的默认值为 `/tmp/pe-netplan-netpland-v1.sock`。Portable backend 支持
解析、规划、protocol test 与 dry-run 行为，但不提供 Windows live mutation 或原生
adapter inventory。

## 4. 首次运行的安全流程

任何 live mutation 前先按顺序执行：

```console
netplan.exe ping
netplan.exe capabilities
netplan.exe adapters
netplan.exe status
netplan.exe validate examples\lab.yaml
netplan.exe plan examples\lab.yaml
netplan.exe apply examples\lab.yaml
```

最后一条仍然只是 dry-run。检查 operation 与 capability，替换所有示例 selector/path，
并保护承载 RDP、SSH、VPN 或内网穿透 agent 的接口。确认后才执行 live apply：

```console
netplan.exe apply C:\PE-Netplan\machine.yaml --live
netplan.exe job <job-id>
```

Live apply 异步执行，最初可能返回 `running`。Job 只保存在 daemon 内存中，
`netpland` 重启后即消失。

## 5. CLI 参考

单次命令默认输出自动换行的人类可读摘要。Adapter 与 Wi-Fi 对象使用多行记录，每个地址
单独占一行；人类输出限制在 88 列，不再横向无限扩展。添加 `--json` 可获得完整机器可读
响应。错误写入 stderr 并返回非零 exit code；使用 `--json` 时，stderr 内容也是 JSON
error object。

### 5.1 全局选项

| 选项 | 含义 |
| --- | --- |
| `--endpoint <ENDPOINT>` | 覆盖 named pipe 或开发用 Unix socket |
| `--no-autostart` | endpoint 缺失时也绝不启动 sibling daemon |
| `--json` | 输出完整稳定的 JSON response，而不是人类可读格式 |
| `--help`、`--version` | 输出帮助或版本 |

全局选项可以出现在子命令之前或之后。

```console
netplan.exe --json status
netplan.exe status --json
```

两种写法等价。`rpc` 始终使用换行分隔的 JSON-RPC，不受此选项影响。

成功时保留下文各命令对应的 JSON 结构。CLI 层失败时向 stderr 写入下列单个 object，并
以非零状态退出：

```json
{"error":{"code":"cli_error","message":"diagnostic"}}
```

Typed daemon rejection 会使用 `permission_denied` 等稳定 code，而不是 `cli_error`。

### 5.2 命令

| 命令 | 行为 |
| --- | --- |
| `enable` | 把默认 endpoint daemon 安装为自动启动的 Windows service 并启动；需要时请求 UAC |
| `disable` | 停止并卸载 Windows service；需要时请求 UAC |
| `start` | 启动已安装的默认 endpoint service；未安装时启动 sibling 后台 daemon |
| `stop` | 停止已安装 service；未安装时通过 typed IPC 优雅停止后台 daemon |
| `ping` | 返回 daemon 与 protocol 版本 |
| `capabilities` | 返回 capability 的 `available`、`read_only`、`dry_run` 或 `unavailable` 状态及原因 |
| `adapters` | 返回原生 adapter inventory |
| `status` | 返回带时间戳的 adapter 与 Wi-Fi 状态快照 |
| `wifi status [--if-index N]` | 返回 Native Wi-Fi interface/link 当前状态 |
| `wifi scan [--if-index N] [--cached] [--timeout-ms N]` | 扫描或读取附近网络 |
| `validate <PATH> [--format auto|yaml|json]` | 解码并验证配置 |
| `plan <PATH> [--format auto|yaml|json]` | 生成确定性有序 operation，不修改系统 |
| `apply <PATH> [--format ...] [--live]` | 提交 dry-run 或 live job |
| `job <JOB_ID>` | 读取一个保留的 job |
| `interactive` | 使用相同 typed request 的交互式 prompt |
| `rpc` | 在 stdin/stdout 提供换行分隔的 JSON-RPC 2.0 |

`status` 是本机状态快照，并不检测互联网连通性。如果 Wi-Fi 状态查询失败，错误写入
`wifi_error`，adapter 信息仍会保留。

四个 lifecycle 命令同样支持 `--json`。成功结果包含 `action`、`mode`
（`windows-service` 或 `background-process`）、`installed`、`state` 与 `message`。它们是
本地 CLI 操作，不是 JSON-RPC method。

### 5.3 交互模式

```console
netplan.exe --no-autostart interactive
PE Netplan interactive mode. Type 'help' or 'exit'.
netplan> status
netplan> wifi scan --cached
netplan> validate "C:\PE Netplan\machine.yaml"
netplan> exit
```

可使用 `help`、`exit` 或 `quit`。支持单引号、双引号，并保留 Windows 反斜杠。
Endpoint 和 autostart 策略在进入交互模式时固定。嵌套执行 `interactive` 或 `rpc` 会被
拒绝。PowerShell 管道第一条命令前存在 UTF-8 BOM 时也能正常解析。使用
`interactive --json` 可让所有命令保持 JSON 输出；也可以只在 prompt 内某条命令末尾
添加 `--json`。

## 6. 网络与 Wi-Fi 状态

默认 `adapters` 多行记录汇总 identity、status、hardware kind、MAC、地址与 description。
IPv4/IPv6 地址分别放在 continuation line，长地址列表不会再撑宽终端。使用
`adapters --json` 获取全部结构化字段：

- `if_index`、friendly `name`，以及可选 description/GUID/MAC；
- operation `status` 和是否为物理硬件；
- 带 prefix length 的 IPv4/IPv6 地址。

JSON 形式的 `status` 额外返回 `captured_at_unix_ms`、`wifi_interfaces` 和可选
`wifi_error`。已连接
的 Wi-Fi interface 包含 SSID 显示文本和精确的 `ssid_hex`、信号质量、profile name、
authentication/cipher、安全状态以及 RX/TX rate。

`wifi scan` 默认触发新扫描，并等待 4000 ms 获取完成通知。`--timeout-ms` 只能处于
250–15000 ms；`--cached` 跳过扫描。响应格式：

```json
{
  "refreshed": true,
  "networks": []
}
```

`refreshed: false` 表示请求了缓存，或超时前未收到扫描完成通知；它不表示附近没有网络。
原生扫描失败仍然是 error。不提供 `--if-index` 时，只读 status/scan CLI 会查询所有
`WlanEnumInterfaces` 返回的已启用 Wi-Fi interface，并合并扫描结果。`--if-index` 只操作
其中一个精确接口；不在 Native Wi-Fi 清单内的 IP Helper 无线/虚拟 adapter 不会被扫描。
Windows 隐私策略可能拒绝 Wi-Fi discovery API；PE Netplan 会返回 typed
`permission_denied`，而不是伪装成空列表。OS 层行为见 Microsoft 的
[WlanEnumInterfaces](https://learn.microsoft.com/windows/win32/api/wlanapi/nf-wlanapi-wlanenuminterfaces)、
[WlanScan](https://learn.microsoft.com/windows/win32/api/wlanapi/nf-wlanapi-wlanscan)
和 [WlanGetAvailableNetworkList](https://learn.microsoft.com/windows/win32/api/wlanapi/nf-wlanapi-wlangetavailablenetworklist)
文档。

## 7. 配置文档

配置是使用严格 schema 的 UTF-8 YAML 或 JSON，未知字段会被拒绝。`--format auto` 会
忽略开头空白；首个字符为 `{` 或 `[` 时按 JSON 解析，其他情况按 YAML 解析。两种格式
对应完全相同的数据模型。

目前只支持 schema version `1`。

### 7.1 顶层字段

| 字段 | 类型 | 默认值 | 作用 |
| --- | --- | --- | --- |
| `version` | integer | 必填 | 必须为 `1` |
| `protect` | object | empty | Live apply 绝不能修改的 interface |
| `identity` | object/null | omitted | Computer name、workgroup、DNS suffix |
| `adapters` | array | `[]` | Adapter desired state |
| `wifi` | array | `[]` | Native Wi-Fi profile |
| `wifi_actions` | array | `[]` | Apply 中的 scan/connect/disconnect action |
| `smb` | object | empty | Account、本地 share、远程 mapping |
| `firewall` | object/null | omitted | 全 profile firewall 状态 |
| `services` | array | `[]` | Service start/stop operation |
| `drivers` | array | `[]` | 驱动安装或 adapter restart operation |
| `hooks` | array | `[]` | 不通过 shell 的直接 executable hook |

完整样例见 [examples/lab.yaml](../../examples/lab.yaml)，最小 JSON DHCP 样例见
[examples/dhcp.json](../../examples/dhcp.json)。

### 7.2 Interface selector 与保护

Selector 至少包含一个字段：

| 字段 | 匹配规则 |
| --- | --- |
| `if_index` | 精确 Windows interface index |
| `name` | 不区分大小写的精确 friendly name |
| `guid` | 不区分大小写的精确 adapter GUID；是否带大括号等价 |
| `mac_address` | 精确 MAC；`:` 与 `-` 分隔符等价 |
| `description_contains` | 不区分大小写的 description substring |

所有已提供字段必须同时匹配同一个 adapter。没有匹配返回 `not_found`，多个匹配属于
invalid/ambiguous。机器专用配置建议同时使用 `if_index` 和另一个 identity 字段，方便
人工审核。

Live apply 前保护管理接口：

```yaml
protect:
  management_interfaces:
    - if_index: 6
      description_contains: Realtek
```

daemon 在 mutation 前把受保护 selector 与目标 selector 都解析成真实 interface index，
因此无法用另一种 selector 写法绕过保护。

### 7.3 机器身份

```yaml
identity:
  computer_name: PE-LAB
  workgroup: WORKGROUP
  dns_suffix: lab.example
```

`computer_name` 必须是最长 15 个 ASCII 字符的非纯数字 NetBIOS name。`workgroup` 最长
15 个字符，并排除 Windows 保留标点。`dns_suffix` 是最长 255 个字符的合法 DNS name。
Domain-joined 机器的 workgroup 变更会 fail closed。

### 7.4 Adapter 与 IPv4

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

| 字段 | 含义 |
| --- | --- |
| `selector` | 必填 adapter selector |
| `enabled` | 可选 administrative desired state |
| `mac_address` | 可选 locally administered unicast MAC |
| `ipv4` | 可选 DHCP 或 static object |

DHCP 写法：

```yaml
ipv4:
  mode: dhcp
  dns_from_dhcp: true
```

`dns_from_dhcp` 默认为 `true`。Static mode 的 `addresses` 至少包含一个 IPv4 CIDR；
gateways、DNS（IPv4 或 IPv6）和 WINS 是保持顺序的可选数组。

### 7.5 Wi-Fi profile 与 apply action

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

Authentication 取值为 `open`、`wpa2_personal`、`wpa3_personal`。Open profile 必须省略
`psk`，加密 profile 必须提供。SSID 长度为 1–32 bytes。`name` 默认等于 SSID，并且
不区分大小写时仍必须唯一。`auto_connect` 和 `hidden` 默认 `false`。

Apply action 通过 `action: scan|connect|disconnect` 标记。`connect.profile` 必须引用
同一文档里声明的 profile。Wi-Fi profile/action 只有在系统恰好存在一个无线 interface
时才能省略 selector；存在多个无线 interface 时必须显式选择。这与可以汇总所有接口的
只读 CLI scan 不同。

### 7.6 Secret

尽量使用 daemon 环境变量：

```yaml
password:
  source: env
  value: NETPLAN_SMB_PASSWORD
```

变量由 `netpland` 解析，因此必须设置在 daemon 环境中，只在稍后启动的 CLI 中设置无效。
临时 PE 工作流也支持 literal：

```yaml
password: { source: literal, value: temporary-secret }
```

Rust debug 输出会隐藏 literal value，但配置文件和进程内存里仍是明文。请限制文件权限，
并且不要提交含 secret 的配置。WPA2/WPA3 passphrase 必须为 8–63 个可打印 ASCII byte；
WPA2 额外允许 64 位十六进制 raw PSK，WPA3 不允许。

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

Account `kind` 默认 `credential`。`local` 会在用户不存在时创建本地用户，并可用于 share
ACL。Windows 无法提供旧密码供 lossless rollback，因此已有本地账号的密码绝不会被
修改。Credential account 只用于远程 mapping。

Share 需要唯一 name 和绝对本地 Windows path；`accounts` 只能引用 `kind: local` 声明。
Mapping 需要 UNC share path，`local` 是可选 drive letter。`account` 与 inline
`username`/`password` 二选一，不能同时使用；drive letter 不能重复。声明 share 时不能
同时停止 `LanmanServer`，声明 mapping 时不能同时停止 `LanmanWorkstation`。

`description` 可选，`read_only` 默认 `false`，`accounts` 默认空数组。Share account
为空时，`read_only: true` 会向 Everyone 授予 read access，否则向 Everyone 授予 full
access；Built-in Administrators 始终拥有 full access。除非确实需要公开访问，否则请显式
声明本地账号。

### 7.8 Firewall 与 service

```yaml
firewall:
  enabled: true

services:
  - name: LanmanServer
    state: running
  - name: LanmanWorkstation
    state: stopped
```

Firewall 状态应用到所有可用 profile。Service state 为 `running` 或 `stopped`；应填写
稳定的 service name，而不是本地化 display name。重复 service operation 会被拒绝。

### 7.9 驱动

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

`force` 默认 `false`。`restart` 为 `never`（默认）、`if_required` 或 `always`；不是
`never` 时必须提供 `hardware_id`。Force install 使用可选 NewDev backend。驱动安装被视为不可逆：后续步骤
失败时，系统无法通过自动卸载驱动精确还原旧状态。请先在一次性镜像中验证。

### 7.10 Hook

```yaml
hooks:
  - stage: before_apply
    program: 'X:\Windows\System32\ipconfig.exe'
    args: [/all]
    wait: true
```

Stage 为 `before_apply`、`after_apply`、`after_rollback`。`wait` 默认 `true`。`program`
和每个 `args` 元素直接传给 process creation，不经过 shell。如确实需要 shell 行为，请
显式指定 `cmd.exe` 或 PowerShell 并提供参数数组，同时接受额外安全风险。

## 8. Validate、plan、apply 与 rollback

1. `validate` 检查 UTF-8、严格 schema 解码、交叉引用和语义规则。
2. `plan` 返回确定性 operation，包含稳定 ID、所需 capability、summary、target 与 risk。
3. Dry-run `apply` 只记录一个成功的内存 job，不修改 Windows。
4. Live `apply --live` 先执行 capability preflight 并解析 selector，再由后台 job mutation。
5. 可逆操作保存 snapshot；失败时按相反顺序 rollback。只有所有已注册 rollback 与
   `after_rollback` hook 成功时，终态才是 `rolled_back`；否则是带诊断的 `failed`。

Risk 值为 `read_only`、`low`、`connectivity`、`destructive`。Live apply 前应逐项审核
所有 `connectivity` 与 `destructive` operation。

## 9. JSON-RPC 网关

启动网关：

```console
netplan.exe --no-autostart rpc
```

每行发送一个 UTF-8 JSON-RPC 2.0 object，并逐行读取响应：

```json
{"jsonrpc":"2.0","id":1,"method":"netplan.status"}
{"jsonrpc":"2.0","id":2,"method":"netplan.wifi.scan","params":{"refresh":true,"timeout_ms":4000}}
{"jsonrpc":"2.0","id":3,"method":"netplan.config.inspect","params":{"format":"yaml","document":"version: 1\n"}}
```

使用 `netplan.rpc.discover` 获取完整 method、parameter、result、共享类型与 error 契约。
网关提供 health、daemon status、capability、adapter lookup、network/Wi-Fi query、配置
validate/plan/inspect/apply、job get/list/wait、配置 metadata/example 和方法发现。
Notification 省略 `id`，不会产生输出。

同一份机器可读契约随仓库提供于
[schemas/jsonrpc.json](../../schemas/jsonrpc.json)；详见 [JSONRPC.md](JSONRPC.md)。

## 10. Rust SDK

在此 workspace 内依赖本地 crate：

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

`Client::call` 自动生成并验证 correlation ID。`call_frame` 用于更底层的接入，接收和返回
已经编码并验证的 frame。详见[集成指南](INTEGRATION.md)。

## 11. C ABI

C DLL 是 frame transport API，不是高级配置 API。调用者必须按 `schemas/ipc.fbs` 构造
并解码带 size prefix 的 `PNET` FlatBuffers envelope。

所有权顺序：

1. 调用 `netplan_client_create`；传 `NULL` 使用默认 endpoint。
2. 构造带 request ID、与 schema 兼容的 request envelope。
3. 调用 `netplan_client_call`。
4. 解码响应并验证 request ID。
5. 用 `netplan_buffer_free` 恰好释放一次返回的 bytes。
6. 用 `netplan_client_destroy` 恰好销毁一次 client。

Transport status 非零后通过 `netplan_client_last_error` 复制错误消息。`NETPLAN_OK` 只
表示收到了已验证 frame；该 frame 仍可能包含 daemon 的 typed `ErrorResponse`。详见
[include/netplan.h](../../include/netplan.h) 与完整[集成指南](INTEGRATION.md)。

## 12. 安全与运行限制

- 只有 `netpland` 执行 live mutation；尽量缩短其部署生命周期，并保护全部远程管理接口。
- Named-pipe ACL 不能让错误 live 配置变安全，仍需审核 selector 与 plan。
- Frame 最大 16 MiB，并在分发前完成 FlatBuffers 验证。
- daemon 不持久化 job 或配置。
- Hook 能以 daemon 权限执行任意程序。
- Literal secret 即使被 debug 输出隐藏，仍然是明文输入。
- 驱动安装无法自动 rollback。
- 裁剪镜像上 Wi-Fi 与 SMB 合理地可能不可用。
- `status` 不检测 DNS、gateway、远程主机或互联网连通性。

## 13. 故障排查

| 现象 | 检查项 |
| --- | --- |
| `系统找不到指定的文件` / endpoint 不存在 | 启动 `netpland`，确认两端 endpoint 相同；同目录 daemon 存在时也可以移除 `--no-autostart` |
| 打开 pipe 时 `permission_denied` | 确认已同意 UAC；`netplan rpc` 的宿主需先提权；否则检查 daemon account/pipe ACL |
| Wi-Fi `permission_denied` | 检查 Windows Wi-Fi/location 隐私策略与 service 状态 |
| `unsupported` | 运行 `capabilities`；向镜像添加缺失组件/service，或移除该 operation |
| Wi-Fi `not_found` | 确认无线 adapter 已启用，并出现在 Native Wi-Fi interface 清单中（`netsh wlan show interfaces`） |
| `refreshed: false` | 在有界范围内增加 timeout 后重试；当前列表可能来自缓存 |
| Selector ambiguous | 添加 `if_index`、GUID 或其他精确字段；所有字段必须共同锁定一个 adapter |
| 受保护接口被拒绝 | 把操作移到非管理接口；远程 session 中不要移除保护 |
| Apply 长时间 `running` | 使用 `job <id>` 或 JSON-RPC `netplan.job.wait`；检查带原生 timeout 的 service/hardware operation |
| Job ID 消失 | `netpland` 已重启；job 设计为仅保存在内存 |
| JSON-RPC parse error | 每行只发送一个 UTF-8 JSON object；不要发送 JSON array 或跨行 object |
| CLI autostart 失败 | 把 `netpland.exe` 放到 `netplan.exe` 同目录、同意 UAC，或显式启动/安装 daemon |

报告缺陷时，请提供 PE Netplan 版本、Windows/PE build、target triple、`ping`、
`capabilities`、失败命令，以及完成脱敏的配置/响应。不要包含 literal password 或 PSK。
