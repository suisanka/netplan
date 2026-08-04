# PE Netplan

[English](README.md) | 简体中文

PE Netplan 是面向 Windows 和修改版 WinPE 镜像的 Rust 网络控制平面。配置使用同一套
严格 schema，可选择 YAML 或 JSON 格式。

工作区提供四种接入方式：

- `netpland.exe`：特权 daemon，只接受本机 typed FlatBuffers IPC。
- `netplan.exe`：CLI、交互式命令行和换行分隔的 JSON-RPC 2.0 网关。
- `netplan`：直接发起 typed daemon 请求的 Rust SDK crate。
- `netplan.dll` 与 `netplan.h`：使用已验证原始 IPC frame 的稳定 C ABI。

## 当前状态

0.1 版实现了严格配置解析、确定性规划、已验证 IPC、异步 job、JSON-RPC、Rust/C
SDK，以及受 capability 约束的 Windows 后端。`apply` 默认 dry-run；只有显式传入
`--live`，并通过配置验证、capability preflight 和受保护接口运行时解析后，才执行
原生系统变更。

PE 镜像可能缺少无线网卡、API 或服务，因此 Wi-Fi 与 SMB 由 capability 控制。请在
目标镜像上运行 `netplan capabilities`，不要假设功能必然存在。

## 构建

固定工具链包含 GNU 与 MSVC Windows target。Tag release 会同时验证并发布两个 target。
GNU build 在 Linux 上交叉编译：

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo build --workspace --release --target x86_64-pc-windows-gnu
```

MSVC build 在 Windows Server 2022 上运行，固定 VC-LTL5 `5.3.1`，且 VC-LTL 仅对
MSVC target 生效。两个 Windows target 的三个最终交付面均使用 mimalloc `0.1.52`：

```console
cargo build --workspace --release --target x86_64-pc-windows-msvc
```

Rust SDK 不会给下游程序安装全局 allocator；只有 PE Netplan 自身的 CLI、daemon 和 C
DLL 选择 mimalloc。

## CLI

可以显式启动 daemon，也可以在本机 endpoint 不存在时让 CLI 启动同目录下的 daemon：

```console
netpland.exe
netplan.exe ping
netplan.exe capabilities
netplan.exe adapters
netplan.exe status
netplan.exe status --json
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

`status` 返回包含适配器地址与当前 Wi-Fi 连接状态的本机快照，并不检测互联网连通性。
`wifi scan` 最多等待四秒以接收 Native Wi-Fi 扫描完成通知，然后读取可用网络列表。
请求缓存列表或等待超时时，`refreshed` 为 `false`。使用 `--if-index` 选择单个无线接口，
使用 `--timeout-ms` 在 250–15000 ms 范围内调整等待时间。

交互模式直接接受相同的子命令，不需要重复输入 `netplan.exe`；它支持带引号的 Windows
路径，并通过 `exit` 或 `quit` 退出。

单次命令默认输出简洁、对齐的人类可读摘要/表格。在子命令前后添加全局 `--json` 可获得
完整且稳定的 JSON 结构；JSON 模式的错误也会以结构化 JSON 写入 stderr，同时保持非零
exit code。

未提供 `--live` 时，`apply` 始终是 dry-run。Live job 通常先返回 `running`，之后使用
`job` 查询。通过 `protect.management_interfaces` 声明绝不能变更的接口；daemon 会在
任何 mutation 前，把受保护 selector 和目标 selector 都解析成真实接口索引。

[lab.yaml](examples/lab.yaml) 和 [dhcp.json](examples/dhcp.json) 分别展示同一 schema
的 YAML 与 JSON 写法。

## 外部接入

运行 `netplan rpc`，通过 stdin/stdout 暴露 JSON-RPC 2.0。每个输入和输出各占一行：

```json
{"jsonrpc":"2.0","id":1,"method":"netplan.ping"}
{"jsonrpc":"2.0","id":2,"method":"netplan.daemon.status"}
{"jsonrpc":"2.0","id":3,"method":"netplan.job.list","params":{"limit":25}}
{"jsonrpc":"2.0","id":4,"method":"netplan.status"}
{"jsonrpc":"2.0","id":5,"method":"netplan.wifi.scan","params":{"timeout_ms":4000}}
```

网关还提供单 capability/adapter 查询、有界 job 等待、配置检查、schema 示例和方法发现。
[schemas/jsonrpc.json](schemas/jsonrpc.json) 是机器可读的权威契约，显式定义全部 method、
parameter schema、result schema、共享结构类型与错误；详见
[中文 JSON-RPC 文档](docs/zh-CN/JSONRPC.md)。

Rust 程序可以依赖 `crates/netplan` 并使用 `netplan::Client`。Native 程序可以包含
[include/netplan.h](include/netplan.h) 并链接 `netplan.dll`；C ABI 接收和返回
[schemas/ipc.fbs](schemas/ipc.fbs) 定义的、带 size prefix 的 `PNET` FlatBuffers
frame。详见[中文集成指南](docs/zh-CN/INTEGRATION.md)。

## 安全模型

- 只有 `netpland` 拥有特权状态变更能力。
- Windows named pipe 拒绝远程客户端，只允许 `SYSTEM` 和 Administrators 成员访问；
  daemon 应以管理员权限运行。
- Frame 最大 16 MiB，并在分发前完成验证。
- 配置拒绝未知字段和无效 selector。
- Hook 保存 executable 和参数数组，而不是 shell 文本。
- Rust debug 输出会隐藏 literal secret。
- Live 操作失败后，可逆步骤按相反顺序 rollback；只有状态验证成功后 job 才报告
  `rolled_back`。
- 驱动安装明确不可逆；请先 dry-run，并只在经过测试的镜像上执行。
- 镜像缺少组件时，在 mutation 前返回 typed `Unsupported` 错误。

PE Netplan 使用 [Mozilla Public License 2.0](LICENSE)。

## 文档

| 主题 | English | 简体中文 |
| --- | --- | --- |
| 完整使用指南 | [User guide](docs/USER_GUIDE.md) | [使用指南](docs/zh-CN/USER_GUIDE.md) |
| JSON-RPC 网关 | [JSON-RPC](docs/JSONRPC.md) | [JSON-RPC](docs/zh-CN/JSONRPC.md) |
| Rust SDK、C ABI 与 IPC | [Integration](docs/INTEGRATION.md) | [集成指南](docs/zh-CN/INTEGRATION.md) |
| GitHub tag 自动发布 | [Release guide](docs/RELEASING.md) | [发布指南](docs/zh-CN/RELEASING.md) |
| 实现与验证矩阵 | [Porting matrix](docs/PORTING.md) | [移植矩阵](docs/zh-CN/PORTING.md) |
