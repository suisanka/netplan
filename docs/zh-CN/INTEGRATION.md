# SDK 与 Native 集成

[English](../INTEGRATION.md) | 简体中文

## Rust

`netplan` crate 提供配置模型、planner、已验证 protocol codec 与 async daemon client：

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

`Client::call` 分配并验证 correlation ID。`Client::call_frame` 是处理已编码、带 size
prefix frame 的底层入口。

Apply response 可能是 `running`。保留 `job_id`，并使用
`Request::JobStatus { job_id }` 查询，直到状态变为 `succeeded`、`failed` 或
`rolled_back`。`Request::ListJobs { state, limit }` 返回 newest-first summary，包含创建/
更新时间；`Request::DaemonStatus` 返回 uptime 与各状态 counter。Job 只存在于 daemon
内存中，daemon 重启后不会保留。

只读运行时查询使用 `Request::NetworkStatus`、`Request::WifiStatus { if_index }` 和
`Request::WifiScan { if_index, refresh, timeout_ms }`。即使可选 Native Wi-Fi 组件不可用，
`NetworkStatus` 也会保留 adapter state。Wi-Fi scan response 包含 `refreshed` 和排序后的
network list；`false` 表示读取缓存结果时没有观察到 scan-complete 通知。

`Request::Shutdown` 会先返回 `Response::ShutdownAccepted`，然后 daemon 才关闭 listener。
它用于本机生命周期管理，只应通过与内置 named pipe 相同、限制为 Administrator/SYSTEM
的 transport 暴露。

Windows 默认 endpoint 是 `\\.\pipe\pe-netplan-netpland-v1`。测试和 Unix 开发环境使用
`/tmp/pe-netplan-netpland-v1.sock`。`NETPLAN_ENDPOINT` 可以覆盖 client 的默认值。

## C ABI

包含 `include/netplan.h`、加载 `netplan.dll`，并遵循下列所有权顺序：

1. 调用 `netplan_client_create`；传 `NULL` 选择默认 endpoint。
2. 按 `schemas/ipc.fbs` 构造 file identifier 为 `PNET`、带 size prefix 的 `Envelope`。
3. 调用 `netplan_client_call`。
4. 解码已验证 response envelope，并关联 `request_id`。
5. 用 `netplan_buffer_free` 恰好释放一次返回 allocation。
6. 用 `netplan_client_destroy` 恰好销毁一次 client。

`netplan_client_call` 返回 `NETPLAN_OK` 只表示收到了已验证 response frame。该 frame 可能
仍包含 typed `ErrorResponse`；daemon application error 属于 protocol data，而不是
transport failure。C status 非零后使用 `netplan_client_last_error` 获取错误。

`netplan_abi_version` 返回 ABI version。Rust 边界会验证所有 pointer 与 length，但 C
调用者违反 header 里声明的所有权规则仍属于 undefined behavior。

## Daemon protocol

- 仅限本机 transport：Windows named pipe 或 Unix-domain 开发 socket。
- Windows endpoint 仅允许管理员访问，并拒绝远程 client。
- Little-endian、带 size prefix 的 FlatBuffers envelope。
- File identifier：`PNET`。
- Protocol version：`1`。
- Frame body 最大 16 MiB。
- 每个 connection 包含一个 request 和一个相关 response。
- Status 与 job list 都是 Native FlatBuffers call；daemon 仍不解析 JSON-RPC。

v1 新消息在已有 `ErrorResponse` 之后追加 union discriminator。0–13 的既有值保持不变；
network/Wi-Fi status 与 scan 消息使用追加的 18–23。

仓库中的 Rust binding 使用 `flatc` 25.12.19 生成：

```console
flatc --rust --gen-object-api --gen-name-strings -o crates/netplan/src/protocol schemas/ipc.fbs
```

Generated module 特意在 file、namespace 与 inner-module scope 添加 lint exemption 和
`extern crate alloc`。Compiler 不会自动重建这些本地 header 调整，因此重新生成后必须
保留它们，并通过 native 与 Windows-target Clippy。

## Windows runtime

`x86_64-pc-windows-msvc` 配置使用 VC-LTL5 `5.3.1`；其 link search path 用兼容 Windows
的 VC-LTL variant 替代 MSVC runtime import library。VC-LTL 仅对该 target 生效，不会
链接到 GNU 或非 Windows build。Tag release workflow 会在 Windows Server 2022 上
验证该 target，通过后才发布 MSVC 压缩包。

CLI、daemon 与 C DLL 在 Windows 上选择 mimalloc `0.1.52` 作为 Rust global allocator。
SDK crate 不替宿主进程选择 allocator。
