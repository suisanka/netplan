# 移植矩阵

[English](../PORTING.md) | 简体中文

0.1 版完成下列 P0 实现边界。“已实现”表示已经具备严格 YAML/JSON contract、确定性
plan、capability preflight、Windows backend 和 rollback classification。依赖硬件的行
保留明确验证说明，不会把缺少测试硬件的情况描述成已经验证。

| Capability | Windows 实现 | 验证状态 |
| --- | --- | --- |
| Adapter inventory | IP Helper 与 `GetIfEntry2`；index、name、GUID、MAC、物理/admin/operation state、IPv4/IPv6、gateway、DNS、WINS、DHCP 与地址来源 | Windows 11 实机 |
| Adapter selection/protection | 非空 index/name/GUID/MAC/description selector 使用 AND 匹配；mutation 前把受保护与目标 selector 解析为真实 index | 实机拒绝 alias bypass |
| DHCP/static IPv4 | `netsh interface ipv4`；显式清理 active-store 中过期的手工地址；rollback 后验证逻辑状态 | 实机 static apply、DHCP restore 与强制 rollback |
| DNS/gateway/WINS | 有序原生 inventory，加 `netsh` apply/restore | Build/plan；实机 empty DNS/WINS 和 no-gateway |
| Adapter state | Enable、disable、restart，并按相反顺序 rollback | 实机 disable/enable |
| MAC override | Adapter-class registry `NetworkAddress` 加 adapter restart；恢复旧值 | 实机 override 与强制 rollback |
| Wi-Fi | 动态加载 Native Wi-Fi API；当前 interface/link status、ACM 完成通知后的 available-network scan、open/WPA2/WPA3 profile XML、connect、disconnect 与旧 profile/connection rollback | GNU target Clippy/build 与 typed test；仍需带 WLAN 硬件的实机 scan |
| SMB account | NetAPI：不存在时创建本地用户；已有密码不会改变，因为无法捕获旧密码执行 lossless rollback | 实机 create 与强制 rollback |
| SMB share | NetAPI level 502 create/update 与 level 1501 ACL restore；支持 Everyone 或命名本地账号 ACL | 实机 create 与强制 rollback |
| SMB mapping | MPR add/cancel，credential 仅在内存；冲突 drive mapping fail closed | API/capability 已验证；没有远程 SMB fixture |
| Machine identity | Native computer name、workgroup 与 primary DNS suffix API；domain-joined 机器 fail closed | Windows GNU build；有意跳过 live mutation |
| Firewall | 所有 profile 的 desired state、逐 profile snapshot 与 rollback | 实机 current-state no-op |
| Service | SCM query/start/stop、terminal-state wait 与 rollback | 实机 SMB service no-op |
| Driver install | PnPUtil normal install/restart；动态加载 NewDev force update；处理 reboot-required | 仅 capability/build；没有 signed disposable driver fixture |
| Hook | Before/after/after-rollback 阶段直接执行 executable 与 argument array；没有隐式 shell | 实机 success/failure 与 rollback |

## Platform 与 protocol 边界

- `netpland` 是唯一特权组件。本机 Windows named pipe 传输经过验证、带 size prefix 的
  `PNET` FlatBuffers，仅允许 `SYSTEM` 与 Administrators，拒绝远程 pipe client。
- `netplan` 是 CLI 和换行分隔的 JSON-RPC 2.0 网关，不会把 daemon transport 改成
  JSON。网关提供 discovery、目标 inventory lookup、配置 inspect、有界 job wait、
  network/Wi-Fi status、Wi-Fi scan、interactive CLI 与 schema/example metadata。
- `netplan` Rust crate 提供 typed 配置、planner、protocol codec 和 async client；
  `netplan.dll` 通过稳定 C ABI 暴露相同的已验证 frame。
- Live apply 是异步内存 job，dry-run 仍为默认。只有所有已注册 rollback action 与
  after-rollback hook 都成功时才产生 terminal `rolled_back`。Native FlatBuffers
  status/list request 暴露 daemon uptime、job counter、timestamp、filter、有界
  newest-first result、adapter/Wi-Fi snapshot 与 Wi-Fi scan result。
- 缺少 PE 组件时，在 mutation 前按 operation 返回 typed `Unsupported`。标准 WinPE 与
  修改版 PE 预期会暴露不同 capability 子集。

## Release gate

- Native format、Clippy、unit test、doc 与 package check。
- `x86_64-pc-windows-gnu` strict Clippy 与 release build。
- Windows 11 FlatBuffers、JSON-RPC、Rust SDK/CLI、C DLL、protection、live apply 与
  rollback smoke test。
- `x86_64-pc-windows-msvc` 保留 VC-LTL5 配置，但不是本版本 verification gate。

本机 AutoIt reference tree 已由 `.gitignore` 排除，不属于仓库或任何 Cargo package。
