# Tag 自动发布指南

[English](../RELEASING.md) | 简体中文

推送以 `v` 开头的 tag 时，`.github/workflows/release.yml` 会启动。只有 GNU 与 MSVC
job 均成功后，workflow 才发布一个同时包含两个 Windows x86_64 版本的 GitHub
Release。

Tag 必须是合法 SemVer；去掉开头 `v` 后，必须与 `Cargo.toml` 的
`workspace.package.version` 完全一致。

| Tag | Workspace version | 结果 |
| --- | --- | --- |
| `v0.1.0` | `0.1.0` | Stable release |
| `v0.2.0-rc.1` | `0.2.0-rc.1` | GitHub prerelease |
| `release-0.1.0` | `0.1.0` | 不触发 workflow |
| `v0.2.0` | `0.1.0` | 验证失败，不构建也不发布 |

## 仓库设置

- 仓库必须启用 GitHub Actions。
- Job 默认只有 `contents: read`。仅最终发布 job 获得 `actions: read` 与
  `contents: write`，用于下载两份 build artifact 并创建 release。Workflow 使用仓库
  范围的自动 `GITHUB_TOKEN`，不需要 personal access token 或额外 secret。
- Organization/repository policy 必须允许按 commit 固定的官方
  `actions/checkout`、`actions/upload-artifact` 与 `actions/download-artifact`。

## 创建 release

1. 修改 `Cargo.toml` 的 `workspace.package.version`，必要时重新生成 `Cargo.lock`。
2. 更新面向 release 的文档并检查 working tree。
3. Commit 并 push release commit。
4. 创建与 Cargo version 对应的 annotated tag，然后 push：

```console
git tag -a v0.1.0 -m "PE Netplan v0.1.0"
git push origin v0.1.0
```

包含 `-rc.1` 等 SemVer prerelease suffix 的 tag 会设置 GitHub prerelease flag。

## Release gate

Workflow 先验证 tag，然后并行运行两个 build job：

| Target | Runner | 必须通过的检查 |
| --- | --- | --- |
| `x86_64-pc-windows-gnu` | `ubuntu-24.04` | Format、native Clippy/test、strict target Clippy、locked release build |
| `x86_64-pc-windows-msvc` | `windows-2022` | Strict target Clippy、target test、使用 VC-LTL5 `5.3.1` 的 locked release build |

每个 build job 会暂存 `netplan.exe`、`netpland.exe`、`netplan.dll` 与对应的 C DLL import
library，并上传短期 workflow artifact。发布 job 只有在两者成功后才启动；它会下载两份
artifact、打包并计算 checksum，上传一份保留 14 天的组合 workflow artifact，最后根据
已经存在的 tag 创建 GitHub Release。

使用 `windows-2022` 是有意的：MSVC release 会继续使用当前 VC-LTL 集成所预期的
Visual Studio 2022 toolset。

## 发布的 asset

每个 Release 包含四个 asset：

```text
pe-netplan-vX.Y.Z-x86_64-pc-windows-gnu.zip
pe-netplan-vX.Y.Z-x86_64-pc-windows-gnu.zip.sha256
pe-netplan-vX.Y.Z-x86_64-pc-windows-msvc.zip
pe-netplan-vX.Y.Z-x86_64-pc-windows-msvc.zip.sha256
```

两个 ZIP 都只有一个顶层目录，公共结构如下：

```text
bin/netplan.exe
bin/netpland.exe
lib/netplan.dll
include/netplan.h
schemas/ipc.fbs
schemas/jsonrpc.json
examples/
docs/
README.md
README.zh-CN.md
LICENSE
```

GNU 压缩包还包含 `lib/libnetplan.dll.a`；MSVC 压缩包包含
`lib/netplan.dll.lib`。两者都是让 C/C++ 调用者链接 `netplan.dll` 的 import library，
不是独立的 Rust SDK library。

`.sha256` 使用标准 `sha256sum`/`shasum` 文本格式。在下载目录选择一条可用命令验证：

```console
sha256sum -c pe-netplan-v0.1.0-x86_64-pc-windows-gnu.zip.sha256
shasum -a 256 -c pe-netplan-v0.1.0-x86_64-pc-windows-gnu.zip.sha256
```

## 本地打包检查

`scripts/package-release.sh` 对已暂存的 target 打包。例如 GNU release build 完成后：

```console
cargo build --workspace --release --locked --target x86_64-pc-windows-gnu
mkdir -p target/release-staging/x86_64-pc-windows-gnu/bin
mkdir -p target/release-staging/x86_64-pc-windows-gnu/lib
cp target/x86_64-pc-windows-gnu/release/netplan.exe target/release-staging/x86_64-pc-windows-gnu/bin/
cp target/x86_64-pc-windows-gnu/release/netpland.exe target/release-staging/x86_64-pc-windows-gnu/bin/
cp target/x86_64-pc-windows-gnu/release/netplan.dll target/release-staging/x86_64-pc-windows-gnu/lib/
cp target/x86_64-pc-windows-gnu/release/libnetplan.dll.a target/release-staging/x86_64-pc-windows-gnu/lib/
scripts/package-release.sh v0.1.0 x86_64-pc-windows-gnu
```

脚本会拒绝非法 tag、version 不匹配、不支持的 target、缺失文件与已有输出路径。产物写入
已忽略的 `dist/`；再次运行前请使用干净的 `dist` 目录。

## 失败与重试策略

- Validate、build、test、staging 或 packaging 失败时不会创建 GitHub Release。
- Release 命令使用 `--verify-tag`，不会自动创建缺失 tag。
- Workflow 不覆盖已有 release 或替换 asset；发布成功后 rerun，预期会在创建 release 时
  失败。
- 已发布 tag 存在缺陷时，优先发布新的 patch version；不要移动已关联公开 release 的 tag。
- 如果 organization policy 降低了 `GITHUB_TOKEN` 权限，应恢复 workflow 中声明的权限，
  不要添加长期 personal token。
