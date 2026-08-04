# Tagged release guide

English | [简体中文](zh-CN/RELEASING.md)

Pushing a tag beginning with `v` starts `.github/workflows/release.yml`. The workflow
publishes one GitHub Release containing both Windows x86_64 variants only after the GNU
and MSVC jobs succeed.

The tag must be valid SemVer and must exactly match `workspace.package.version` in
`Cargo.toml` after removing the leading `v`.

| Tag | Workspace version | Result |
| --- | --- | --- |
| `v0.1.0` | `0.1.0` | Stable release |
| `v0.2.0-rc.1` | `0.2.0-rc.1` | GitHub prerelease |
| `release-0.1.0` | `0.1.0` | Does not trigger the workflow |
| `v0.2.0` | `0.1.0` | Validation fails; no build or release |

## Repository setup

- GitHub Actions must be enabled for the repository.
- Jobs default to `contents: read`. Only the final publishing job receives
  `actions: read` and `contents: write` so it can download the two build artifacts and
  create the release. The repository-scoped automatic `GITHUB_TOKEN` is used; no
  personal access token or additional secret is required.
- Organization or repository policy must permit the commit-pinned official
  `actions/checkout`, `actions/upload-artifact`, and `actions/download-artifact`
  actions.

## Create a release

1. Update `workspace.package.version` in `Cargo.toml` and regenerate `Cargo.lock` if
   needed.
2. Update release-facing documentation and verify the working tree.
3. Commit and push the release commit.
4. Create and push an annotated tag matching the Cargo version:

```console
git tag -a v0.1.0 -m "PE Netplan v0.1.0"
git push origin v0.1.0
```

A tag containing a SemVer prerelease suffix such as `-rc.1` is published with GitHub's
prerelease flag.

## Release gates

The workflow first validates the tag, then runs these build jobs in parallel:

| Target | Runner | Required checks |
| --- | --- | --- |
| `x86_64-pc-windows-gnu` | `ubuntu-24.04` | Format, native Clippy/tests, strict target Clippy, locked release build |
| `x86_64-pc-windows-msvc` | `windows-2022` | Strict target Clippy, target tests, locked release build with VC-LTL5 `5.3.1` |

Each build job stages `netplan.exe`, `netpland.exe`, `netplan.dll`, and the matching C
DLL import library into a short-lived workflow artifact. The publishing job starts only
after both jobs succeed. It downloads both artifacts, packages and checksums them,
uploads a combined 14-day workflow artifact, and creates the GitHub Release from the
already-existing tag.

`windows-2022` is intentional: it keeps the MSVC release on the Visual Studio 2022
toolset expected by the current VC-LTL integration.

## Published assets

Every release contains four assets:

```text
pe-netplan-vX.Y.Z-x86_64-pc-windows-gnu.zip
pe-netplan-vX.Y.Z-x86_64-pc-windows-gnu.zip.sha256
pe-netplan-vX.Y.Z-x86_64-pc-windows-msvc.zip
pe-netplan-vX.Y.Z-x86_64-pc-windows-msvc.zip.sha256
```

Both ZIPs contain one top-level directory with this common layout:

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

The GNU archive additionally contains `lib/libnetplan.dll.a`; the MSVC archive contains
`lib/netplan.dll.lib`. These are import libraries for linking C/C++ callers to
`netplan.dll`, not standalone Rust SDK libraries.

The `.sha256` files use standard `sha256sum`/`shasum` text format. Verify one from its
download directory with an available command:

```console
sha256sum -c pe-netplan-v0.1.0-x86_64-pc-windows-gnu.zip.sha256
shasum -a 256 -c pe-netplan-v0.1.0-x86_64-pc-windows-gnu.zip.sha256
```

## Local packaging check

`scripts/package-release.sh` packages an already-staged target. For example, after a
GNU release build:

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

The script refuses malformed tags, version mismatches, unsupported targets, missing
files, and an existing output path. It writes ignored output under `dist/`; use a clean
`dist` directory for another run.

## Failure and retry policy

- A failed validation, build, test, staging, or packaging step does not create a
  GitHub Release.
- The release command uses `--verify-tag`; it never invents a missing tag.
- The workflow does not overwrite an existing release or replace its assets. A rerun
  after successful publication is expected to fail at release creation.
- Prefer a new patch version for a defective published tag. Do not move a tag associated
  with a public release.
- If organization policy reduces `GITHUB_TOKEN` permissions, restore the declared
  permissions for this workflow instead of adding a long-lived personal token.
