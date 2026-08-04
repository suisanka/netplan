#!/usr/bin/env bash

set -euo pipefail

readonly release_tag="${1:-}"
readonly release_target="${2:-}"
readonly stage_root="${3:-target/release-staging/${release_target}}"
readonly dist_root="dist"

scripts/check-release-tag.sh "$release_tag"

case "$release_target" in
  x86_64-pc-windows-gnu)
    readonly import_library="libnetplan.dll.a"
    ;;
  x86_64-pc-windows-msvc)
    readonly import_library="netplan.dll.lib"
    ;;
  *)
    echo "unsupported release target: ${release_target:-<empty>}" >&2
    exit 2
    ;;
esac

readonly package_name="pe-netplan-${release_tag}-${release_target}"
readonly package_root="${dist_root}/${package_name}"
readonly archive_path="${dist_root}/${package_name}.zip"
readonly checksum_path="${archive_path}.sha256"

if [[ -e "$package_root" || -e "$archive_path" || -e "$checksum_path" ]]; then
  echo "release output already exists for ${package_name}; use a clean dist directory" >&2
  exit 2
fi

required_files=(
  "${stage_root}/bin/netplan.exe"
  "${stage_root}/bin/netpland.exe"
  "${stage_root}/lib/netplan.dll"
  "${stage_root}/lib/${import_library}"
  "include/netplan.h"
  "schemas/ipc.fbs"
  "examples/dhcp.json"
  "examples/lab.yaml"
  "README.md"
  "README.zh-CN.md"
  "LICENSE"
)
for required_file in "${required_files[@]}"; do
  if [[ ! -f "$required_file" ]]; then
    echo "required release file is missing: ${required_file}" >&2
    exit 2
  fi
done

mkdir -p \
  "${package_root}/bin" \
  "${package_root}/lib" \
  "${package_root}/include" \
  "${package_root}/schemas" \
  "${package_root}/examples" \
  "${package_root}/docs"

cp "${stage_root}/bin/netplan.exe" "${package_root}/bin/"
cp "${stage_root}/bin/netpland.exe" "${package_root}/bin/"
cp "${stage_root}/lib/netplan.dll" "${package_root}/lib/"
cp "${stage_root}/lib/${import_library}" "${package_root}/lib/"
cp include/netplan.h "${package_root}/include/"
cp schemas/ipc.fbs "${package_root}/schemas/"
cp examples/dhcp.json examples/lab.yaml "${package_root}/examples/"
cp README.md README.zh-CN.md LICENSE "${package_root}/"
cp docs/*.md "${package_root}/docs/"
cp -R docs/zh-CN "${package_root}/docs/"

(
  cd "$dist_root"
  zip -X -q -r "${package_name}.zip" "$package_name"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${package_name}.zip" > "${package_name}.zip.sha256"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${package_name}.zip" > "${package_name}.zip.sha256"
  else
    echo "neither sha256sum nor shasum is available" >&2
    exit 2
  fi
)

echo "created ${archive_path}"
echo "created ${checksum_path}"
