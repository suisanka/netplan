#!/usr/bin/env bash

set -euo pipefail

readonly release_tag="${1:-}"

if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "release tag must be valid SemVer prefixed with v (for example v0.1.0)" >&2
  exit 2
fi

workspace_version="$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)"
if [[ -z "$workspace_version" ]]; then
  echo "could not read workspace.package.version from Cargo.toml" >&2
  exit 2
fi
if [[ "${release_tag#v}" != "$workspace_version" ]]; then
  echo "release tag ${release_tag} does not match workspace version ${workspace_version}" >&2
  exit 2
fi

echo "validated release tag ${release_tag} for workspace version ${workspace_version}"
