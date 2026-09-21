#!/usr/bin/env bash
set -euo pipefail
[[ "$(uname -s)-$(uname -m)" == Linux-x86_64 ]]
tool_dir="${RUNNER_TEMP:-/tmp}/sag-release-tools"
mkdir -p "$tool_dir/bin"
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64 \
  --output "$tool_dir/bin/cosign"
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/cli/cli/releases/download/v2.101.0/gh_2.101.0_linux_amd64.tar.gz \
  --output "$tool_dir/gh.tar.gz"
printf '%s  %s\n' \
  4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 "$tool_dir/bin/cosign" \
  9bca2d1c16825f109907a23307628a2f0698fbf99662b73a5cf0b020293072b8 "$tool_dir/gh.tar.gz" | sha256sum --check --strict
tar -xzf "$tool_dir/gh.tar.gz" -C "$tool_dir" gh_2.101.0_linux_amd64/bin/gh
cp "$tool_dir/gh_2.101.0_linux_amd64/bin/gh" "$tool_dir/bin/gh"
chmod +x "$tool_dir/bin/cosign" "$tool_dir/bin/gh"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$tool_dir/bin" >> "$GITHUB_PATH"
fi
"$tool_dir/bin/cosign" version
"$tool_dir/bin/gh" --version
