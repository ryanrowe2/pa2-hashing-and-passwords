#!/usr/bin/env bash
# Install reproducible Ubuntu 24.04 toolchain versions for CI.
set -euo pipefail

snapshot=20261111T000000Z
# Capture the parser's exit status. Process substitution would hide failures and
# could install a truncated package inventory after a partial read.
if ! validated_lock=$(python3 ci/parse-toolchain-lock.py ci/toolchain.lock); then
  printf '::error::Toolchain lock validation failed; refusing installation\n' >&2
  exit 2
fi
mapfile -t packages <<< "$validated_lock"

# Always use the same Ubuntu snapshot for both package indexes and downloads.
sudo apt-get --snapshot "$snapshot" update
sudo DEBIAN_FRONTEND=noninteractive apt-get --snapshot "$snapshot" install \
  -y --no-install-recommends --allow-downgrades "${packages[@]}"

# Fail loudly if an updated runner image invalidates the package lock.
for spec in "${packages[@]}"; do
  name=${spec%%=*}
  expected=${spec#*=}
  actual=$(dpkg-query --show --showformat='${Version}' "$name")
  if [[ "$actual" != "$expected" ]]; then
    printf 'Package version mismatch: %s expected %s, found %s\n' \
      "$name" "$expected" "$actual" >&2
    exit 1
  fi
done
printf 'Validated %d locked package versions at Ubuntu snapshot %s\n' \
  "${#packages[@]}" "$snapshot"
