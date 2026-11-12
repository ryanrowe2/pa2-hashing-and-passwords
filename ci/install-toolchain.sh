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

# Prefer the dated Ubuntu snapshot, but never accept an apt-get update that
# only succeeded because APT ignored failed snapshot indexes (e.g. HTTP 503).
# If the snapshot endpoint is unavailable, permit the normal signed Ubuntu
# repositories only when they can supply every EXACT locked version.
source_used="Ubuntu snapshot $snapshot"
if sudo apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=3 \
     --snapshot "$snapshot" update && \
   sudo DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 \
     --snapshot "$snapshot" install -y --no-install-recommends \
     --allow-downgrades "${packages[@]}"; then
  :
else
  printf '::warning::Ubuntu snapshot unavailable; retrying exact locked versions from configured signed repositories\n' >&2
  sudo apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=3 update
  sudo DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 install \
    -y --no-install-recommends --allow-downgrades "${packages[@]}"
  source_used="configured signed Ubuntu repositories (exact locked versions)"
fi

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
printf 'Validated %d locked package versions using %s\n' \
  "${#packages[@]}" "$source_used"
