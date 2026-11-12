#!/usr/bin/env bash
# Install reproducible Ubuntu 24.04 toolchain versions for CI.
set -euo pipefail

snapshot=20261111T000000Z
mapfile -t packages < <(grep -vE '^[[:space:]]*(#|$)' ci/toolchain.lock)
if (( ${#packages[@]} == 0 )); then
  echo 'Toolchain lock contains no packages' >&2
  exit 1
fi

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
