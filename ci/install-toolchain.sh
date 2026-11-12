#!/usr/bin/env bash
# Install exactly locked Ubuntu 24.04 toolchain packages from signed Ubuntu
# archives. Optional snapshot replay permits 502/503/504 index-outage fallback;
# installation and signature failures must never be reclassified as outages.
set -euo pipefail
source ci/ubuntu-apt.sh
pa2_apt_init
trap pa2_apt_cleanup EXIT

if ! validated_lock=$(python3 ci/parse-toolchain-lock.py ci/toolchain.lock) ||
   ! snapshot=$(python3 ci/parse-toolchain-lock.py --snapshot ci/toolchain.lock); then
  printf '::error::Invalid toolchain lock; refusing installation\n' >&2
  exit 2
fi
mapfile -t packages <<< "$validated_lock"
# The signed current Ubuntu archives are the routine CI source. Snapshot replay
# is opt-in, since the historical snapshot CDN can return errors after indexes
# succeed, including when downloading pinned .deb files. Both modes enforce
# the same exact package versions and Ubuntu archive signing key.
if [[ "${PA2_USE_SNAPSHOT:-0}" == "1" ]]; then
  pa2_apt_select snapshot "$snapshot"

  update_log="$PA2_APT_DIR/snapshot-update.stderr"
  if timeout --signal=TERM --kill-after=5s 30s \
       sudo apt-get "${PA2_APT_OPTIONS[@]}" update -qq 2> "$update_log"; then
    source_used="Ubuntu snapshot $snapshot"
  else
    update_status=$?
    cat "$update_log" >&2
    if { [[ "$update_status" -eq 124 ]] ||
         grep -Eq 'Failed to fetch https://snapshot\.ubuntu\.com/ubuntu/.* (502|503|504) ' "$update_log"; } &&
       ! grep -Eiq '(NO_PUBKEY|BADSIG|Hash Sum mismatch|not signed|does not have a Release file)' "$update_log"; then
      printf '::warning::Ubuntu snapshot availability error; retrying identical version pins from signed Ubuntu archives\n' >&2
      pa2_apt_select current "$snapshot"
      if ! sudo apt-get "${PA2_APT_OPTIONS[@]}" update -qq; then
        printf '::error::Current Ubuntu archive index refresh failed\n' >&2
        exit 2
      fi
      source_used="signed Ubuntu archives (snapshot unavailable)"
    else
      printf '::error::Snapshot refresh failed (exit %s); no fallback permitted\n' "$update_status" >&2
      exit 2
    fi
  fi


else
  pa2_apt_select current "$snapshot"
  if ! sudo apt-get "${PA2_APT_OPTIONS[@]}" update -qq; then
    printf '::error::Current Ubuntu archive index refresh failed\n' >&2
    exit 2
  fi
  source_used="signed Ubuntu archives (exact locked versions)"
fi

# Installation failure is never an outage signal. Do not retry from a
# different source after a signed package install or integrity error.
if ! sudo DEBIAN_FRONTEND=noninteractive apt-get "${PA2_APT_OPTIONS[@]}" install \
      -y --no-install-recommends --allow-downgrades "${packages[@]}"; then
  printf '::error::Installation of exact locked versions failed\n' >&2
  exit 2
fi

for spec in "${packages[@]}"; do
  name=${spec%%=*}
  expected=${spec#*=}
  if ! actual=$(dpkg-query --show --showformat='${Version}' "$name"); then
    printf '::error::Missing installed package %s\n' "$name" >&2
    exit 2
  fi
  if [[ "$actual" != "$expected" ]]; then
    printf '::error::Package version mismatch: %s expected %s, found %s\n' \
      "$name" "$expected" "$actual" >&2
    exit 2
  fi
done
printf 'Validated %d locked package versions using %s\n' \
  "${#packages[@]}" "$source_used"
