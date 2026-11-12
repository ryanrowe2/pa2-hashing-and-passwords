#!/usr/bin/env bash
# Fail-closed update availability audit using only Ubuntu-signed repositories.
set -euo pipefail
source ci/ubuntu-apt.sh
pa2_apt_init
trap pa2_apt_cleanup EXIT

if ! validated_lock=$(python3 ci/parse-toolchain-lock.py ci/toolchain.lock); then
  printf '::error::Toolchain lock validation failed; refusing review\n' >&2
  exit 2
fi
mapfile -t packages <<< "$validated_lock"
pa2_apt_select current ""

# APT normally tolerates partial index refresh failures and falls back to
# stale local metadata. Error-Mode=any makes that a fatal audit error.
if ! sudo apt-get "${PA2_APT_OPTIONS[@]}" update -qq; then
  printf '::error::Incomplete Ubuntu package index refresh; refusing stale audit\n' >&2
  exit 2
fi

updates=0
for spec in "${packages[@]}"; do
  if pa2_apt_check_available audit "$spec"; then
    :
  else
    check_status=$?
    if (( check_status == 1 )); then
      updates=$((updates + 1))
    else
      printf '::error::Unavailable or untrusted repository pin: %s\n' "$spec" >&2
      exit 2
    fi
  fi
done
if (( updates > 0 )); then
  printf '::error::%d locked package(s) have updates; review pins and snapshot together.\n' "$updates" >&2
  exit 1
fi
printf 'No newer candidate package versions found for the %d tracked toolchain packages.\n' "${#packages[@]}"
