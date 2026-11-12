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
  name=${spec%%=*}
  pinned=${spec#*=}
  if ! policy=$(apt-cache "${PA2_APT_OPTIONS[@]}" policy "$name"); then
    printf '::error::Cannot query available package versions for %s\n' "$name" >&2
    exit 2
  fi
  candidate=$(printf '%s\n' "$policy" | awk '$1 == "Candidate:" {print $2; exit}')
  if [[ -z "$candidate" || "$candidate" == '(none)' ]]; then
    printf '::error::Cannot determine available version of %s\n' "$name" >&2
    exit 2
  fi
  if dpkg --compare-versions "$candidate" gt "$pinned"; then
    printf '::warning title=Toolchain update available::%s %s -> %s\n' \
      "$name" "$pinned" "$candidate"
    updates=$((updates + 1))
  else
    compare_status=$?
    if (( compare_status != 1 )); then
      printf '::error::Version comparison failed for %s (exit %d)\n' \
        "$name" "$compare_status" >&2
      exit 2
    fi
  fi
done
if (( updates > 0 )); then
  printf '::error::%d locked package(s) have updates; review pins and snapshot together.\n' "$updates" >&2
  exit 1
fi
printf 'No newer candidate package versions found for the %d tracked toolchain packages.\n' "${#packages[@]}"
