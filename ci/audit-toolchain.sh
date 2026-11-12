#!/usr/bin/env bash
# Weekly update-availability check for the Ubuntu toolchain snapshot lock.
set -euo pipefail

sudo apt-get update -qq
updates=0
while IFS= read -r spec || [[ -n "$spec" ]]; do
  case "$spec" in ''|\#*) continue ;; esac
  name=${spec%%=*}
  pinned=${spec#*=}
  candidate=$(apt-cache policy "$name" | awk '$1 == "Candidate:" {print $2; exit}')
  if [[ -z "$candidate" || "$candidate" == "(none)" ]]; then
    printf '::error::Cannot determine available version of %s\n' "$name" >&2
    exit 2
  fi
  if dpkg --compare-versions "$candidate" gt "$pinned"; then
    printf '::warning title=Toolchain update available::%s %s -> %s\n' \
      "$name" "$pinned" "$candidate"
    updates=$((updates + 1))
  fi
done < ci/toolchain.lock

if (( updates > 0 )); then
  printf '::error::%d locked package(s) have updates; review the pinned snapshot and version lock in a pull request.\n' "$updates" >&2
  exit 1
fi
printf 'No newer candidate package versions found for the %s tracked toolchain packages.\n' "$(grep -cE '^[^#[:space:]]' ci/toolchain.lock)"
