#!/usr/bin/env bash
# Weekly update-availability check for the Ubuntu toolchain snapshot lock.
set -euo pipefail

lock=ci/toolchain.lock
packages=()
declare -A seen_packages=()
line_number=0
while IFS= read -r line || [[ -n "$line" ]]; do
  ((line_number += 1))
  # Ignore blank/comment-only lines, including indentation.
  line="${line#"${line%%[![:space:]]*}"}"
  if [[ -z "$line" || "${line:0:1}" == '#' ]]; then
    continue
  fi
  if [[ ! "$line" =~ ^([a-z0-9][a-z0-9.+-]*)=([0-9][a-zA-Z0-9.+:~_-]*)$ ]]; then
    printf '::error::Malformed toolchain lock entry on line %d\n' "$line_number" >&2
    exit 2
  fi
  name=${BASH_REMATCH[1]}
  if [[ -v seen_packages[$name] ]]; then
    printf '::error::Duplicate package %s on line %d\n' "$name" "$line_number" >&2
    exit 2
  fi
  seen_packages[$name]=1
  packages+=("$line")
done < "$lock"

if (( ${#packages[@]} == 0 )); then
  printf '::error::Toolchain lock contains no package versions\n' >&2
  exit 2
fi

sudo apt-get update -qq
updates=0
for spec in "${packages[@]}"; do
  name=${spec%%=*}
  pinned=${spec#*=}
  if ! policy=$(apt-cache policy "$name"); then
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
  printf '::error::%d locked package(s) have updates; review the pinned snapshot and version lock in a pull request.\n' "$updates" >&2
  exit 1
fi
printf 'No newer candidate package versions found for the %d tracked toolchain packages.\n' "${#packages[@]}"
