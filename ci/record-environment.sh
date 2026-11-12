#!/usr/bin/env bash
# Record the full installed Debian package inventory and build-runner metadata.
# This is provenance evidence, not a claim of hermetic bit-for-bit reproduction.
set -euo pipefail
export LC_ALL=C

manifest="$(mktemp)"
trap 'rm -f "$manifest"' EXIT

dpkg-query -W -f='${binary:Package}\t${Version}\n' | sort > "$manifest"
count="$(wc -l < "$manifest")"
fingerprint="$(sha256sum "$manifest" | cut -d ' ' -f 1)"

printf 'Runner image: %s / %s\n' "${ImageOS:-unknown}" "${ImageVersion:-unknown}"
printf 'Kernel: '; uname -srmo
printf 'Compiler: '; gcc --version | head -n 1
printf 'Clang: '; clang --version | head -n 1
printf 'Python: '; python3 --version
printf 'OpenSSL: '; openssl version
printf 'Installed package count: %s\n' "$count"
printf 'Full sorted Debian package manifest SHA-256: %s\n' "$fingerprint"
printf '%s\n' '--- START INSTALLED PACKAGE MANIFEST ---'
cat "$manifest"
printf '%s\n' '--- END INSTALLED PACKAGE MANIFEST ---'

# Verify that actual executables are Debian-owned and match locked versions,
# rather than relying on installed package records alone.
version_from_lock() {
  local value
  value=$(grep -E "^$1=" ci/toolchain.lock | cut -d= -f2-)
  value=${value#*:}
  printf '%s' "${value%%-*}"
}
assert_version() {
  if [[ "$2" != "$3" ]]; then
    printf '::error::%s executable version %s does not match pinned %s\n' "$1" "$2" "$3" >&2
    exit 2
  fi
}
for name in gcc clang python3 openssl; do
  path=$(command -v "$name") || { printf '::error::Executable %s missing\n' "$name" >&2; exit 2; }
  resolved=$(readlink -f "$path")
  if ! ownership=$(dpkg-query -S "$resolved"); then
    printf '::error::Executable %s (%s) is not owned by a Debian package\n' "$name" "$resolved" >&2
    exit 2
  fi
  case "$name:$ownership" in
    gcc:gcc-13*|clang:clang-18*|python3:python3.12*|openssl:openssl:*) ;;
    *) printf '::error::Unexpected package owner for %s: %s\n' "$name" "$ownership" >&2; exit 2 ;;
  esac
  printf 'Executable provenance: %s => %s (%s), SHA-256 %s\n' \
    "$name" "$resolved" "$ownership" "$(sha256sum "$resolved" | cut -d ' ' -f1)"
done
assert_version GCC "$(gcc -dumpfullversion)" "$(version_from_lock gcc-13)"
assert_version Clang "$(clang --version | sed -n '1s/.*clang version \([0-9.]*\).*/\1/p')" "$(version_from_lock clang-18)"
assert_version Python "$(python3 --version | awk '{print $2}')" "$(version_from_lock python3)"
assert_version OpenSSL "$(openssl version | awk '{print $2}')" "$(version_from_lock libssl-dev)"
for package in openssl libssl3t64; do
  actual=$(dpkg-query -W -f='${Version}' "$package")
  pinned=$(grep '^libssl-dev=' ci/toolchain.lock | cut -d= -f2-)
  if [[ "$actual" != "$pinned" ]]; then
    printf '::error::%s runtime package version %s differs from locked OpenSSL %s\n' "$package" "$actual" "$pinned" >&2
    exit 2
  fi
done


if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '### CI toolchain environment\n'
    printf -- '- Runner image: `%s / %s`\n' "${ImageOS:-unknown}" "${ImageVersion:-unknown}"
    printf -- '- Installed Debian packages: `%s`\n' "$count"
    printf -- '- Sorted package inventory SHA-256: `%s`\n' "$fingerprint"
    printf -- '- The full installed-package inventory is retained in this step log.\n'
    printf -- '- Full reproducibility is not guaranteed by hosted runner version tags or top-level APT pins.\n'
  } >> "$GITHUB_STEP_SUMMARY"
fi
