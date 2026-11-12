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
