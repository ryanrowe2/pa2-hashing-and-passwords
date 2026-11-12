# Toolchain maintenance policy

Both the installer and weekly audit validate package entries and the single authoritative UTC snapshot date through the shared `ci/parse-toolchain-lock.py` parser. It requires exactly `build-essential`, `gcc`, `gcc-13`, `clang`, `clang-18`, `libssl-dev`, and `python3`, rejects invalid whitespace, malformed versions, duplicate or unexpected packages, and never emits partial arguments on a failed read. The application CI installs Ubuntu 24.04 toolchain packages from Ubuntu-signed current archives using the exact versions in `ci/toolchain.lock`, with executable provenance checked afterward. For historical snapshot replay, set `PA2_USE_SNAPSHOT=1` when invoking `ci/install-toolchain.sh`. Both modes pin identical top-level package versions. The installer and auditor use `ci/ubuntu-apt.sh` to isolate APT from all other sources, allowing only Ubuntu-signed archives through the Canonical archive keyring. In opt-in snapshot replay, if the snapshot index returns HTTP 502, 503 or 504 or exceeds the 30-second bounded index refresh without a signing/integrity error, the installer may fall back to current signed Ubuntu archives and must still install every exact locked version. Installation failures and other index errors never trigger fallback. Both paths reject partial APT refreshes. All seven locked package versions are verified after installation. Pinning protects builds against unreviewed dependency drift; it does not guarantee security updates or perfectly immutable runner images.

## Weekly monitoring

[The automated toolchain review workflow](../.github/workflows/toolchain-review.yml) runs every Monday at 09:23 UTC, on every pull request and push to main, and can also be dispatched manually. The same audit is enforced inside the required GCC quality job, so an available toolchain update cannot be ignored during merging even if the separate workflow is not configured as a required status check. It checks recent versions available in the Ubuntu apt repositories against each pinned version. Newer candidates cause an annotated failure; this is an update-availability signal, not a vulnerability scan. The review also fails on missing, empty, malformed, or duplicate entries in the lockfile, unavailable package metadata, and version-comparison errors. Exit status 0 means every tracked package was checked and no newer candidate was found; exit status 1 signals an available update; exit status 2 signals a validation or comparison failure. Ubuntu runner and GitHub Actions update notices should also be reviewed.

## Updating safely

1. Review the workflow failure or relevant Ubuntu security advisory. Determine the appropriate available and supported versions for each affected package.
2. Select a UTC APT snapshot timestamp containing the desired packages. Change `snapshot` in `ci/install-toolchain.sh` and the matching timestamp comment in `ci/toolchain.lock` together.
3. Update the exact Debian versions in `ci/toolchain.lock` and review direct and transitive dependencies. Document the rationale in the PR description.
4. Open a PR. Allow both `quality (gcc)` and `quality (clang)` to pass, including fault-injection tests, static analysis, and sanitizer builds.
5. Merge only after validation, confirm default-branch CI passes, and review the next weekly audit.

Document any accepted exceptions or deferrals instead of silently disabling the review.

## Offline regression checks

Run `python3 -m unittest discover -s tests -p 'test_toolchain_audit.py' -v` to exercise update-availability and error paths using local mock commands without contacting APT repositories. These checks also run automatically in the main C build-and-test GitHub Actions workflow.

## Environment provenance

The `ci/record-environment.sh` script runs after package installation in both compiler jobs, verifies Debian ownership and expected tool versions of the invoked compiler, Python and OpenSSL executables, checks matching runtime OpenSSL packages, and records executable SHA-256 hashes. It prints the complete sorted installed Debian package inventory to the workflow step log, its SHA-256 fingerprint, the runner image identifiers, kernel, and compiler/runtime versions. The job summary includes the fingerprint. This makes transitive dependency drift visible across runs without claiming bit-for-bit reproducibility. The Ubuntu snapshot pins selected direct packages, but transitive packages and GitHub-hosted runner image components are not fully locked. If hermetic builds become a requirement, migrate to a container with an immutable digest and audited transitive dependencies.

## Failure and regression guarantees

The dependency audit returns 2 on incomplete APT refreshes, metadata/lock errors, unavailable packages or comparison failures. Available newer packages return 1; fully checked, up-to-date pins return 0. The installer never silently selects third-party repositories and never reclassifies package-installation failures as snapshot outages. The shared parser validates the mandatory UTC snapshot timestamp; a missing, malformed or duplicate timestamp is rejected. End-to-end mocks test ordinary operation, partial update failures, package-installation failures, signing errors and snapshot HTTP 503 fallback.
