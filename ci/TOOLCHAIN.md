# Toolchain maintenance policy

Both the installer and weekly audit validate package entries through the shared `ci/parse-toolchain-lock.py` parser. It requires exactly `build-essential`, `gcc`, `gcc-13`, `clang`, `clang-18`, `libssl-dev`, and `python3`, rejects invalid whitespace, malformed versions, duplicate or unexpected packages, and never emits partial arguments on a failed read. The application CI installs Ubuntu 24.04 toolchain packages from the dated APT snapshot specified in `ci/install-toolchain.sh`, with package versions checked against `ci/toolchain.lock`. Pinning protects builds against unreviewed dependency drift; it does not guarantee security updates or perfectly immutable runner images.

## Weekly monitoring

[The automated toolchain review workflow](../.github/workflows/toolchain-review.yml) runs every Monday at 09:23 UTC and is also manually dispatchable. It checks recent versions available in the Ubuntu apt repositories against each pinned version. Newer candidates cause an annotated failure; this is an update-availability signal, not a vulnerability scan. The review also fails on missing, empty, malformed, or duplicate entries in the lockfile, unavailable package metadata, and version-comparison errors. Exit status 0 means every tracked package was checked and no newer candidate was found; exit status 1 signals an available update; exit status 2 signals a validation or comparison failure. Ubuntu runner and GitHub Actions update notices should also be reviewed.

## Updating safely

1. Review the workflow failure or relevant Ubuntu security advisory. Determine the appropriate available and supported versions for each affected package.
2. Select a UTC APT snapshot timestamp containing the desired packages. Change `snapshot` in `ci/install-toolchain.sh` and the matching timestamp comment in `ci/toolchain.lock` together.
3. Update the exact Debian versions in `ci/toolchain.lock` and review direct and transitive dependencies. Document the rationale in the PR description.
4. Open a PR. Allow both `quality (gcc)` and `quality (clang)` to pass, including fault-injection tests, static analysis, and sanitizer builds.
5. Merge only after validation, confirm default-branch CI passes, and review the next weekly audit.

Document any accepted exceptions or deferrals instead of silently disabling the review.

## Offline regression checks

Run `python3 -m unittest discover -s tests -p 'test_toolchain_audit.py' -v` to exercise update-availability and error paths using local mock commands without contacting APT repositories. These checks also run automatically in the main C build-and-test GitHub Actions workflow.
