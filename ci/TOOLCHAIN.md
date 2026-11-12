# Toolchain maintenance policy

The application CI installs Ubuntu 24.04 toolchain packages from the dated APT snapshot specified in `ci/install-toolchain.sh`, with package versions checked against `ci/toolchain.lock`. Pinning protects builds against unreviewed dependency drift; it does not guarantee security updates or perfectly immutable runner images.

## Weekly monitoring

[The automated toolchain review workflow](../.github/workflows/toolchain-review.yml) runs every Monday at 09:23 UTC and is also manually dispatchable. It checks recent versions available in the Ubuntu apt repositories against each pinned version. Newer candidates cause an annotated failure; this is an update-availability signal, not a vulnerability scan. Ubuntu runner and GitHub Actions update notices should also be reviewed.

## Updating safely

1. Review the workflow failure or relevant Ubuntu security advisory. Determine the appropriate available and supported versions for each affected package.
2. Select a UTC APT snapshot timestamp containing the desired packages. Change `snapshot` in `ci/install-toolchain.sh` and the matching timestamp comment in `ci/toolchain.lock` together.
3. Update the exact Debian versions in `ci/toolchain.lock` and review direct and transitive dependencies. Document the rationale in the PR description.
4. Open a PR. Allow both `quality (gcc)` and `quality (clang)` to pass, including fault-injection tests, static analysis, and sanitizer builds.
5. Merge only after validation, confirm default-branch CI passes, and review the next weekly audit.

Document any accepted exceptions or deferrals instead of silently disabling the review.
