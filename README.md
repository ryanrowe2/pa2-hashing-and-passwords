# SHA-256 Candidate Verification in C

[![C build and tests](https://github.com/ryanrowe2/pa2-hashing-and-passwords/actions/workflows/ci.yml/badge.svg)](https://github.com/ryanrowe2/pa2-hashing-and-passwords/actions/workflows/ci.yml)

A compact, testable C11 program for verifying locally supplied candidate strings against a SHA-256 digest, including **one ASCII letter case change per candidate**. Originally developed for UC San Diego's Fall 2024 CSE 29 PA2 assignment; subsequently refactored for engineering reliability, automated verification, and clear portfolio presentation. Original history is retained.

## Build and run

Supported build environment: Linux (Ubuntu 24.04 in CI), GNU Make, util-linux `flock`, a C11 compiler (GCC or Clang), OpenSSL development headers/libcrypto, and Python 3 for integration tests. Fault-injection test builds additionally use the GNU/ELF linker `--wrap` option.

```sh
make
printf 'not-it\nsecret\n' | ./build/pwcrack a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd
```

Output:

```text
Found password: SHA256(seCret) = a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd
```

The example uses synthetic test strings. A SHA-256 argument must have exactly 64 ASCII hexadecimal characters, in either case.

## Input contract

- Read one candidate per standard-input line. Remove only the LF line separator.
- Accept empty candidates and an unterminated final line.
- Maximum candidate length: **1,023 bytes**, not Unicode code points.
- Reject overlong lines immediately at the 1,024th byte, embedded NUL immediately, invalid digest arguments, and read, output-write, and cryptographic failures with an error on stderr and exit status **2**.
- Check the exact candidate, then every variation with one ASCII A–Z/a–z letter's case flipped. Non-ASCII UTF-8 bytes are preserved. Multiple flips are not combined.
- On success, print the first matching candidate with terminal-safe byte escapes and return **0**. After normal EOF without a match, print `Did not find a matching password` and return **0**.
- CRLF input retains CR as a candidate byte. Output encodes backslashes as `\\`, and control or non-ASCII bytes as `\xHH` (uppercase hex); for example, UTF-8 `é` becomes `\xC3\xA9`. The hash is always checked against the original, unescaped bytes. On POSIX, a broken output pipe is reported with exit status 2.

## Structure

| File | Role |
| --- | --- |
| `src/main.c` | CLI validation, bounded line reader, diagnostics |
| `src/pwcrack.c` | Hex decoding, SHA-256 comparison, case variations |
| `include/pwcrack.h` | Public interface and input limit |
| `tests/test_core.c` | Unit assertions |
| `tests/test_fault.c`, `tests/sha256_fail.c` | Injected cryptographic failure checks |
| `tests/test_cli.py` | End-to-end and malformed-input regression suite |
| `tests/benchmark.py` | Synthetic-input timing |
| `.github/workflows/ci.yml` | GCC/Clang, tests, analyzer, ASan/UBSan |

## Verify

```sh
make clean && make test
make analyze
make CC=clang SANITIZE=1 test
make CC=gcc test
make bench
```

`make test` checks exact and case-flip matches, invalid digests, empty input, EOF, large input, embedded NUL, multiple candidates, UTF-8 preservation, simulated cryptographic errors, input read failures, output write failures, broken pipes, streaming overlength rejection, and terminal-safe escaping. GitHub Actions runs these checks on Ubuntu 24.04, using a commit-pinned `actions/checkout` v7.0.1 action and minimum workflow permissions. Its Clang job additionally verifies build-configuration changes trigger recompilation and runs sanitizer and static-analysis checks. CI installs exact GCC, Clang, OpenSSL development, and Python package versions from Canonical-signed Ubuntu archive repositories; historical snapshot replay (`PA2_USE_SNAPSHOT=1`) is also available, with fail-closed fallback solely to signed Ubuntu archives after snapshot HTTP 502/503/504 index outages or bounded availability timeouts, using [ci/toolchain.lock](ci/toolchain.lock) and [ci/install-toolchain.sh](ci/install-toolchain.sh). It verifies installed versions and logs compiler and dependency metadata. When updating the toolchain, advance the snapshot and lock versions together in a reviewed pull request. The toolchain update audit also runs inside the required GCC quality job, and the standalone review workflow runs on all PRs and main pushes as well as weekly. Both compiler jobs verify tool executable ownership and expected versions, confirm OpenSSL runtime packages, and record executable hashes plus the full installed Debian package inventory and a SHA-256 fingerprint in their workflow logs. This is a traceable environment snapshot, not a guarantee of hermetic builds. Dependabot checks GitHub Actions dependencies weekly. Results should be verified in the Actions tab rather than assumed.

The algorithm performs at most **1 + a SHA-256 evaluations** per candidate, where a is the number of ASCII alphabetic bytes. At length n the worst-case total hashing work is O(n²), and working memory is O(1) under the fixed candidate-length bound. The optional benchmark reports local elapsed time, which includes startup and I/O overhead; it is not a portable performance claim.

## History, responsibility and limitations

The original PA2 course assignment instructions remain accessible in Git history, and the original written design discussion remains in `DESIGN.md`. Attribution is in `CREDITS.md`. This is a limited, educational candidate verification exercise, not a credential attack tool or a password-storage system. It uses locally supplied synthetic/authorized test data only and has no networking, credential collection, parallel searching or attack automation. Plain SHA-256 is not appropriate for secure password storage; use a password-specific algorithm such as Argon2id in real applications. See the [commit history](https://github.com/ryanrowe2/pa2-hashing-and-passwords/commits/main/).

## Build configuration and licensing

Make automatically recompiles binaries when the selected compiler, preprocessor/compiler/linker flags, linked libraries, or the Makefile itself change. All generated executables are compiled to temporary files and atomically renamed only after a successful build; failed compiler invocations preserve previously valid binaries and clean temporary outputs. `.DELETE_ON_ERROR` guards against failed targets. Concurrent, independent Make processes are serialized by `flock` (util-linux) over the complete build/test invocation. The ignored `.pa2-build.lock` file is intentionally stored at repository root so `make clean` cannot invalidate an active lock; shared `build/` outputs correspond to the last completed compiler configuration. Compile and configuration-stamp temporary files include the shell process ID and are cleaned on errors. The fault-injection tests use GNU/ELF linker `--wrap` and therefore target Linux toolchains. The project code and author-owned documentation are offered under the [MIT License](LICENSE); third-party course materials in history and the OpenSSL dependency are excluded. The historical [DESIGN.md](DESIGN.md) reflects the 2024 assignment, not the current code architecture.

## GitHub repository settings

Recommended repository description: **C11 SHA-256 candidate verification with defensive input handling, fault-injection tests, reproducible builds, and automated CI.** Suggested topics: `c`, `sha256`, `openssl`, `systems-programming`, `unit-testing`, `github-actions`. Protect `main` with a rule requiring the `quality (gcc)` and `quality (clang)` checks before merging. The required GCC check itself runs the toolchain audit; optionally also require the standalone `check-toolchain-updates` status. For independent review, configure at least one non-author approval if a second maintainer is available. Verified active repository settings (November 11, 2026): [Protect main](https://github.com/ryanrowe2/pa2-hashing-and-passwords/settings/rules/27086339) applies to `main` and requires pull requests plus `quality (gcc)` and `quality (clang)`, blocks force pushes and deletion, and has no bypass actors. The repository description and all six topics above are saved. Strict up-to-date required status checks are enabled in the active `Protect main` ruleset; GitHub administration should be rechecked after future configuration changes.

## Maintenance and workflow policy

Make inspection options (`-n`/`--just-print` and `-q`/`--question`) inspect the build without acquiring the build lock or changing generated files. GNU Make `-t`/`--touch` is intentionally rejected: it would otherwise create empty binaries or incorrectly create a regular file named `build` on a fresh tree. For a concrete up-to-date target, `make -q` exits 0; missing, stale, or differently configured binaries return 1 without updating the build stamp. The read-only configuration comparison prevents the normal forced stamp check from producing false stale results. Standard CI runs on pull requests and on pushes to `main`, avoiding duplicate feature-branch CI. New regression tests cover an interrupted/failed compiler and early argument errors with closed stderr pipes. A [toolchain update check](.github/workflows/toolchain-review.yml) checks newer available Ubuntu packages on every pull request, every push to main and every Monday, and validates the monitoring workflow whenever any code changes; see [the toolchain maintenance policy](ci/TOOLCHAIN.md) for the review and update procedure. Toolchain review failures indicate packages to inspect, not necessarily security vulnerabilities.
