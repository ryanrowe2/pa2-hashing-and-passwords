# SHA-256 Candidate Verification in C

[![C build and tests](https://github.com/ryanrowe2/pa2-hashing-and-passwords/actions/workflows/ci.yml/badge.svg)](https://github.com/ryanrowe2/pa2-hashing-and-passwords/actions/workflows/ci.yml)

A compact, testable C11 program for verifying locally supplied candidate strings against a SHA-256 digest, including **one ASCII letter case change per candidate**. Originally developed for UC San Diego's Fall 2024 CSE 29 PA2 assignment; subsequently refactored for engineering reliability, automated verification, and clear portfolio presentation. Original history is retained.

## Build and run

Requires a C11 compiler, make, OpenSSL development headers/libcrypto, and Python 3 for integration tests.

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

`make test` checks exact and case-flip matches, invalid digests, empty input, EOF, large input, embedded NUL, multiple candidates, UTF-8 preservation, simulated cryptographic errors, input read failures, output write failures, broken pipes, streaming overlength rejection, and terminal-safe escaping. GitHub Actions runs these checks on Ubuntu 24.04, using a commit-pinned `actions/checkout` v7.0.1 action and minimum workflow permissions. Its Clang job additionally verifies build-configuration changes trigger recompilation and runs sanitizer and static-analysis checks. CI records compiler, Python, OpenSSL and installed package versions for reproducibility diagnostics; Ubuntu packages still receive upstream updates. Dependabot checks GitHub Actions dependencies weekly. Results should be verified in the Actions tab rather than assumed.

The algorithm performs at most **1 + a SHA-256 evaluations** per candidate, where a is the number of ASCII alphabetic bytes. At length n the worst-case total hashing work is O(n²), and working memory is O(1) under the fixed candidate-length bound. The optional benchmark reports local elapsed time, which includes startup and I/O overhead; it is not a portable performance claim.

## History, responsibility and limitations

The original PA2 course assignment instructions remain accessible in Git history, and the original written design discussion remains in `DESIGN.md`. Attribution is in `CREDITS.md`. This is a limited, educational candidate verification exercise, not a credential attack tool or a password-storage system. It uses locally supplied synthetic/authorized test data only and has no networking, credential collection, parallel searching or attack automation. Plain SHA-256 is not appropriate for secure password storage; use a password-specific algorithm such as Argon2id in real applications. See the [commit history](https://github.com/ryanrowe2/pa2-hashing-and-passwords/commits/main/).

## Build configuration and licensing

Make automatically recompiles binaries when the selected compiler, preprocessor/compiler/linker flags, linked libraries, or the Makefile itself change. The fault-injection tests use GNU/ELF linker `--wrap` and therefore target Linux toolchains. The project code and author-owned documentation are offered under the [MIT License](LICENSE); third-party course materials in history and the OpenSSL dependency are excluded. The historical [DESIGN.md](DESIGN.md) reflects the 2024 assignment, not the current code architecture.

## GitHub repository settings

Recommended repository description: **C11 SHA-256 candidate verification with defensive input handling, fault-injection tests, reproducible builds, and automated CI.** Suggested topics: `c`, `sha256`, `openssl`, `systems-programming`, `unit-testing`, `github-actions`. Protect `main` with a rule requiring the `quality (gcc)` and `quality (clang)` checks before merging. These GitHub settings are configured outside the source tree and must be verified in repository Settings; documentation here does not change them.
