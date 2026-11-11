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
- Reject overlong lines, embedded NUL, invalid digest arguments, and read failures with an error on stderr and exit status **2**.
- Check the exact candidate, then every variation with one ASCII A–Z/a–z letter's case flipped. Non-ASCII UTF-8 bytes are preserved. Multiple flips are not combined.
- On success, print the first matching candidate and return **0**. After normal EOF without a match, print `Did not find a matching password` and return **0**.
- CRLF input retains CR as a candidate byte. Output reproduces matched input bytes literally; use trusted test data.

## Structure

| File | Role |
| --- | --- |
| `src/main.c` | CLI validation, bounded line reader, diagnostics |
| `src/pwcrack.c` | Hex decoding, SHA-256 comparison, case variations |
| `include/pwcrack.h` | Public interface and input limit |
| `tests/test_core.c` | Unit assertions |
| `tests/test_cli.py` | End-to-end and malformed-input regression suite |
| `tests/benchmark.py` | Synthetic-input timing |
| `.github/workflows/ci.yml` | GCC/Clang, tests, analyzer, ASan/UBSan |

## Verify

```sh
make clean && make test
make analyze
make clean && make CC=clang SANITIZE=1 test
make clean && make CC=gcc test
make bench
```

`make test` checks exact and case-flip matches, invalid digests, empty input, EOF, large input, embedded NUL, multiple candidates, and UTF-8 preservation. GitHub Actions runs the same checks on Ubuntu, including sanitizer and Clang static-analysis jobs. Results should be verified in the Actions tab rather than assumed.

The algorithm performs at most **1 + a SHA-256 evaluations** per candidate, where a is the number of ASCII alphabetic bytes. At length n the worst-case total hashing work is O(n²), and working memory is O(1) under the fixed candidate-length bound. The optional benchmark reports local elapsed time, which includes startup and I/O overhead; it is not a portable performance claim.

## History, responsibility and limitations

The original PA2 course assignment instructions remain accessible in Git history, and the original written design discussion remains in `DESIGN.md`. Attribution is in `CREDITS.md`. This is a limited, educational candidate verification exercise, not a credential attack tool or a password-storage system. It uses locally supplied synthetic/authorized test data only and has no networking, credential collection, parallel searching or attack automation. Plain SHA-256 is not appropriate for secure password storage; use a password-specific algorithm such as Argon2id in real applications. See the [commit history](https://github.com/ryanrowe2/pa2-hashing-and-passwords/commits/main/).
