"""End-to-end regression tests using only synthetic local candidates."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BIN = Path(os.environ.get("PWCRACK_BIN", "build/pwcrack")).resolve()
FAULT_BIN = Path(os.environ.get("PWCRACK_FAULT_BIN", "build/pwcrack_sha_error")).resolve()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def escape_output(candidate: bytes) -> bytes:
    output = bytearray()
    for byte in candidate:
        if byte == 92:
            output.extend(b"\\\\")
        elif byte < 32 or byte > 126:
            output.extend(f"\\x{byte:02X}".encode("ascii"))
        else:
            output.append(byte)
    return bytes(output)


def run_cli(target: str, candidates: bytes = b"", *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(BIN), target, *extra],
        input=candidates,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )


class CLITests(unittest.TestCase):
    def assert_match(self, target: bytes, input_bytes: bytes, expected: bytes) -> None:
        h = digest(target)
        result = run_cli(h, input_bytes)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(
            result.stdout,
            b"Found password: SHA256(" + escape_output(expected) + b") = " + h.encode() + b"\n",
        )

    def test_exact_match(self) -> None:
        self.assert_match(b"example", b"example\n", b"example")

    def test_one_case_flip(self) -> None:
        self.assert_match(b"seCret", b"secret\n", b"seCret")

    def test_upper_to_lower(self) -> None:
        self.assert_match(b"password", b"paSsword\n", b"password")

    def test_multiple_candidates(self) -> None:
        self.assert_match(b"final", b"first\nsecond\nfinal\n", b"final")

    def test_empty_candidate(self) -> None:
        self.assert_match(b"", b"\n", b"")

    def test_no_final_newline(self) -> None:
        self.assert_match(b"final", b"final", b"final")

    def test_boundary_length(self) -> None:
        value = b"a" * 1023
        self.assert_match(value, value + b"\n", value)

    def test_empty_stdin(self) -> None:
        result = run_cli(digest(b"something"))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"Did not find a matching password\n")

    def test_no_match_and_no_multiflip(self) -> None:
        result = run_cli(digest(b"seCret"), b"SECRET\nother\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"Did not find a matching password\n")

    def test_uppercase_digest(self) -> None:
        h = digest(b"sample").upper()
        result = run_cli(h, b"sample\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, f"Found password: SHA256(sample) = {h}\n".encode())

    def test_missing_argument(self) -> None:
        result = subprocess.run([str(BIN)], capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"Usage:", result.stderr)
        self.assertEqual(result.stdout, b"")

    @unittest.skipUnless(os.name == "posix", "requires executable symlinks")
    def test_usage_diagnostic_rejects_terminal_control_in_invocation_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwcrack-usage-") as directory:
            executable = Path(directory) / ("pw" + chr(27) + "[31mcrack")
            executable.symlink_to(BIN)
            result = subprocess.run([str(executable)], capture_output=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(bytes([27]), result.stderr)
            self.assertEqual(result.stderr,
                             b"Usage: pwcrack <64-character SHA-256 hex digest>\n")

    def test_extra_argument(self) -> None:
        result = run_cli(digest(b"sample"), b"sample\n", "extra")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"Usage:", result.stderr)

    def test_invalid_digest_lengths(self) -> None:
        for value in ("", "abc", "0" * 63, "0" * 65):
            with self.subTest(length=len(value)):
                result = run_cli(value)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"exactly 64", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_invalid_digest_characters(self) -> None:
        for value in ("g" + "0" * 63, "0" * 63 + "z", "0" * 20 + ":" + "0" * 43):
            with self.subTest(value=value):
                result = run_cli(value)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"hexadecimal", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_overlong_line_rejected_without_fragmentation(self) -> None:
        # The first 1023 bytes match the target, but the entire input line
        # is invalid; it must not silently match the truncated fragment.
        result = run_cli(digest(b"x" * 1023), b"x" * 1024 + b"\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"line 1 exceeds 1023", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_overlong_line_without_newline(self) -> None:
        result = run_cli(digest(b"x"), b"y" * 1024)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"exceeds 1023", result.stderr)

    def test_overlong_second_line(self) -> None:
        result = run_cli(digest(b"absent"), b"short\n" + b"x" * 1024 + b"\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"line 2 exceeds", result.stderr)

    def test_embedded_nul_rejected(self) -> None:
        result = run_cli(digest(b"abc"), b"abc\x00spoof\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"NUL byte", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_utf8_candidate(self) -> None:
        self.assert_match("caféA".encode(), "caféa".encode() + b"\n", "caféA".encode())

    @unittest.skipUnless(os.name == "posix", "requires POSIX pipes")
    def test_closed_stdout_pipe_is_handled_as_error(self) -> None:
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = subprocess.run(
                [str(BIN), digest(b"hello")], input=b"hello\n",
                stdout=writer, stderr=subprocess.PIPE, check=False, timeout=10,
            )
        finally:
            os.close(writer)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"unable to write standard output", result.stderr)

    def test_streaming_oversized_line_rejected_before_eof(self) -> None:
        process = subprocess.Popen(
            [str(BIN), digest(b"irrelevant")], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            assert process.stdin is not None
            process.stdin.write(b"x" * 1024)
            process.stdin.flush()
            try:
                code = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.fail("oversized input was not rejected before EOF")
            self.assertEqual(code, 2)
            assert process.stderr is not None
            self.assertIn(b"exceeds 1023", process.stderr.read())
        finally:
            if process.poll() is None:
                process.kill()
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            process.wait(timeout=3)

    def test_terminal_control_bytes_escaped(self) -> None:
        raw = b"head\x1b[31m\r\t\\tail"
        result = run_cli(digest(raw), raw + b"\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            b"Found password: SHA256(head\\x1B[31m\\x0D\\x09\\\\tail) = "
            + digest(raw).encode() + b"\n",
        )
        self.assertNotIn(b"\x1b", result.stdout)
        self.assertNotIn(b"\r", result.stdout)

    def test_non_ascii_bytes_are_escaped(self) -> None:
        raw = "caf\u00e9".encode("utf-8")
        result = run_cli(digest(raw), raw + b"\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"SHA256(caf\\xC3\\xA9)", result.stdout)
        self.assertTrue(result.stdout.isascii())

    @unittest.skipUnless(os.path.exists("/dev/full"), "requires /dev/full")
    def test_stdout_failure_on_match(self) -> None:
        with open("/dev/full", "wb") as output:
            result = subprocess.run(
                [str(BIN), digest(b"secret")], input=b"secret\n",
                stdout=output, stderr=subprocess.PIPE, check=False, timeout=10,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"unable to write standard output", result.stderr)

    @unittest.skipUnless(os.path.exists("/dev/full"), "requires /dev/full")
    def test_stdout_failure_on_no_match(self) -> None:
        with open("/dev/full", "wb") as output:
            result = subprocess.run(
                [str(BIN), digest(b"not-present")], input=b"candidate\n",
                stdout=output, stderr=subprocess.PIPE, check=False, timeout=10,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"unable to write standard output", result.stderr)

    @unittest.skipUnless(os.name == "posix", "requires POSIX directory file descriptors")
    def test_stdin_read_failure(self) -> None:
        directory_fd = os.open(".", os.O_RDONLY)
        try:
            result = subprocess.run(
                [str(BIN), digest(b"something")], stdin=directory_fd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=10,
            )
        finally:
            os.close(directory_fd)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"unable to read standard input", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_sha256_failure_reported_by_cli(self) -> None:
        result = subprocess.run(
            [str(FAULT_BIN), digest(b"secret")], input=b"secret\n",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"SHA-256 calculation failed", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_long_stream_of_nonmatches(self) -> None:
        data = b"".join(f"candidate-{i:04d}\n".encode() for i in range(1000))
        result = run_cli(digest(b"deliberately-not-in-input"), data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"Did not find a matching password\n")


if __name__ == "__main__":
    unittest.main()
