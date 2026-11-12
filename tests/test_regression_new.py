"""Regression coverage for error handling and failure-safe incremental builds."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("PWCRACK_BIN", ROOT / "build" / "pwcrack")).resolve()


class EarlyBrokenPipeTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "requires POSIX pipes")
    def test_argument_diagnostics_with_closed_stderr_pipe(self):
        for args in ([], ["invalid"]):
            with self.subTest(args=args):
                reader, writer = os.pipe()
                os.close(reader)
                try:
                    result = subprocess.run(
                        [str(BIN), *args], input=b"", stdout=subprocess.PIPE,
                        stderr=writer, check=False, timeout=10,
                    )
                finally:
                    os.close(writer)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")


class FailedBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cwd = Path(self.temp.name)
        shutil.copy2(ROOT / "Makefile", self.cwd / "Makefile")
        shutil.copytree(ROOT / "src", self.cwd / "src")
        shutil.copytree(ROOT / "include", self.cwd / "include")
        self.failing_compiler = self.cwd / "fake-cc"
        self.failing_compiler.write_text("""#!/usr/bin/env python3
import pathlib, sys
out = sys.argv[sys.argv.index('-o') + 1]
pathlib.Path(out).write_bytes(b'partial or corrupted executable')
sys.exit(17)
""")
        self.failing_compiler.chmod(0o755)

    def run_make(self, compiler):
        return subprocess.run(
            ["make", "CC=" + str(compiler), "build/pwcrack"],
            cwd=self.cwd, capture_output=True, check=False, timeout=30,
        )

    def test_failed_initial_build_does_not_leave_output(self):
        bad = self.run_make(self.failing_compiler)
        self.assertNotEqual(bad.returncode, 0, bad.stdout.decode())
        self.assertFalse((self.cwd / "build/pwcrack").exists())
        self.assertEqual(list((self.cwd / "build").glob("pwcrack.tmp.*")), [])
        good = self.run_make("gcc")
        self.assertEqual(good.returncode, 0, good.stderr.decode())
        self.assertTrue((self.cwd / "build/pwcrack").is_file())

    def test_failed_rebuild_preserves_existing_binary_and_retries(self):
        good = self.run_make("gcc")
        self.assertEqual(good.returncode, 0, good.stderr.decode())
        exe = self.cwd / "build/pwcrack"
        existing = exe.read_bytes()
        for _ in range(2):
            failed = self.run_make(self.failing_compiler)
            self.assertNotEqual(failed.returncode, 0, failed.stdout.decode())
            self.assertEqual(exe.read_bytes(), existing)
            self.assertEqual(list((self.cwd / "build").glob("pwcrack.tmp.*")), [])
        ok = self.run_make("gcc")
        self.assertEqual(ok.returncode, 0, ok.stderr.decode())
        result = subprocess.run(
            [str(exe), hashlib.sha256(b"example").hexdigest()],
            input=b"example\n", capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"Found password:", result.stdout)
