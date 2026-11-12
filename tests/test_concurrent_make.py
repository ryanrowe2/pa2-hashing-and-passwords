"""Regression tests for independent concurrent GNU Make invocations."""

import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    shutil.which("flock") and shutil.which("gcc") and shutil.which("clang"),
    "requires flock, GCC and Clang on Linux",
)
class ConcurrentBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pwcrack-parallel-")
        self.addCleanup(self.temp.cleanup)
        self.cwd = Path(self.temp.name)
        shutil.copy2(ROOT / "Makefile", self.cwd / "Makefile")
        shutil.copytree(ROOT / "src", self.cwd / "src")
        shutil.copytree(ROOT / "include", self.cwd / "include")

    def test_parallel_same_and_different_compilers(self):
        # Independent Make processes previously raced over .build-config.tmp.
        # A single Make -j invocation did not reproduce the original defect.
        for compilers in (
            ("gcc", "gcc", "gcc", "gcc"),
            ("clang", "gcc", "clang", "gcc"),
            ("gcc", "clang", "gcc", "clang"),
        ):
            with self.subTest(compilers=compilers):
                processes = [
                    subprocess.Popen(
                        ["make", "CC=" + compiler, "build/pwcrack"],
                        cwd=self.cwd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    for compiler in compilers
                ]
                for proc in processes:
                    try:
                        stdout, stderr = proc.communicate(timeout=35)
                    finally:
                        if proc.poll() is None:
                            proc.kill()
                            proc.communicate(timeout=5)
                    self.assertEqual(
                        proc.returncode, 0,
                        f"concurrent Make failed:\n{stdout.decode()}\n{stderr.decode()}",
                    )

                stamp = (self.cwd / "build/.build-config").read_text()
                self.assertEqual(
                    len([line for line in stamp.splitlines() if line.startswith("CC=")]),
                    1,
                )
                self.assertIn(stamp.splitlines()[0], ("CC=gcc", "CC=clang"))
                self.assertEqual(list((self.cwd / "build").glob("*.tmp.*")), [])

                digest = hashlib.sha256(b"example").hexdigest()
                result = subprocess.run(
                    [str(self.cwd / "build/pwcrack"), digest],
                    input=b"example\n",
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b"Found password:", result.stdout)

    def test_clean_preserves_persistent_lock_inode(self):
        result = subprocess.run(
            ["make", "CC=gcc", "build/pwcrack"],
            cwd=self.cwd, capture_output=True, check=False, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        clean = subprocess.run(
            ["make", "clean"], cwd=self.cwd,
            capture_output=True, check=False, timeout=30,
        )
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertTrue((self.cwd / ".pa2-build.lock").is_file())
        self.assertFalse((self.cwd / "build").exists())

    def test_compiler_receives_unique_temporary_output_path(self):
        fake = self.cwd / "record-failing-cc"
        fake.write_text("""#!/usr/bin/env python3
import pathlib, sys
output = sys.argv[sys.argv.index('-o') + 1]
pathlib.Path('compiler-output-path.txt').write_text(output)
pathlib.Path(output).write_bytes(b'partial')
sys.exit(17)
""")
        fake.chmod(0o755)
        result = subprocess.run(
            ["make", "CC=" + str(fake), "build/pwcrack"],
            cwd=self.cwd, capture_output=True, check=False, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        output = (self.cwd / "compiler-output-path.txt").read_text()
        self.assertTrue(output.startswith("build/pwcrack.tmp."), output)
        suffix = output.rsplit(".", 1)[-1]
        self.assertTrue(suffix.isdecimal(), output)
        self.assertFalse((self.cwd / output).exists(), output)
        self.assertFalse((self.cwd / "build/pwcrack").exists())
