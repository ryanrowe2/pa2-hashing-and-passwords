"""Ensure Make inspection modes never change the working tree."""
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("make"), "requires GNU Make")
class MakeInspectionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pa2-inspect-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copy2(ROOT / "Makefile", self.root / "Makefile")
        shutil.copytree(ROOT / "src", self.root / "src")
        shutil.copytree(ROOT / "include", self.root / "include")

    def invoke(self, *args):
        return subprocess.run(["make", *args], cwd=self.root,
                              capture_output=True, check=False, timeout=20)

    def test_inspection_modes_do_not_create_lock_or_build_artifacts(self):
        for flags in (("-n",), ("--just-print",), ("-n", "-j4"),
                      ("-q",), ("--question",), ("--no-print-directory", "-n")):
            with self.subTest(flags=flags):
                result = self.invoke(*flags, "build/pwcrack")
                self.assertIn(result.returncode, (0, 1), result.stderr.decode())
                self.assertFalse((self.root / ".pa2-build.lock").exists())
                self.assertFalse((self.root / "build").exists())

    def test_inspection_modes_do_not_modify_completed_build(self):
        build = self.invoke("CC=gcc", "build/pwcrack")
        self.assertEqual(build.returncode, 0, build.stderr.decode())
        binary = self.root / "build/pwcrack"
        locked = self.root / ".pa2-build.lock"
        self.assertTrue(binary.is_file())
        self.assertTrue(locked.is_file())
        original_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        stamp = (self.root / "build/.build-config").read_bytes()
        lock_mtime = locked.stat().st_mtime_ns
        for flags in (("-n",), ("-q",), ("--no-print-directory", "-n")):
            with self.subTest(flags=flags):
                result = self.invoke(*flags, "build/pwcrack")
                self.assertIn(result.returncode, (0, 1), result.stderr.decode())
                self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), original_hash)
                self.assertEqual((self.root / "build/.build-config").read_bytes(), stamp)
                self.assertEqual(locked.stat().st_mtime_ns, lock_mtime)

    def test_normal_make_still_uses_lock_with_long_option(self):
        result = self.invoke("--no-print-directory", "CC=gcc", "build/pwcrack")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue((self.root / ".pa2-build.lock").is_file())
        self.assertTrue((self.root / "build/pwcrack").is_file())
