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
        cases = (
            (("-n",), 0), (("--just-print",), 0),
            (("-n", "-j4"), 0), (("-q",), 1),
            (("--question",), 1), (("--no-print-directory", "-n"), 0),
        )
        for flags, expected in cases:
            with self.subTest(flags=flags):
                result = self.invoke(*flags, "build/pwcrack")
                self.assertEqual(result.returncode, expected, result.stderr.decode())
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
        for flags in (("-n",), ("-q",), ("--question",),
                      ("--no-print-directory", "-n")):
            with self.subTest(flags=flags):
                result = self.invoke(*flags, "CC=gcc", "build/pwcrack")
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), original_hash)
                self.assertEqual((self.root / "build/.build-config").read_bytes(), stamp)
                self.assertEqual(locked.stat().st_mtime_ns, lock_mtime)

    def test_question_mode_detects_compiler_changes_without_writing(self):
        result = self.invoke("CC=gcc", "build/pwcrack")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        original_stamp = (self.root / "build/.build-config").read_bytes()
        original_hash = hashlib.sha256((self.root / "build/pwcrack").read_bytes()).hexdigest()
        for compiler in ("clang", "gcc"):
            for flags in (("-q",), ("--question",)):
                with self.subTest(compiler=compiler, flags=flags):
                    changed = self.invoke(*flags, "CC=" + compiler,
                                          "CFLAGS=-std=c11 -O0", "build/pwcrack")
                    self.assertEqual(changed.returncode, 1, changed.stderr.decode())
                    self.assertEqual((self.root / "build/.build-config").read_bytes(), original_stamp)
                    self.assertEqual(hashlib.sha256((self.root / "build/pwcrack").read_bytes()).hexdigest(), original_hash)
        self.assertEqual(self.invoke("-q", "CC=gcc", "build/pwcrack").returncode, 0)
        self.assertEqual(self.invoke("-q", "CC=gcc", "all").returncode, 0)

    def test_question_mode_recognizes_compiler_rebuild(self):
        first = self.invoke("CC=gcc", "build/pwcrack")
        self.assertEqual(first.returncode, 0, first.stderr.decode())
        self.assertEqual(self.invoke("-q", "CC=clang", "build/pwcrack").returncode, 1)
        changed = self.invoke("CC=clang", "build/pwcrack")
        self.assertEqual(changed.returncode, 0, changed.stderr.decode())
        self.assertEqual(self.invoke("-q", "CC=clang", "build/pwcrack").returncode, 0)
        self.assertEqual(self.invoke("-q", "CC=gcc", "build/pwcrack").returncode, 1)

    def test_touch_mode_rejected_before_creating_poisoned_build_artifacts(self):
        for flags in (("-t",), ("--touch",), ("-nt",)):
            with self.subTest(flags=flags):
                result = self.invoke(*flags, "build/pwcrack")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "build").exists())
                self.assertFalse((self.root / ".pa2-build.lock").exists())

    def test_touch_mode_rejected_without_modifying_existing_binary(self):
        result = self.invoke("CC=gcc", "build/pwcrack")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        binary = self.root / "build/pwcrack"
        original = binary.read_bytes()
        for flags in (("-t",), ("--touch",)):
            self.assertNotEqual(self.invoke(*flags, "build/pwcrack").returncode, 0)
            self.assertEqual(binary.read_bytes(), original)

    def test_normal_make_still_uses_lock_with_long_option(self):
        result = self.invoke("--no-print-directory", "CC=gcc", "build/pwcrack")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue((self.root / ".pa2-build.lock").is_file())
        self.assertTrue((self.root / "build/pwcrack").is_file())
