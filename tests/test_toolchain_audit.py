"""Offline failure-path tests for the Ubuntu toolchain update audit."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("bash") and Path("/usr/bin/dpkg").exists(),
                     "requires Bash and Debian dpkg")
class ToolchainAuditTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pa2-audit-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "ci").mkdir()
        (self.root / "fake-bin").mkdir()
        shutil.copy2(ROOT / "ci" / "audit-toolchain.sh",
                     self.root / "ci" / "audit-toolchain.sh")
        self.lock = self.root / "ci" / "toolchain.lock"
        self.lock.write_text("gcc=1.2.3\n", encoding="utf-8")
        mocks = {
            "sudo": """#!/bin/sh
printf 'called' > fake-update-called.txt
if [ "${FAKE_APT_GET_ERROR:-}" = 1 ]; then exit 22; fi
exit 0
""",
            "apt-cache": """#!/bin/sh
if [ "${FAKE_APT_CACHE_ERROR:-}" = 1 ]; then exit 23; fi
if [ "${FAKE_NO_CANDIDATE:-}" = 1 ]; then
  printf ' Candidate: (none)\\n'
else
  printf ' Candidate: %s\\n' "${FAKE_CANDIDATE:-1.2.3}"
fi
""",
            "dpkg": """#!/bin/sh
if [ "${FAKE_DPKG_ERROR:-}" = 1 ]; then exit 2; fi
exec /usr/bin/dpkg "$@"
""",
        }
        for name, content in mocks.items():
            executable = self.root / "fake-bin" / name
            executable.write_text(content, encoding="utf-8")
            executable.chmod(0o755)

    def audit(self, **overrides):
        environment = os.environ.copy()
        environment["PATH"] = str(self.root / "fake-bin") + os.pathsep + environment["PATH"]
        for key in ("FAKE_APT_GET_ERROR", "FAKE_APT_CACHE_ERROR", "FAKE_NO_CANDIDATE",
                    "FAKE_DPKG_ERROR", "FAKE_CANDIDATE"):
            environment.pop(key, None)
        environment.update(overrides)
        return subprocess.run(
            ["bash", "ci/audit-toolchain.sh"], cwd=self.root,
            env=environment, capture_output=True, check=False, timeout=10,
        )

    def test_current_version_succeeds(self):
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"1 tracked", result.stdout)

    def test_older_available_version_succeeds(self):
        result = self.audit(FAKE_CANDIDATE="1.2.2")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_newer_version_requires_update(self):
        result = self.audit(FAKE_CANDIDATE="1.2.4")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"Toolchain update available", result.stdout)

    def test_dpkg_comparison_error_fails_closed(self):
        result = self.audit(FAKE_DPKG_ERROR="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"Version comparison failed", result.stderr)
        self.assertNotIn(b"No newer candidate", result.stdout)

    def test_empty_or_comment_only_lock_fails_without_apt(self):
        for content in ("", "# comment\n    # comment\n   \n"):
            with self.subTest(content=content):
                (self.root / "fake-update-called.txt").unlink(missing_ok=True)
                self.lock.write_text(content, encoding="utf-8")
                result = self.audit()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(b"no package versions", result.stderr)
                self.assertFalse((self.root / "fake-update-called.txt").exists())

    def test_malformed_or_duplicate_entries_fail(self):
        for content in ("gcc\n", "gcc=\n", "gcc=1.2.3\ngcc=1.2.4\n",
                        "gcc=1.2.3\ninvalid package=1.0\n",
                        "gcc=$(touch owned)\n", "gcc=1.2.3 garbage\n"):
            with self.subTest(content=content):
                self.lock.write_text(content, encoding="utf-8")
                result = self.audit()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(b"::error::", result.stderr)

    def test_last_line_without_newline_is_read(self):
        self.lock.write_text("# pinned\ngcc=1.2.3", encoding="utf-8")
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_package_lookup_failure_fails_closed(self):
        result = self.audit(FAKE_APT_CACHE_ERROR="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"Cannot query", result.stderr)

    def test_missing_candidate_fails_closed(self):
        result = self.audit(FAKE_NO_CANDIDATE="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"Cannot determine", result.stderr)

    def test_package_index_update_failure_propagates(self):
        result = self.audit(FAKE_APT_GET_ERROR="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"No newer candidate", result.stdout)


if __name__ == "__main__":
    unittest.main()
