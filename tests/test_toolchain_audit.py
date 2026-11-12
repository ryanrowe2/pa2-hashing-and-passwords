"""Hermetic tests of the shared toolchain lock parser, installer and audit."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("build-essential", "gcc", "gcc-13", "clang", "clang-18",
            "libssl-dev", "python3")


@unittest.skipUnless(shutil.which("bash") and Path("/usr/bin/dpkg").exists(),
                     "requires Bash and Debian dpkg")
class ToolchainAuditTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pa2-lock-")
        self.addCleanup(temp.cleanup)
        self.cwd = Path(temp.name)
        (self.cwd / "ci").mkdir()
        fake = self.cwd / "fake"
        fake.mkdir()
        for file in ("parse-toolchain-lock.py", "audit-toolchain.sh",
                     "install-toolchain.sh", "ubuntu-apt.sh"):
            shutil.copy2(ROOT / "ci" / file, self.cwd / "ci" / file)
        self.lock = self.cwd / "ci" / "toolchain.lock"
        self.set_lock()
        commands = {
            "sudo": """#!/bin/sh
printf '%s\\n' "$*" >> sudo.log
case "$*" in
  *pa2-snapshot.list*' update '*|*pa2-snapshot.list*' update -qq'*)
    if [ "${FAIL_SNAPSHOT:-}" = 1 ]; then
      printf 'E: Failed to fetch https://snapshot.ubuntu.com/ubuntu/20261111T000000Z/dists/noble/InRelease  503  Service Unavailable\\n' >&2
      if [ "${BAD_SIGNATURE:-}" = 1 ]; then echo 'NO_PUBKEY' >&2; fi
      exit 26
    fi
    ;;
esac
case " $* " in
  *' update '*)
    if [ "${FAIL_UPDATE:-}" = 1 ]; then exit 22; fi
    if [ "${PARTIAL_INDEX:-}" = 1 ]; then
      printf 'W: Failed to fetch some package indexes (cached indexes used)\\n' >&2
      case "$*" in *APT::Update::Error-Mode=any*) exit 100;; esac
    fi
    ;;
  *' install '*)
    if [ "${FAIL_INSTALL:-}" = 1 ]; then exit 23; fi
    ;;
esac
exit 0
""",
            "apt-cache": """#!/bin/sh
if [ "${FAIL_POLICY:-}" = 1 ]; then exit 24; fi
printf ' Candidate: %s\n' "${CANDIDATE:-1.2.3}"
""",
            "dpkg": """#!/bin/sh
if [ "${FAIL_COMPARE:-}" = 1 ]; then exit 2; fi
exec /usr/bin/dpkg "$@"
""",
            "dpkg-query": """#!/bin/sh
if [ "${FAIL_QUERY:-}" = 1 ]; then exit 25; fi
printf '%s' "${INSTALLED:-1.2.3}"
""",
        }
        for name, body in commands.items():
            p = fake / name
            p.write_text(body)
            p.chmod(0o755)

    def set_lock(self, missing=(), added=(), version="1.2.3"):
        lines = [f"{name}={version}" for name in PACKAGES if name not in missing]
        self.lock.write_text("# Ubuntu apt snapshot: 20261111T000000Z (UTC)\n" + "\n".join([*lines, *added]) + "\n")

    def command(self, name, **options):
        env = os.environ.copy()
        env["PATH"] = str(self.cwd / "fake") + os.pathsep + env["PATH"]
        for k in ("FAIL_SNAPSHOT", "BAD_SIGNATURE", "PARTIAL_INDEX", "FAIL_UPDATE", "FAIL_INSTALL", "FAIL_POLICY",
                  "FAIL_COMPARE", "FAIL_QUERY", "CANDIDATE", "INSTALLED"):
            env.pop(k, None)
        env.update(options)
        if name == "parse":
            args = [sys.executable, "ci/parse-toolchain-lock.py", "ci/toolchain.lock"]
        else:
            args = ["bash", f"ci/{name}.sh"]
        return subprocess.run(args, cwd=self.cwd, env=env, capture_output=True,
                              check=False, timeout=20)

    def test_valid_inventory_emits_expected_arguments(self):
        x = self.command("parse")
        self.assertEqual(x.returncode, 0, x.stderr)
        self.assertEqual(x.stdout.decode().splitlines(),
                         [f"{name}=1.2.3" for name in PACKAGES])

    def test_installer_accepts_exact_full_inventory(self):
        x = self.command("install-toolchain")
        self.assertEqual(x.returncode, 0, x.stderr)
        text = (self.cwd / "sudo.log").read_text()
        for name in PACKAGES:
            self.assertIn(f"{name}=1.2.3", text)
        self.assertIn(b"Validated 7 locked", x.stdout)

    def test_snapshot_outage_uses_exact_pins_or_fails(self):
        x = self.command("install-toolchain", FAIL_SNAPSHOT="1")
        self.assertEqual(x.returncode, 0, x.stderr)
        self.assertIn(b"retrying identical version pins", x.stderr)
        log = (self.cwd / "sudo.log").read_text()
        self.assertIn("pa2-snapshot.list", log)
        self.assertIn("pa2-current.list", log)
        self.assertIn("APT::Update::Error-Mode=any", log)
        for name in PACKAGES:
            self.assertIn(f"{name}=1.2.3", log)

    def test_metadata_snapshot_is_single_authoritative_source(self):
        args = [sys.executable, "ci/parse-toolchain-lock.py",
                "--snapshot", "ci/toolchain.lock"]
        x = subprocess.run(args, cwd=self.cwd, capture_output=True,
                           check=False, timeout=10)
        self.assertEqual(x.returncode, 0, x.stderr)
        self.assertEqual(x.stdout, b"20261111T000000Z\n")
        original = self.lock.read_text()
        for modified in (
            original.replace("# Ubuntu apt snapshot: 20261111T000000Z (UTC)\n", ""),
            original.replace("20261111T000000Z", "20261311T000000Z"),
            original.replace("20261111T000000Z", "20261111T250000Z"),
            original + "# Ubuntu apt snapshot: 20261111T000000Z (UTC)\n",
        ):
            with self.subTest(modified=modified[-40:]):
                self.lock.write_text(modified)
                self.assertEqual(self.command("parse").returncode, 2)
                self.assertEqual(self.command("install-toolchain").returncode, 2)
        self.lock.write_text(original)

    def test_partial_indexes_cannot_pass_update_audit(self):
        result = self.command("audit-toolchain", PARTIAL_INDEX="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"Incomplete Ubuntu package index refresh", result.stderr)
        self.assertIn("APT::Update::Error-Mode=any",
                      (self.cwd / "sudo.log").read_text())

    def test_package_manager_audit_error_has_documented_status(self):
        result = self.command("audit-toolchain", FAIL_UPDATE="1")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_snapshot_install_failure_never_activates_fallback(self):
        result = self.command("install-toolchain", FAIL_INSTALL="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        log = (self.cwd / "sudo.log").read_text()
        self.assertIn("pa2-snapshot.list", log)
        self.assertNotIn("pa2-current.list", log)

    def test_snapshot_authenticity_error_never_activates_fallback(self):
        result = self.command("install-toolchain", FAIL_SNAPSHOT="1",
                              BAD_SIGNATURE="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("pa2-current.list", (self.cwd / "sudo.log").read_text())

    def test_ubuntu_only_sources_are_hardcoded_and_signed(self):
        helper = (self.cwd / "ci" / "ubuntu-apt.sh").read_text()
        self.assertIn("ubuntu-archive-keyring.gpg", helper)
        self.assertIn('sourceparts=-', helper)
        self.assertIn("archive.ubuntu.com/ubuntu", helper)
        self.assertIn("security.ubuntu.com/ubuntu", helper)
        self.assertNotIn("packages.microsoft.com", helper)

    def test_audit_accepts_exact_full_inventory(self):
        x = self.command("audit-toolchain")
        self.assertEqual(x.returncode, 0, x.stderr)
        self.assertIn(b"7 tracked", x.stdout)

    def test_update_detection(self):
        x = self.command("audit-toolchain", CANDIDATE="1.2.4")
        self.assertEqual(x.returncode, 1, x.stderr)
        self.assertIn(b"Toolchain update available", x.stdout)

    def test_older_candidate_is_not_update(self):
        self.assertEqual(self.command("audit-toolchain", CANDIDATE="1.2.2").returncode, 0)

    def test_comparison_failure_fails_closed(self):
        x = self.command("audit-toolchain", FAIL_COMPARE="1")
        self.assertEqual(x.returncode, 2, x.stderr)
        self.assertIn(b"Version comparison failed", x.stderr)

    def test_missing_each_mandatory_package_rejected(self):
        for missing in PACKAGES:
            with self.subTest(missing=missing):
                self.set_lock(missing=(missing,))
                for tool in ("parse", "audit-toolchain", "install-toolchain"):
                    x = self.command(tool)
                    self.assertEqual(x.returncode, 2, x.stderr)
                    self.assertIn(b"missing=", x.stderr)
        self.assertFalse((self.cwd / "sudo.log").exists())

    def test_partial_or_empty_lock_rejected(self):
        for data in ("", "# only a comment\n", "gcc=1.2.3\n",
                     "gcc=1.2.3\nclang=1.2.3\n"):
            with self.subTest(data=data):
                self.lock.write_text(data)
                for tool in ("parse", "audit-toolchain", "install-toolchain"):
                    x = self.command(tool)
                    self.assertEqual(x.returncode, 2, x.stderr)
        self.assertFalse((self.cwd / "sudo.log").exists())

    def test_invalid_unknown_duplicate_and_whitespace_rejected(self):
        original = self.lock.read_text()
        for addition in ("gcc=1.2.3", "bogus=1.2.3",
                         "  gcc=1.2.3", "\tgcc=1.2.3", "gcc=1.2.3 ",
                         "gcc=$(touch unsafe)", "gcc", "gcc=", "bad name=1"):
            with self.subTest(addition=addition):
                self.lock.write_text(original + addition + "\n")
                self.assertEqual(self.command("parse").returncode, 2)
                self.assertEqual(self.command("install-toolchain").returncode, 2)
                self.assertEqual(self.command("audit-toolchain").returncode, 2)
        self.assertFalse((self.cwd / "sudo.log").exists())

    def test_leading_whitespace_on_existing_entry_rejected(self):
        self.lock.write_text(self.lock.read_text().replace(
            "gcc=1.2.3", "  gcc=1.2.3"))
        for tool in ("parse", "audit-toolchain", "install-toolchain"):
            self.assertEqual(self.command(tool).returncode, 2)
        self.assertFalse((self.cwd / "sudo.log").exists())

    def test_non_ascii_or_missing_lock_rejected(self):
        self.lock.write_bytes(self.lock.read_bytes() + b"\xff")
        self.assertEqual(self.command("parse").returncode, 2)
        self.lock.unlink()
        for tool in ("parse", "audit-toolchain", "install-toolchain"):
            self.assertEqual(self.command(tool).returncode, 2)

    def test_partial_parser_failure_cannot_install(self):
        fake_python = self.cwd / "fake" / "python3"
        fake_python.write_text("#!/bin/sh\nprintf 'gcc=1.2.3\\\n'\nexit 19\n")
        fake_python.chmod(0o755)
        for tool in ("audit-toolchain", "install-toolchain"):
            x = self.command(tool)
            self.assertEqual(x.returncode, 2, x.stderr)
            expected = (b"validation failed" if tool == "audit-toolchain"
                        else b"Invalid toolchain lock")
            self.assertIn(expected, x.stderr)
        self.assertFalse((self.cwd / "sudo.log").exists())

    def test_package_manager_failures_propagate(self):
        for tool, variable in (("audit-toolchain", "FAIL_POLICY"),
                               ("audit-toolchain", "FAIL_UPDATE"),
                               ("install-toolchain", "FAIL_UPDATE"),
                               ("install-toolchain", "FAIL_INSTALL"),
                               ("install-toolchain", "FAIL_QUERY")):
            with self.subTest(tool=tool, variable=variable):
                self.assertNotEqual(self.command(tool, **{variable: "1"}).returncode, 0)

    def test_version_mismatch_rejected(self):
        x = self.command("install-toolchain", INSTALLED="9.9.9")
        self.assertNotEqual(x.returncode, 0)
        self.assertIn(b"Package version mismatch", x.stderr)

    def test_final_line_without_newline(self):
        self.lock.write_bytes(self.lock.read_bytes().rstrip(b"\n"))
        self.assertEqual(self.command("parse").returncode, 0)
        self.assertEqual(self.command("audit-toolchain").returncode, 0)
        self.assertEqual(self.command("install-toolchain").returncode, 0)


if __name__ == "__main__":
    unittest.main()
