"""Test APT repository-version attestation against malicious or absent indexes."""
from importlib import util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = util.spec_from_file_location("pa2_verify_apt", ROOT / "ci" / "verify-ubuntu-candidates.py")
assert spec is not None and spec.loader is not None
apt = util.module_from_spec(spec)
spec.loader.exec_module(apt)

PACKAGE = "gcc-13"
PIN = "13.3.0-6ubuntu2~24.04.1"
CURRENT = f" {PACKAGE} | {PIN} | http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages\n"
SECURITY = f" {PACKAGE} | {PIN} | http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages\n"
SNAP = f" {PACKAGE} | {PIN} | https://snapshot.ubuntu.com/ubuntu/20261111T000000Z noble/main amd64 Packages\n"


class RepositoryMetadataTests(unittest.TestCase):
    def test_valid_current_and_security_sources(self):
        versions = apt.parse_madison(CURRENT + SECURITY, PACKAGE, "current", "-")
        self.assertEqual(versions, {PIN})

    def test_valid_exact_snapshot_source(self):
        versions = apt.parse_madison(SNAP, PACKAGE, "snapshot", "20261111T000000Z")
        self.assertEqual(versions, {PIN})

    def test_installed_only_and_empty_sources_provide_no_eligible_pin(self):
        self.assertEqual(apt.parse_madison("", PACKAGE, "current", "-"), set())
        self.assertNotIn(PIN, apt.parse_madison("", PACKAGE, "current", "-"))

    def test_untrusted_mismatched_and_malformed_sources_rejected(self):
        invalid = (
            CURRENT.replace("archive.ubuntu.com", "malicious.example"),
            CURRENT.replace("noble-updates", "noble-backports"),
            CURRENT.replace("noble-updates/main", "noble-updates/nonfree"),
            CURRENT.replace("amd64 Packages", "amd64 Sources"),
            CURRENT.replace(PACKAGE + " |", "python3 |"),
            CURRENT.replace(PIN, "$(touch evil)"),
            CURRENT.replace("http://", "file://"),
            CURRENT.replace("noble-updates/main", "noble-security/main"),
            " Candidate: " + PIN,
            CURRENT + "garbage",
        )
        for raw in invalid:
            with self.subTest(raw=raw[:90]):
                with self.assertRaises(apt.InvalidRepositoryMetadata):
                    apt.parse_madison(raw, PACKAGE, "current", "-")

    def test_snapshot_timestamp_mismatch_rejected(self):
        with self.assertRaises(apt.InvalidRepositoryMetadata):
            apt.parse_madison(SNAP, PACKAGE, "snapshot", "20261110T000000Z")


if __name__ == "__main__":
    unittest.main()
