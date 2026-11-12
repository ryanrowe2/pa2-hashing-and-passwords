"""Adversarial validation of the actual OpenSSL shared-library loader path."""
from importlib import util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = util.spec_from_file_location("pa2_verify_libcrypto", ROOT / "ci" / "verify-libcrypto.py")
assert spec is not None and spec.loader is not None
lib = util.module_from_spec(spec)
spec.loader.exec_module(lib)

GOOD = "\tlibcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3 (0x00007f01)\n"
EXPECTED = Path("/usr/lib/x86_64-linux-gnu/libcrypto.so.3")
OWNER = "libssl3t64:amd64: /usr/lib/x86_64-linux-gnu/libcrypto.so.3"


class OpenSSLRuntimeProvenanceTests(unittest.TestCase):
    def test_exact_soname_and_absolute_resolved_system_path_accepted(self):
        self.assertEqual(lib.library_from_ldd(GOOD),
                         "/lib/x86_64-linux-gnu/libcrypto.so.3")
        lib.require_system_library(EXPECTED, OWNER)

    def test_missing_duplicate_or_unresolved_runtime_rejected(self):
        bad = (
            "", "linux-vdso.so.1 (0x00007f01)\n",
            "\tlibcrypto.so.3 => not found\n",
            GOOD + GOOD,
            "\tlibcrypto.so.3 => libcrypto.so.3 (0x00007f01)\n",
            "\tlibcrypto.so.3 => /tmp/evil/libcrypto.so.3\n",
            "\tlibcrypto.so.3 => /tmp/evil/libcrypto.so.3 (not an address)\n",
        )
        for output in bad:
            with self.subTest(output=output):
                with self.assertRaises(lib.InvalidLibcrypto):
                    lib.library_from_ldd(output)

    def test_external_ld_library_path_injection_rejected(self):
        injected = "\tlibcrypto.so.3 => /tmp/evil/libcrypto.so.3 (0x00007f01)\n"
        path = Path(lib.library_from_ldd(injected))
        with self.assertRaisesRegex(lib.InvalidLibcrypto, "unexpected libcrypto runtime path"):
            lib.require_system_library(path, OWNER)
        for invalid in (
            Path("/opt/custom/libcrypto.so.3"),
            Path("/usr/local/lib/libcrypto.so.3"),
            Path("/usr/lib/x86_64-linux-gnu/libcrypto.so.3.9"),
        ):
            with self.subTest(path=invalid):
                with self.assertRaises(lib.InvalidLibcrypto):
                    lib.require_system_library(invalid, OWNER)

    def test_unexpected_dpkg_owner_rejected(self):
        for owner in (
            "evil:amd64: /usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "libssl-dev:amd64: /usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "libssl3t64:arm64: /usr/lib/aarch64-linux-gnu/libcrypto.so.3",
            "libssl3t64:amd64 /usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "",
        ):
            with self.subTest(owner=owner):
                with self.assertRaises(lib.InvalidLibcrypto):
                    lib.require_system_library(EXPECTED, owner)


if __name__ == "__main__":
    unittest.main()
