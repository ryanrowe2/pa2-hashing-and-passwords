#!/usr/bin/env python3
"""Verify the actual OpenSSL shared library selected by the ELF loader."""
from pathlib import Path
import re
import subprocess
import sys

LIB_LINE = re.compile(r"^\s*libcrypto\.so\.3\s*=>\s*(/\S+)\s+\(0x[0-9a-fA-F]+\)\s*$")
EXPECTED_DIRECTORY = Path("/usr/lib/x86_64-linux-gnu")
EXPECTED_PACKAGE = "libssl3t64:amd64"


class InvalidLibcrypto(ValueError):
    pass


def library_from_ldd(output: str) -> str:
    lines = [line for line in output.splitlines()
             if re.match(r"^\s*libcrypto\.so\.3(?:\s|$)", line)]
    if len(lines) != 1:
        raise InvalidLibcrypto("expected exactly one libcrypto.so.3 dependency")
    found = LIB_LINE.fullmatch(lines[0])
    if found is None:
        raise InvalidLibcrypto("libcrypto.so.3 is missing or has an invalid loader path")
    return found.group(1)


def require_system_library(path: Path, owner: str) -> None:
    if path.parent != EXPECTED_DIRECTORY or path.name != "libcrypto.so.3":
        raise InvalidLibcrypto(f"unexpected libcrypto runtime path: {path}")
    if not owner.strip().startswith(EXPECTED_PACKAGE + ": "):
        raise InvalidLibcrypto(f"unexpected library package owner: {owner.strip()}")


def checked(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode:
        raise InvalidLibcrypto(f"{cmd[0]} failed (exit {proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify-libcrypto.py ELF_BINARY", file=sys.stderr)
        return 2
    try:
        linked_path = library_from_ldd(checked(["ldd", sys.argv[1]]))
        realpath = Path(linked_path).resolve(strict=True)
        owner = checked(["dpkg-query", "-S", str(realpath)])
        require_system_library(realpath, owner)
        runtime_version = checked(["dpkg-query", "-W", "-f=$"+"{Version}", "libssl3t64"])
        lock = Path("ci/toolchain.lock").read_text(encoding="ascii")
        matches = [line.partition("=")[2] for line in lock.splitlines()
                   if line.startswith("libssl-dev=")]
        if len(matches) != 1 or runtime_version != matches[0]:
            raise InvalidLibcrypto("OpenSSL runtime version differs from signed toolchain pin")
    except (InvalidLibcrypto, OSError, UnicodeError) as exc:
        print(f"::error::OpenSSL runtime verification failed: {exc}", file=sys.stderr)
        return 2
    print(f"Verified libcrypto.so.3: {realpath} ({owner}, {runtime_version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
