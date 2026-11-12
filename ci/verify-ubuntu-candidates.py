#!/usr/bin/env python3
"""Fail-closed APT repository provenance and version checks.

Only apt-cache madison entries from the isolated, Ubuntu-signed source indexes
are accepted. dpkg's status database alone is never evidence of availability.
"""
import re
import subprocess
import sys

DEBIAN_VERSION = re.compile(r"[0-9][A-Za-z0-9.+:~_-]*\Z", re.ASCII)
PACKAGES = re.compile(r"[a-z0-9][a-z0-9+.-]*\Z", re.ASCII)
CURRENT = {"http://archive.ubuntu.com/ubuntu", "http://security.ubuntu.com/ubuntu"}
SUITES = {"noble", "noble-updates", "noble-security"}
COMPONENTS = {"main", "universe"}
INDEX_ARCH = {"amd64", "all"}


class InvalidRepositoryMetadata(ValueError):
    pass


def parse_madison(text: str, package: str, source_mode: str,
                  snapshot: str) -> set[str]:
    versions = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = [part.strip() for part in line.split("|")]
        if len(fields) != 3:
            raise InvalidRepositoryMetadata("malformed APT madison entry")
        name, version, origin = fields
        if name != package or DEBIAN_VERSION.fullmatch(version) is None:
            raise InvalidRepositoryMetadata("unexpected package or version metadata")
        parts = origin.split()
        if len(parts) != 4 or parts[-1] != "Packages" or parts[2] not in INDEX_ARCH:
            raise InvalidRepositoryMetadata("missing authenticated archive index")
        uri, suite_component, _, _ = parts
        suite, separator, component = suite_component.partition("/")
        if not separator or suite not in SUITES or component not in COMPONENTS:
            raise InvalidRepositoryMetadata("unexpected Ubuntu suite/component")
        if source_mode == "current":
            if uri not in CURRENT:
                raise InvalidRepositoryMetadata("package supplied by unexpected origin")
            if suite == "noble-security" and uri != "http://security.ubuntu.com/ubuntu":
                raise InvalidRepositoryMetadata("security packages must use Ubuntu security archive")
        elif source_mode == "snapshot":
            if uri != f"https://snapshot.ubuntu.com/ubuntu/{snapshot}":
                raise InvalidRepositoryMetadata("package supplied by unexpected snapshot")
        else:
            raise InvalidRepositoryMetadata("unrecognized package source mode")
        versions.add(version)
    return versions


def has_newer(versions: set[str], pinned: str) -> bool:
    newer = False
    for version in sorted(versions):
        check = subprocess.run(["dpkg", "--compare-versions", version, "gt", pinned],
                               check=False, capture_output=True)
        if check.returncode == 0:
            newer = True
        elif check.returncode != 1:
            raise InvalidRepositoryMetadata("Version comparison failed")
    return newer


def main() -> int:
    if len(sys.argv) != 6:
        print("usage: verify-ubuntu-candidates.py audit|install current|snapshot TIMESTAMP|'-' PACKAGE PIN", file=sys.stderr)
        return 2
    mode, source_mode, snapshot, package, pinned = sys.argv[1:]
    if mode not in {"audit", "install"} or PACKAGES.fullmatch(package) is None or DEBIAN_VERSION.fullmatch(pinned) is None:
        print("::error::Invalid Ubuntu package verification arguments", file=sys.stderr)
        return 2
    try:
        versions = parse_madison(sys.stdin.read(), package, source_mode, snapshot)
        if pinned not in versions:
            raise InvalidRepositoryMetadata(
                f"{package}={pinned} unavailable from authenticated Ubuntu repositories"
            )
        if mode == "audit" and has_newer(versions, pinned):
            print(f"::warning title=Toolchain update available::{package} pinned {pinned}; newer Ubuntu version available")
            return 1
    except InvalidRepositoryMetadata as exc:
        print(f"::error::APT repository verification failed for {package}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
