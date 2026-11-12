#!/usr/bin/env python3
"""Validate the entire toolchain lock before yielding any APT arguments.

The UTC snapshot timestamp is read from this same file, so metadata and
installation cannot silently drift apart.
"""

from datetime import datetime
from pathlib import Path
import re
import sys

REQUIRED_PACKAGES = frozenset({
    "build-essential", "gcc", "gcc-13", "clang", "clang-18",
    "libssl-dev", "python3",
})
ENTRY = re.compile(r"([a-z0-9][a-z0-9+.-]*)=([0-9][A-Za-z0-9.+:~_-]*)", re.ASCII)
SNAPSHOT_HEADER = re.compile(
    r"# Ubuntu apt snapshot: (20[0-9]{6}T[0-9]{6}Z) \(UTC\)", re.ASCII
)


def parse_lock(path: Path) -> tuple[str, list[str]]:
    content = path.read_bytes().decode("ascii")
    entries: dict[str, str] = {}
    snapshot = None
    for line_number, line in enumerate(content.splitlines(), start=1):
        if line.startswith("# Ubuntu apt snapshot:"):
            found = SNAPSHOT_HEADER.fullmatch(line)
            if found is None or snapshot is not None:
                raise ValueError(f"invalid or repeated snapshot metadata on line {line_number}")
            snapshot = found.group(1)
            try:
                datetime.strptime(snapshot, "%Y%m%dT%H%M%SZ")
            except ValueError as exc:
                raise ValueError(f"invalid UTC snapshot date on line {line_number}") from exc
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        found = ENTRY.fullmatch(line)
        if found is None:
            raise ValueError(f"malformed lock entry on line {line_number}")
        name, version = found.groups()
        if name in entries:
            raise ValueError(f"duplicate package {name!r} on line {line_number}")
        entries[name] = version
    if snapshot is None:
        raise ValueError("missing required Ubuntu snapshot metadata")
    missing = REQUIRED_PACKAGES - entries.keys()
    unexpected = entries.keys() - REQUIRED_PACKAGES
    if missing or unexpected:
        raise ValueError(
            "invalid toolchain inventory; "
            f"missing={','.join(sorted(missing)) or 'none'}; "
            f"unexpected={','.join(sorted(unexpected)) or 'none'}"
        )
    return snapshot, [f"{name}={version}" for name, version in entries.items()]


def main() -> int:
    snapshot_mode = len(sys.argv) == 3 and sys.argv[1] == "--snapshot"
    if not snapshot_mode and len(sys.argv) != 2:
        print("usage: parse-toolchain-lock.py [--snapshot] LOCKFILE", file=sys.stderr)
        return 2
    path = Path(sys.argv[-1])
    try:
        snapshot, entries = parse_lock(path)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"::error::Invalid toolchain lock: {exc}", file=sys.stderr)
        return 2
    print(snapshot if snapshot_mode else "\n".join(entries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
