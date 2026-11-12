#!/usr/bin/env python3
"""Validate the complete CI toolchain lock and emit safe APT package arguments.

Both the installer and weekly audit MUST use this parser. It buffers results until
validation finishes, so invalid/incomplete input cannot yield a partial install.
"""

from pathlib import Path
import re
import sys

REQUIRED_PACKAGES = frozenset({
    "build-essential", "gcc", "gcc-13", "clang", "clang-18",
    "libssl-dev", "python3",
})
ENTRY = re.compile(r"([a-z0-9][a-z0-9+.-]*)=([0-9][A-Za-z0-9.+:~_-]*)", re.ASCII)


def parse_lock(path: Path) -> list[str]:
    # read_bytes either completes or raises. Do not stream validated entries to
    # stdout until the entire file and mandatory package inventory are checked.
    content = path.read_bytes().decode("ascii")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        found = ENTRY.fullmatch(line)
        if found is None:
            raise ValueError(f"malformed lock entry on line {line_number}")
        name, version = found.groups()
        if name in entries:
            raise ValueError(f"duplicate package {name!r} on line {line_number}")
        entries[name] = version

    missing = REQUIRED_PACKAGES - entries.keys()
    unexpected = entries.keys() - REQUIRED_PACKAGES
    if missing or unexpected:
        raise ValueError(
            "invalid toolchain inventory; "
            f"missing={','.join(sorted(missing)) or 'none'}; "
            f"unexpected={','.join(sorted(unexpected)) or 'none'}"
        )
    return [f"{name}={version}" for name, version in entries.items()]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: parse-toolchain-lock.py LOCKFILE", file=sys.stderr)
        return 2
    try:
        entries = parse_lock(Path(sys.argv[1]))
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"::error::Invalid toolchain lock: {exc}", file=sys.stderr)
        return 2
    print("\n".join(entries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
