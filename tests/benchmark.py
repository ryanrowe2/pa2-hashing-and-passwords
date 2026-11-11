"""Optional local benchmark with deterministically generated synthetic candidates."""

import hashlib
import os
from pathlib import Path
import subprocess
import time

binary = str(Path(os.environ.get("PWCRACK_BIN", "build/pwcrack")).resolve())
count = 10000
candidate_data = b"".join(f"synthetic-{i:06d}\n".encode() for i in range(count))
target = hashlib.sha256(b"deliberately-absent-target").hexdigest()
start = time.perf_counter()
result = subprocess.run(
    [binary, target], input=candidate_data, capture_output=True, check=True
)
elapsed = time.perf_counter() - start
if result.stdout != b"Did not find a matching password\n":
    raise RuntimeError(f"unexpected output: {result.stdout!r}")
print(f"{count:,} synthetic candidates in {elapsed:.3f}s ({count / elapsed:,.0f} lines/s)")
print("Elapsed time includes process startup, stdin transfer and output collection.")
