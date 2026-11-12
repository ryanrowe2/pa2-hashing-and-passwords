"""Validate toolchain review trigger coverage without extra Python dependencies."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "toolchain-review.yml"


class ToolchainWorkflowTriggerTests(unittest.TestCase):
    def test_all_toolchain_inputs_trigger_pr_and_main_review(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                match = re.search(
                    rf"(?m)^  {event}:\n((?:^    .*\n|^      .*\n)+)",
                    workflow,
                )
                self.assertIsNotNone(match, f"missing {event} event")
                block = match.group(1)
                for path in (
                    "ci/install-toolchain.sh",
                    "ci/parse-toolchain-lock.py",
                    "ci/toolchain.lock",
                    "ci/audit-toolchain.sh",
                    ".github/workflows/toolchain-review.yml",
                ):
                    self.assertIn(f"      - '{path}'", block)
