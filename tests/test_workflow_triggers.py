"""Check that security-related workflow checks cannot silently skip PRs."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / ".github" / "workflows" / "toolchain-review.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"


class ToolchainWorkflowTriggerTests(unittest.TestCase):
    def test_toolchain_review_reports_on_every_pr_and_main_push(self):
        workflow = REVIEW.read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?m)^  pull_request:\s*$")
        self.assertRegex(workflow, r"(?m)^  push:\s*$")
        self.assertRegex(workflow, r"(?m)^    branches: \[main\]\s*$")
        self.assertNotRegex(workflow, r"(?m)^\s+paths(?:-ignore)?:")
        self.assertIn("schedule:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("check-toolchain-updates:", workflow)

    def test_existing_required_gcc_job_enforces_toolchain_update_audit(self):
        ci = CI.read_text(encoding="utf-8")
        self.assertIn("quality:", ci)
        self.assertIn("compiler: [gcc, clang]", ci)
        self.assertIn("if: matrix.compiler == 'gcc'", ci)
        self.assertIn("run: bash ci/audit-toolchain.sh", ci)
        self.assertIn("run: bash ci/install-toolchain.sh", ci)

    def test_ci_records_full_installed_environment(self):
        ci = CI.read_text(encoding="utf-8")
        self.assertIn("run: bash ci/record-environment.sh", ci)
        script = (ROOT / "ci" / "record-environment.sh").read_text(encoding="utf-8")
        self.assertIn("dpkg-query -W", script)
        self.assertIn("sha256sum", script)


if __name__ == "__main__":
    unittest.main()
