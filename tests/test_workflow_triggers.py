"""Dependency validation must remain an unavoidable part of required CI checks."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / ".github" / "workflows" / "toolchain-review.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def audit_gate_is_valid(ci: str) -> bool:
    if not re.search(r"(?m)^  pull_request:\s*$", ci):
        return False
    jobs = ci.split("\njobs:\n", 1)
    if len(jobs) != 2:
        return False
    match = re.search(r"(?ms)^  quality:\n(.*?)(?=^  [A-Za-z_-]+:|\Z)", jobs[1])
    if not match:
        return False
    job = match.group(1)
    header = job.split("    steps:", 1)
    if len(header) != 2:
        return False
    if re.search(r"(?m)^    (?:if|continue-on-error):", header[0]):
        return False
    if not re.search(r"(?m)^        compiler: \[gcc, clang\]$", job):
        return False
    steps = re.split(r"(?m)(?=^      - (?:name|uses):)", header[1])
    audit_steps = [s for s in steps if "Enforce toolchain-update review" in s]
    if len(audit_steps) != 1:
        return False
    exact_lines = [line.strip() for line in audit_steps[0].splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
    return exact_lines == [
        "- name: Enforce toolchain-update review in required GCC check",
        "if: matrix.compiler == 'gcc'",
        "run: bash ci/audit-toolchain.sh",
    ]


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

    def test_required_gcc_job_executes_unconditionally_gated_toolchain_audit(self):
        ci = CI.read_text(encoding="utf-8")
        self.assertTrue(audit_gate_is_valid(ci))
        self.assertIn("run: bash ci/install-toolchain.sh", ci)

    def test_disabled_moved_or_nonblocking_audit_is_rejected(self):
        ci = CI.read_text(encoding="utf-8")
        self.assertTrue(audit_gate_is_valid(ci))
        mutants = (
            ci.replace("if: matrix.compiler == 'gcc'", "if: false"),
            ci.replace("if: matrix.compiler == 'gcc'",
                       "if: matrix.compiler == 'clang'"),
            ci.replace("run: bash ci/audit-toolchain.sh",
                       "run: echo audit intentionally skipped"),
            ci.replace("run: bash ci/audit-toolchain.sh",
                       "run: bash ci/audit-toolchain.sh\n        continue-on-error: true"),
            ci.replace("  quality:\n", "  quality:\n    if: false\n"),
            ci.replace("  quality:\n", "  quality:\n    continue-on-error: true\n"),
            ci.replace("compiler: [gcc, clang]", "compiler: [clang]"),
        )
        for mutant in mutants:
            with self.subTest(mutant=mutant[:100]):
                self.assertFalse(audit_gate_is_valid(mutant))

    def test_ci_records_full_installed_environment_and_executable_origins(self):
        ci = CI.read_text(encoding="utf-8")
        self.assertIn("run: bash ci/record-environment.sh", ci)
        self.assertIn("ldd build/pwcrack", ci)
        script = (ROOT / "ci" / "record-environment.sh").read_text(encoding="utf-8")
        for required in ("dpkg-query -W", "dpkg-query -S",
                         "sha256sum", "assert_version", "libssl3t64"):
            self.assertIn(required, script)


if __name__ == "__main__":
    unittest.main()
