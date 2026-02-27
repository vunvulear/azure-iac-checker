"""Markdown report generator — produces the compliance-report.md output."""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List

from iac_checker.config.loader import CheckerConfig
from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.reporters.base_reporter import BaseReporter


# Domain grouping by rule ID prefix
DOMAIN_LABELS = {
    "WAF-REL": "WAF — Reliability (RE:01–RE:10)",
    "WAF-SEC": "WAF — Security (SE:01–SE:12)",
    "WAF-COST": "WAF — Cost Optimization (CO:01–CO:14)",
    "WAF-OPS": "WAF — Operational Excellence (OE:01–OE:11)",
    "WAF-PERF": "WAF — Performance Efficiency (PE:01–PE:12)",
    "WAF-SVC": "WAF — Service Guides",
    "CAF-NAME": "CAF — Naming Conventions",
    "CAF-TAG": "CAF — Tagging Strategy",
    "CAF-LZ": "CAF — Landing Zone & Subscription",
    "CAF-NET": "CAF — Networking",
    "CAF-IAM": "CAF — Identity & Access",
    "CAF-GOV": "CAF — Governance & Policy",
}


class MarkdownReporter(BaseReporter):
    def __init__(self, scan_path: str, files_scanned: int, config: CheckerConfig):
        self.scan_path = scan_path
        self.files_scanned = files_scanned
        self.config = config

    def generate(self, findings: List[Finding]) -> str:
        """Generate the full Markdown compliance report."""
        lines: List[str] = []

        # Header
        lines.append(self._header(findings))

        # Executive Summary
        lines.append(self._executive_summary(findings))

        # Results by Domain
        lines.append(self._results_by_domain(findings))

        # Findings (failures) grouped by severity
        lines.append(self._findings_detail(findings))

        # Passed rules (collapsible)
        lines.append(self._passed_rules(findings))

        return "\n".join(lines)

    def _header(self, findings: List[Finding]) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        total = len(findings)
        failed = len([f for f in findings if not f.passed and not f.suppressed])

        return f"""# Azure IaC Compliance Report

**Scan Date:** {now}
**Path Scanned:** `{self.scan_path}`
**Files Scanned:** {self.files_scanned}
**Rules Evaluated:** {total}
**Severity Threshold:** {self.config.severity_threshold.value}

---
"""

    def _executive_summary(self, findings: List[Finding]) -> str:
        passed = [f for f in findings if f.passed]
        failed = [f for f in findings if not f.passed and not f.suppressed]
        suppressed = [f for f in findings if f.suppressed]

        severity_counts = defaultdict(int)
        for f in failed:
            severity_counts[f.severity] += 1

        lines = [
            "## Executive Summary\n",
            "| Status | Count |",
            "|--------|-------|",
            f"| ✅ Passed | {len(passed)} |",
            f"| ❌ Failed | {len(failed)} |",
            f"| ⏭️ Skipped/Suppressed | {len(suppressed)} |",
            f"| **Total** | **{len(findings)}** |",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts.get(sev, 0)
            lines.append(f"| {sev.emoji} {sev.value} | {count} |")

        lines.append("\n---\n")
        return "\n".join(lines)

    def _results_by_domain(self, findings: List[Finding]) -> str:
        lines = ["## Results by Domain\n"]

        domain_findings: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            prefix = self._get_domain_prefix(f.rule_id)
            domain_findings[prefix].append(f)

        for prefix, label in DOMAIN_LABELS.items():
            domain = domain_findings.get(prefix, [])
            passed = len([f for f in domain if f.passed])
            failed = len([f for f in domain if not f.passed and not f.suppressed])
            if domain:
                status = "✅" if failed == 0 else "❌"
                lines.append(f"### {label}")
                lines.append(f"{status} {passed} passed | ❌ {failed} failed\n")

        lines.append("---\n")
        return "\n".join(lines)

    def _findings_detail(self, findings: List[Finding]) -> str:
        failed = [f for f in findings if not f.passed and not f.suppressed]
        failed.sort(key=lambda f: f.severity.rank)

        if not failed:
            return "## Findings\n\n✅ **No violations found!** All checks passed.\n\n---\n"

        lines = ["## Findings\n"]

        current_severity = None
        for f in failed:
            if f.severity != current_severity:
                current_severity = f.severity
                lines.append(f"### {f.severity.emoji} {f.severity.value}\n")

            lines.append(f"#### {f.rule_id} — {f.description}\n")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")

            if f.framework_ref != "—":
                lines.append(f"| **WAF/CAF Reference** | {f.framework_ref} |")

            lines.append(f"| **Severity** | {f.severity.emoji} {f.severity.value} |")
            lines.append(f"| **File** | `{f.location}` |")
            lines.append(f"| **Resource** | `{f.resource_fqn}` |")
            lines.append(f"| **Description** | {f.description} |")
            lines.append(f"| **Recommendation** | {f.recommendation} |")

            if f.doc_url:
                lines.append(f"| **Documentation** | [{f.framework_ref}]({f.doc_url}) |")

            lines.append("")

        lines.append("---\n")
        return "\n".join(lines)

    def _passed_rules(self, findings: List[Finding]) -> str:
        passed = [f for f in findings if f.passed]
        if not passed:
            return ""

        lines = [
            "## Passed Rules",
            "<details>",
            f"<summary>Click to expand ({len(passed)} rules passed)</summary>\n",
            "| Rule ID | WAF/CAF Ref | Description |",
            "|---------|-------------|-------------|",
        ]

        for f in sorted(passed, key=lambda x: x.rule_id):
            lines.append(f"| {f.rule_id} | {f.framework_ref} | {f.description} |")

        lines.append("\n</details>\n")
        return "\n".join(lines)

    @staticmethod
    def _get_domain_prefix(rule_id: str) -> str:
        """Extract the domain prefix from a rule ID (e.g., WAF-SEC from WAF-SEC-001)."""
        parts = rule_id.split("-")
        if len(parts) >= 2:
            return f"{parts[0]}-{parts[1]}"
        return rule_id
