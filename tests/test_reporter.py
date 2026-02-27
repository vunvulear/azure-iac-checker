"""Tests for the Markdown report generator."""

import pytest
from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.config.loader import CheckerConfig
from iac_checker.reporters.markdown_reporter import MarkdownReporter


def make_finding(rule_id="WAF-SEC-001", severity=Severity.HIGH, passed=False, waf_ref="SE:01"):
    return Finding(
        rule_id=rule_id,
        description="Test finding",
        severity=severity,
        file_path="main.tf",
        line_number=10,
        resource_type="azurerm_storage_account",
        resource_name="main",
        recommendation="Fix it",
        doc_url="https://example.com",
        waf_ref=waf_ref,
        passed=passed,
    )


class TestMarkdownReporter:
    def setup_method(self):
        self.reporter = MarkdownReporter(
            scan_path="/test/terraform",
            files_scanned=10,
            config=CheckerConfig(),
        )

    def test_generate_returns_string(self):
        findings = [make_finding()]
        report = self.reporter.generate(findings)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_report_contains_header(self):
        report = self.reporter.generate([make_finding()])
        assert "# Azure IaC Compliance Report" in report
        assert "/test/terraform" in report

    def test_report_contains_executive_summary(self):
        findings = [
            make_finding(passed=True),
            make_finding(passed=False),
        ]
        report = self.reporter.generate(findings)
        assert "## Executive Summary" in report
        assert "✅ Passed" in report
        assert "❌ Failed" in report

    def test_report_severity_counts(self):
        findings = [
            make_finding(severity=Severity.CRITICAL, passed=False),
            make_finding(rule_id="WAF-SEC-002", severity=Severity.HIGH, passed=False),
            make_finding(rule_id="WAF-SEC-003", severity=Severity.MEDIUM, passed=False),
        ]
        report = self.reporter.generate(findings)
        assert "Critical" in report
        assert "High" in report
        assert "Medium" in report

    def test_report_contains_findings_section(self):
        findings = [make_finding(passed=False)]
        report = self.reporter.generate(findings)
        assert "## Findings" in report
        assert "WAF-SEC-001" in report

    def test_report_no_violations(self):
        findings = [make_finding(passed=True)]
        report = self.reporter.generate(findings)
        assert "No violations found" in report

    def test_report_contains_doc_links(self):
        findings = [make_finding(passed=False)]
        report = self.reporter.generate(findings)
        assert "https://example.com" in report

    def test_report_contains_waf_ref(self):
        findings = [make_finding(passed=False, waf_ref="SE:07")]
        report = self.reporter.generate(findings)
        assert "SE:07" in report

    def test_report_passed_rules_section(self):
        findings = [
            make_finding(rule_id="WAF-SEC-001", passed=True),
            make_finding(rule_id="WAF-SEC-002", passed=True),
        ]
        report = self.reporter.generate(findings)
        assert "## Passed Rules" in report
        assert "2 rules passed" in report

    def test_report_domain_breakdown(self):
        findings = [
            make_finding(rule_id="WAF-SEC-001", passed=False),
            make_finding(rule_id="WAF-REL-001", passed=True, waf_ref="RE:01"),
        ]
        report = self.reporter.generate(findings)
        assert "## Results by Domain" in report

    def test_suppressed_findings_not_in_failures(self):
        f = make_finding(passed=False)
        f.suppressed = True
        report = self.reporter.generate([f])
        assert "No violations found" in report

    def test_report_file_location_in_findings(self):
        findings = [make_finding(passed=False)]
        report = self.reporter.generate(findings)
        assert "main.tf:10" in report
        assert "azurerm_storage_account.main" in report
