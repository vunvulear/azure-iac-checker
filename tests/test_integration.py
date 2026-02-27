"""Integration tests — run the full tool pipeline end-to-end against fixture files."""

import pytest
from pathlib import Path

from iac_checker.config.loader import ConfigLoader, CheckerConfig
from iac_checker.parser.scanner import IacScanner
from iac_checker.parser.terraform.hcl_parser import HclParser
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.engine import RulesEngine
from iac_checker.reporters.markdown_reporter import MarkdownReporter
from iac_checker.models.enums import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def run_pipeline(tf_dir: Path, config: CheckerConfig = None):
    """Run the full scan→parse→evaluate→report pipeline."""
    if config is None:
        config = CheckerConfig()

    scanner = IacScanner(root_path=tf_dir, exclude_paths=config.exclude_paths, formats={"terraform"})
    files_by_format = scanner.discover()
    tf_files = files_by_format.get("terraform", [])
    assert len(tf_files) > 0, f"No .tf files found in {tf_dir}"

    parser = HclParser()
    parsed_files = parser.parse_files(tf_files)
    assert len(parsed_files) > 0, "No files were parsed successfully"

    index = ResourceIndex()
    index.build(parsed_files)

    engine = RulesEngine(config=config)
    findings = engine.evaluate(index)

    reporter = MarkdownReporter(
        scan_path=str(tf_dir),
        files_scanned=len(tf_files),
        config=config,
    )
    report = reporter.generate(findings)

    return findings, report, index, engine


class TestEndToEndValidTerraform:
    """Integration tests against the valid (compliant) fixture."""

    def test_pipeline_runs_without_error(self):
        findings, report, index, engine = run_pipeline(FIXTURES / "valid_terraform")
        assert findings is not None
        assert report is not None

    def test_resources_indexed(self):
        findings, report, index, engine = run_pipeline(FIXTURES / "valid_terraform")
        assert len(index.resources) >= 3  # rg, storage, key_vault

    def test_rules_loaded(self):
        findings, report, index, engine = run_pipeline(FIXTURES / "valid_terraform")
        assert engine.rules_count > 30  # YAML + programmatic rules

    def test_report_is_markdown(self):
        findings, report, index, engine = run_pipeline(FIXTURES / "valid_terraform")
        assert report.startswith("# Azure IaC Compliance Report")
        assert "## Executive Summary" in report
        assert "## Results by Domain" in report
        assert "## Findings" in report

    def test_key_vault_passes_security(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "valid_terraform")
        kv_sec_findings = [
            f for f in findings
            if f.rule_id == "WAF-SEC-014" and f.resource_name == "main"
        ]
        assert len(kv_sec_findings) == 1
        assert kv_sec_findings[0].passed is True

    def test_storage_grs_passes_dr(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "valid_terraform")
        dr_findings = [
            f for f in findings
            if f.rule_id == "WAF-REL-013" and f.resource_name == "main"
        ]
        assert len(dr_findings) == 1
        assert dr_findings[0].passed is True

    def test_storage_tls_passes(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "valid_terraform")
        tls_findings = [
            f for f in findings
            if f.rule_id == "WAF-SEC-012" and "azurerm_storage_account" in f.resource_type
        ]
        assert len(tls_findings) == 1
        assert tls_findings[0].passed is True

    def test_mandatory_tags_pass(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "valid_terraform")
        tag_findings = [
            f for f in findings
            if f.rule_id == "CAF-TAG-012" and f.resource_name == "main"
        ]
        # All resources have tags
        assert all(f.passed for f in tag_findings)


class TestEndToEndInvalidTerraform:
    """Integration tests against the invalid (non-compliant) fixture."""

    def test_pipeline_runs_without_error(self):
        findings, report, index, engine = run_pipeline(FIXTURES / "invalid_terraform")
        assert findings is not None

    def test_has_violations(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform")
        failed = [f for f in findings if not f.passed]
        assert len(failed) > 0

    def test_detects_hardcoded_secret(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform")
        secret_findings = [
            f for f in findings
            if f.rule_id == "WAF-SEC-019" and not f.passed
        ]
        assert len(secret_findings) >= 1

    def test_detects_missing_tags(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform")
        tag_findings = [
            f for f in findings
            if f.rule_id == "CAF-TAG-012" and not f.passed
        ]
        assert len(tag_findings) >= 1  # azurerm_resource_group.bad has no tags

    def test_detects_nsg_wildcard(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform")
        nsg_findings = [
            f for f in findings
            if f.rule_id == "CAF-NET-004" and not f.passed
        ]
        assert len(nsg_findings) >= 1

    def test_detects_missing_az_zones(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform")
        az_findings = [
            f for f in findings
            if f.rule_id == "WAF-REL-002" and not f.passed
        ]
        assert len(az_findings) >= 1  # VM or AKS without zones

    def test_detects_lrs_no_geo_redundancy(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform")
        dr_findings = [
            f for f in findings
            if f.rule_id == "WAF-REL-013" and not f.passed
        ]
        assert len(dr_findings) >= 1  # storage with LRS

    def test_detects_invalid_env_tag_value(self):
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform")
        env_findings = [
            f for f in findings
            if f.rule_id == "CAF-TAG-009" and not f.passed
        ]
        assert len(env_findings) >= 1  # env = "production"

    def test_report_contains_violations(self):
        _, report, _, _ = run_pipeline(FIXTURES / "invalid_terraform")
        assert "❌ Failed" in report
        assert "No violations found" not in report


class TestEndToEndWithConfig:
    """Test config overrides affect findings."""

    def test_disable_rule(self):
        config = CheckerConfig()
        config.rule_overrides["WAF-SEC-019"] = type(
            "RuleOverride", (), {"enabled": False, "severity": None, "pattern": None}
        )()
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform", config)
        secret_findings = [f for f in findings if f.rule_id == "WAF-SEC-019"]
        assert len(secret_findings) == 0

    def test_severity_override(self):
        config = CheckerConfig()
        from iac_checker.config.loader import RuleOverride
        config.rule_overrides["CAF-TAG-012"] = RuleOverride(
            enabled=True, severity=Severity.LOW
        )
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform", config)
        tag_findings = [f for f in findings if f.rule_id == "CAF-TAG-012"]
        assert all(f.severity == Severity.LOW for f in tag_findings)

    def test_severity_threshold_filters_exit(self):
        """With Critical threshold, only critical findings trigger failure."""
        config = CheckerConfig()
        config.severity_threshold = Severity.CRITICAL
        findings, _, _, _ = run_pipeline(FIXTURES / "invalid_terraform", config)
        failed = [f for f in findings if not f.passed and not f.suppressed]
        critical_failures = [f for f in failed if f.severity.rank <= Severity.CRITICAL.rank]
        # There should be at least 1 critical (hardcoded password)
        assert len(critical_failures) >= 1


class TestEndToEndExamples:
    """Run against the examples/ directories if they exist."""

    @pytest.fixture
    def examples_dir(self):
        return Path(__file__).parent.parent / "examples"

    def test_non_compliant_example(self, examples_dir):
        non_compliant = examples_dir / "non-compliant"
        if not non_compliant.exists():
            pytest.skip("examples/non-compliant not found")
        findings, report, _, _ = run_pipeline(non_compliant)
        failed = [f for f in findings if not f.passed and not f.suppressed]
        assert len(failed) > 5  # Should have many violations

    def test_compliant_example(self, examples_dir):
        compliant = examples_dir / "compliant"
        if not compliant.exists():
            pytest.skip("examples/compliant not found")
        findings, report, _, _ = run_pipeline(compliant)
        # Compliant example should have very few failures
        critical = [f for f in findings if not f.passed and f.severity == Severity.CRITICAL]
        assert len(critical) == 0  # No critical violations
