"""Tests for the IaC file scanner and resource index utilities."""

import json
import pytest
from pathlib import Path
from iac_checker.parser.scanner import IacScanner, TerraformScanner
from iac_checker.parser.resource_index import ResourceIndex


FIXTURES = Path(__file__).parent / "fixtures"


class TestIacScanner:
    """Tests for the multi-format IacScanner."""

    def test_discover_valid_terraform(self):
        scanner = IacScanner(root_path=FIXTURES / "valid_terraform", formats={"terraform"})
        result = scanner.discover()
        tf_files = result["terraform"]
        assert len(tf_files) >= 1
        assert all(f.suffix in {".tf", ".tfvars"} for f in tf_files)

    def test_discover_invalid_terraform(self):
        scanner = IacScanner(root_path=FIXTURES / "invalid_terraform", formats={"terraform"})
        result = scanner.discover()
        assert len(result["terraform"]) >= 1

    def test_discover_empty_dir(self, tmp_path):
        scanner = IacScanner(root_path=tmp_path, formats={"terraform"})
        result = scanner.discover()
        assert result["terraform"] == []

    def test_discover_excludes_paths(self, tmp_path):
        (tmp_path / "main.tf").write_text('resource "azurerm_resource_group" "rg" {}')
        excluded_dir = tmp_path / ".terraform"
        excluded_dir.mkdir()
        (excluded_dir / "providers.tf").write_text("provider {}")

        scanner = IacScanner(root_path=tmp_path, exclude_paths=[".terraform/"], formats={"terraform"})
        result = scanner.discover()
        assert len(result["terraform"]) == 1
        assert result["terraform"][0].name == "main.tf"

    def test_discover_finds_tfvars(self, tmp_path):
        (tmp_path / "vars.tfvars").write_text('location = "eastus2"')
        scanner = IacScanner(root_path=tmp_path, formats={"terraform"})
        result = scanner.discover()
        assert len(result["terraform"]) == 1
        assert result["terraform"][0].suffix == ".tfvars"

    def test_discover_ignores_non_tf_files(self, tmp_path):
        (tmp_path / "main.tf").write_text("resource {}")
        (tmp_path / "readme.md").write_text("# Hello")
        (tmp_path / "script.py").write_text("print('hi')")

        scanner = IacScanner(root_path=tmp_path, formats={"terraform"})
        result = scanner.discover()
        assert len(result["terraform"]) == 1

    def test_discover_recursive(self, tmp_path):
        (tmp_path / "main.tf").write_text("resource {}")
        sub = tmp_path / "modules" / "db"
        sub.mkdir(parents=True)
        (sub / "main.tf").write_text("resource {}")

        scanner = IacScanner(root_path=tmp_path, formats={"terraform"})
        result = scanner.discover()
        assert len(result["terraform"]) == 2

    def test_results_sorted(self, tmp_path):
        (tmp_path / "z.tf").write_text("")
        (tmp_path / "a.tf").write_text("")
        (tmp_path / "m.tf").write_text("")

        scanner = IacScanner(root_path=tmp_path, formats={"terraform"})
        result = scanner.discover()
        names = [f.name for f in result["terraform"]]
        assert names == sorted(names)

    def test_discover_arm_templates(self, tmp_path):
        arm = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0", "resources": [],
        }
        (tmp_path / "main.json").write_text(json.dumps(arm))
        (tmp_path / "other.json").write_text('{"key": "value"}')

        scanner = IacScanner(root_path=tmp_path, formats={"arm"})
        result = scanner.discover()
        assert len(result["arm"]) == 1
        assert result["arm"][0].name == "main.json"

    def test_discover_bicep_files(self, tmp_path):
        (tmp_path / "main.bicep").write_text("resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {}")
        scanner = IacScanner(root_path=tmp_path, formats={"bicep"})
        result = scanner.discover()
        assert len(result["bicep"]) == 1

    def test_discover_all_formats(self, tmp_path):
        (tmp_path / "main.tf").write_text("resource {}")
        arm = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0", "resources": [],
        }
        (tmp_path / "deploy.json").write_text(json.dumps(arm))
        (tmp_path / "main.bicep").write_text("resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {}")

        scanner = IacScanner(root_path=tmp_path)
        result = scanner.discover()
        assert len(result["terraform"]) == 1
        assert len(result["arm"]) == 1
        assert len(result["bicep"]) == 1

    def test_backward_compatible_alias(self, tmp_path):
        """TerraformScanner is an alias for IacScanner."""
        assert TerraformScanner is IacScanner


class TestInlineSuppressions:
    """Tests for ResourceIndex.get_inline_suppressions()."""

    def _make_index_with_lines(self, file_path, lines):
        idx = ResourceIndex()
        idx.raw_lines_by_file[file_path] = lines
        return idx

    def test_single_waf_ignore(self):
        lines = [
            '# waf-ignore: WAF-SEC-019',
            'resource "azurerm_mssql_server" "legacy" {',
        ]
        idx = self._make_index_with_lines("main.tf", lines)
        suppressions = idx.get_inline_suppressions("main.tf", 2)
        assert "WAF-SEC-019" in suppressions

    def test_multiple_rule_ids(self):
        lines = [
            '# waf-ignore: WAF-SEC-019, WAF-REL-002',
            'resource "azurerm_mssql_server" "legacy" {',
        ]
        idx = self._make_index_with_lines("main.tf", lines)
        suppressions = idx.get_inline_suppressions("main.tf", 2)
        assert "WAF-SEC-019" in suppressions
        assert "WAF-REL-002" in suppressions

    def test_caf_ignore(self):
        lines = [
            '# caf-ignore: CAF-TAG-012',
            'resource "azurerm_resource_group" "temp" {',
        ]
        idx = self._make_index_with_lines("main.tf", lines)
        suppressions = idx.get_inline_suppressions("main.tf", 2)
        assert "CAF-TAG-012" in suppressions

    def test_no_suppression_when_absent(self):
        lines = [
            '# This is a normal comment',
            'resource "azurerm_resource_group" "main" {',
        ]
        idx = self._make_index_with_lines("main.tf", lines)
        suppressions = idx.get_inline_suppressions("main.tf", 2)
        assert suppressions == []

    def test_suppression_only_checks_5_lines_above(self):
        lines = [
            '# waf-ignore: WAF-SEC-019',  # line 1 — too far above line 8
            '',
            '',
            '',
            '',
            '',
            '',
            'resource "azurerm_mssql_server" "legacy" {',  # line 8
        ]
        idx = self._make_index_with_lines("main.tf", lines)
        suppressions = idx.get_inline_suppressions("main.tf", 8)
        assert "WAF-SEC-019" not in suppressions

    def test_suppression_within_5_lines(self):
        lines = [
            '',
            '',
            '# waf-ignore: WAF-SEC-019',  # line 3 — within 5 lines of line 6
            '',
            '',
            'resource "azurerm_mssql_server" "legacy" {',  # line 6
        ]
        idx = self._make_index_with_lines("main.tf", lines)
        suppressions = idx.get_inline_suppressions("main.tf", 6)
        assert "WAF-SEC-019" in suppressions

    def test_unknown_file_returns_empty(self):
        idx = ResourceIndex()
        suppressions = idx.get_inline_suppressions("nonexistent.tf", 5)
        assert suppressions == []
