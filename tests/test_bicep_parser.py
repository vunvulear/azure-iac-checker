"""Tests for Bicep parser — transpilation check and comment suppression."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import json

from iac_checker.parser.bicep.bicep_parser import BicepParser
from iac_checker.parser.resource_index import ResourceIndex


class TestBicepParserCanParse:
    def test_can_parse_bicep_file(self, tmp_path):
        bicep_file = tmp_path / "main.bicep"
        bicep_file.write_text("param location string")
        parser = BicepParser()
        assert parser.can_parse(bicep_file) is True

    def test_cannot_parse_json_file(self, tmp_path):
        json_file = tmp_path / "main.json"
        json_file.write_text("{}")
        parser = BicepParser()
        assert parser.can_parse(json_file) is False

    def test_cannot_parse_tf_file(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text("")
        parser = BicepParser()
        assert parser.can_parse(tf_file) is False


class TestBicepParserCliDetection:
    def test_bicep_cli_not_found(self):
        parser = BicepParser(bicep_cli_path="nonexistent_binary_xyz")
        parser._bicep_available = None
        # Mock subprocess to raise FileNotFoundError for both attempts
        with patch("iac_checker.parser.bicep.bicep_parser.subprocess.run",
                    side_effect=FileNotFoundError):
            assert parser.is_bicep_cli_available() is False

    def test_bicep_cli_found(self):
        parser = BicepParser()
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("iac_checker.parser.bicep.bicep_parser.subprocess.run",
                    return_value=mock_result):
            parser._bicep_available = None
            assert parser.is_bicep_cli_available() is True


class TestBicepParserWithMockedCli:
    """Test Bicep parsing by mocking the CLI transpilation to return ARM JSON."""

    def _make_arm_json(self, resources=None):
        return json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": resources or [],
            "parameters": {},
            "outputs": {}
        })

    def test_parse_bicep_with_storage(self, tmp_path):
        bicep_file = tmp_path / "main.bicep"
        bicep_content = """\
param location string = resourceGroup().location

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystg'
  location: location
  sku: { name: 'Standard_GRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}
"""
        bicep_file.write_text(bicep_content)

        arm_json = self._make_arm_json([{
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2023-01-01",
            "name": "mystg",
            "location": "[parameters('location')]",
            "sku": {"name": "Standard_GRS"},
            "kind": "StorageV2",
            "properties": {
                "minimumTlsVersion": "TLS1_2",
                "supportsHttpsTrafficOnly": True
            }
        }])

        parser = BicepParser()
        parser._bicep_available = True

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = arm_json

        with patch("iac_checker.parser.bicep.bicep_parser.subprocess.run",
                    return_value=mock_result):
            parsed = parser.parse_file(bicep_file)

        assert parsed is not None
        assert len(parsed.content["resource"]) == 1
        # Raw lines should be from original .bicep, not the ARM JSON
        assert "param location" in parsed.raw_lines[0]

    def test_parse_bicep_resources_indexed(self, tmp_path):
        bicep_file = tmp_path / "main.bicep"
        bicep_file.write_text("resource kv 'Microsoft.KeyVault/vaults@2023-02-01' = {}")

        arm_json = self._make_arm_json([{
            "type": "Microsoft.KeyVault/vaults",
            "apiVersion": "2023-02-01",
            "name": "kv-prod",
            "location": "eastus",
            "properties": {
                "enableRbacAuthorization": True,
                "enablePurgeProtection": True,
                "enableSoftDelete": True,
            }
        }])

        parser = BicepParser()
        parser._bicep_available = True

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = arm_json

        with patch("iac_checker.parser.bicep.bicep_parser.subprocess.run",
                    return_value=mock_result):
            parsed = parser.parse_file(bicep_file)

        index = ResourceIndex()
        index.build([parsed])

        kvs = index.get_resources_by_type("azurerm_key_vault")
        assert len(kvs) == 1
        assert kvs[0].get_attribute("enable_rbac_authorization") is True
        assert kvs[0].get_attribute("purge_protection_enabled") is True

    def test_bicep_cli_failure_returns_none(self, tmp_path):
        bicep_file = tmp_path / "broken.bicep"
        bicep_file.write_text("invalid bicep content")

        parser = BicepParser()
        parser._bicep_available = True

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Error: some compilation error"

        with patch("iac_checker.parser.bicep.bicep_parser.subprocess.run",
                    return_value=mock_result):
            parsed = parser.parse_file(bicep_file)

        assert parsed is None

    def test_bicep_not_installed_returns_none(self, tmp_path):
        bicep_file = tmp_path / "main.bicep"
        bicep_file.write_text("param x string")

        parser = BicepParser()
        parser._bicep_available = False

        parsed = parser.parse_file(bicep_file)
        assert parsed is None


class TestBicepSuppressionComments:
    """Bicep uses // comments for suppressions."""

    def test_bicep_suppression_parsed(self):
        index = ResourceIndex()
        index.raw_lines_by_file["main.bicep"] = [
            "param location string",
            "",
            "// waf-ignore: WAF-SEC-017, WAF-REL-013",
            "// caf-ignore: CAF-TAG-001",
            "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {",
            "  name: 'mystg'",
            "}",
        ]
        suppressions = index.get_inline_suppressions("main.bicep", 5)
        assert "WAF-SEC-017" in suppressions
        assert "WAF-REL-013" in suppressions
        assert "CAF-TAG-001" in suppressions

    def test_no_suppression_when_no_comments(self):
        index = ResourceIndex()
        index.raw_lines_by_file["main.bicep"] = [
            "param location string",
            "",
            "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {",
            "  name: 'mystg'",
            "}",
        ]
        suppressions = index.get_inline_suppressions("main.bicep", 3)
        assert suppressions == []


class TestArmMetadataSuppressions:
    def test_arm_metadata_waf_ignore(self):
        from iac_checker.models.resource import TerraformResource
        resource = TerraformResource(
            resource_type="azurerm_storage_account",
            name="mystg",
            attributes={"_waf_ignore": "WAF-SEC-017, WAF-REL-013"},
            file_path="main.json",
            line_number=10,
        )
        index = ResourceIndex()
        suppressions = index.get_arm_metadata_suppressions(resource)
        assert "WAF-SEC-017" in suppressions
        assert "WAF-REL-013" in suppressions

    def test_no_arm_metadata_suppression(self):
        from iac_checker.models.resource import TerraformResource
        resource = TerraformResource(
            resource_type="azurerm_storage_account",
            name="mystg",
            attributes={"location": "eastus"},
            file_path="main.json",
            line_number=10,
        )
        index = ResourceIndex()
        suppressions = index.get_arm_metadata_suppressions(resource)
        assert suppressions == []
