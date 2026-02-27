"""Tests for ARM template parser — parsing, type mapping, property flattening."""

import json
import pytest
from pathlib import Path

from iac_checker.parser.arm.arm_parser import ArmParser
from iac_checker.parser.arm.type_mapper import arm_type_to_terraform, terraform_type_to_arm
from iac_checker.parser.arm.property_mapper import flatten_arm_resource, _camel_to_snake
from iac_checker.parser.resource_index import ResourceIndex


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "arm"


# ============================================================
# Type Mapper Tests
# ============================================================

class TestTypeMapper:
    def test_storage_account_mapping(self):
        assert arm_type_to_terraform("Microsoft.Storage/storageAccounts") == "azurerm_storage_account"

    def test_key_vault_mapping(self):
        assert arm_type_to_terraform("Microsoft.KeyVault/vaults") == "azurerm_key_vault"

    def test_virtual_network_mapping(self):
        assert arm_type_to_terraform("Microsoft.Network/virtualNetworks") == "azurerm_virtual_network"

    def test_sql_server_mapping(self):
        assert arm_type_to_terraform("Microsoft.Sql/servers") == "azurerm_mssql_server"

    def test_kubernetes_cluster_mapping(self):
        assert arm_type_to_terraform("Microsoft.ContainerService/managedClusters") == "azurerm_kubernetes_cluster"

    def test_case_insensitive(self):
        assert arm_type_to_terraform("microsoft.storage/storageaccounts") == "azurerm_storage_account"

    def test_unknown_type_fallback(self):
        result = arm_type_to_terraform("Microsoft.Foo/bars")
        assert result.startswith("azurerm_")

    def test_reverse_mapping(self):
        assert "storage" in terraform_type_to_arm("azurerm_storage_account").lower()

    def test_reverse_mapping_unknown(self):
        assert terraform_type_to_arm("azurerm_nonexistent_thing") == ""

    def test_firewall_mapping(self):
        assert arm_type_to_terraform("Microsoft.Network/firewalls") == "azurerm_firewall"

    def test_log_analytics_mapping(self):
        assert arm_type_to_terraform("Microsoft.OperationalInsights/workspaces") == "azurerm_log_analytics_workspace"

    def test_policy_assignment_mapping(self):
        assert arm_type_to_terraform("Microsoft.Authorization/policyAssignments") == "azurerm_policy_assignment"

    def test_management_lock_mapping(self):
        assert arm_type_to_terraform("Microsoft.Authorization/locks") == "azurerm_management_lock"

    def test_monitor_alert_mapping(self):
        assert arm_type_to_terraform("Microsoft.Insights/metricAlerts") == "azurerm_monitor_metric_alert"


# ============================================================
# Property Mapper Tests
# ============================================================

class TestPropertyMapper:
    def test_storage_account_flattening(self):
        arm_resource = {
            "type": "Microsoft.Storage/storageAccounts",
            "location": "eastus",
            "tags": {"env": "prod"},
            "sku": {"name": "Standard_GRS"},
            "kind": "StorageV2",
            "properties": {
                "minimumTlsVersion": "TLS1_2",
                "supportsHttpsTrafficOnly": True,
                "allowBlobPublicAccess": False,
                "encryption": {
                    "requireInfrastructureEncryption": True
                },
                "networkAcls": {
                    "defaultAction": "Deny"
                }
            }
        }
        attrs = flatten_arm_resource("Microsoft.Storage/storageAccounts", arm_resource)
        assert attrs["location"] == "eastus"
        assert attrs["tags"] == {"env": "prod"}
        assert attrs["min_tls_version"] == "TLS1_2"
        assert attrs["enable_https_traffic_only"] is True
        assert attrs["infrastructure_encryption_enabled"] is True

    def test_key_vault_flattening(self):
        arm_resource = {
            "type": "Microsoft.KeyVault/vaults",
            "location": "eastus",
            "properties": {
                "enableRbacAuthorization": True,
                "enablePurgeProtection": True,
                "enableSoftDelete": True,
            }
        }
        attrs = flatten_arm_resource("Microsoft.KeyVault/vaults", arm_resource)
        assert attrs["enable_rbac_authorization"] is True
        assert attrs["purge_protection_enabled"] is True
        assert attrs["soft_delete_enabled"] is True

    def test_servicebus_local_auth(self):
        arm_resource = {
            "type": "Microsoft.ServiceBus/namespaces",
            "properties": {
                "disableLocalAuth": True
            }
        }
        attrs = flatten_arm_resource("Microsoft.ServiceBus/namespaces", arm_resource)
        assert attrs["local_auth_enabled"] is False  # disableLocalAuth=True → local_auth_enabled=False (inverted)

    def test_vnet_dns_servers(self):
        arm_resource = {
            "type": "Microsoft.Network/virtualNetworks",
            "location": "eastus",
            "properties": {
                "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                "dhcpOptions": {"dnsServers": ["10.0.0.4"]},
                "subnets": [{"name": "web"}]
            }
        }
        attrs = flatten_arm_resource("Microsoft.Network/virtualNetworks", arm_resource)
        assert attrs["dns_servers"] == ["10.0.0.4"]
        assert attrs["address_space"] == ["10.0.0.0/16"]

    def test_camel_to_snake(self):
        assert _camel_to_snake("minimumTlsVersion") == "minimum_tls_version"
        assert _camel_to_snake("enableRbacAuthorization") == "enable_rbac_authorization"
        assert _camel_to_snake("publicNetworkAccess") == "public_network_access"

    def test_unmapped_properties_fallback(self):
        """Unmapped properties should still appear via camelCase → snake_case fallback."""
        arm_resource = {
            "properties": {
                "someCustomProp": "value123"
            }
        }
        attrs = flatten_arm_resource("Microsoft.UnknownService/things", arm_resource)
        assert attrs["some_custom_prop"] == "value123"


# ============================================================
# ARM Parser Tests
# ============================================================

class TestArmParser:
    def test_can_parse_arm_template(self, tmp_path):
        arm_file = tmp_path / "template.json"
        arm_file.write_text(json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": []
        }))
        parser = ArmParser()
        assert parser.can_parse(arm_file) is True

    def test_cannot_parse_non_arm_json(self, tmp_path):
        json_file = tmp_path / "package.json"
        json_file.write_text(json.dumps({"name": "myapp", "version": "1.0.0"}))
        parser = ArmParser()
        assert parser.can_parse(json_file) is False

    def test_cannot_parse_non_json(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "azurerm_resource_group" "rg" {}')
        parser = ArmParser()
        assert parser.can_parse(tf_file) is False

    def test_parse_storage_account(self, tmp_path):
        arm_file = tmp_path / "storage.json"
        arm_file.write_text(json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [{
                "type": "Microsoft.Storage/storageAccounts",
                "apiVersion": "2023-01-01",
                "name": "mystorageaccount",
                "location": "eastus",
                "sku": {"name": "Standard_GRS"},
                "kind": "StorageV2",
                "tags": {"env": "prod"},
                "properties": {
                    "minimumTlsVersion": "TLS1_2",
                    "supportsHttpsTrafficOnly": True
                }
            }],
            "parameters": {},
            "outputs": {}
        }))
        parser = ArmParser()
        parsed = parser.parse_file(arm_file)
        assert parsed is not None
        assert len(parsed.content["resource"]) == 1
        resource_block = parsed.content["resource"][0]
        assert "azurerm_storage_account" in resource_block
        # Check attributes are flattened
        label = list(resource_block["azurerm_storage_account"].keys())[0]
        attrs = resource_block["azurerm_storage_account"][label]
        assert attrs["location"] == "eastus"
        assert attrs["min_tls_version"] == "TLS1_2"

    def test_parse_parameters_to_variables(self, tmp_path):
        arm_file = tmp_path / "params.json"
        arm_file.write_text(json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "location": {
                    "type": "string",
                    "defaultValue": "eastus",
                    "metadata": {"description": "Deployment region"}
                },
                "storageSku": {
                    "type": "string"
                }
            },
            "resources": [],
            "outputs": {}
        }))
        parser = ArmParser()
        parsed = parser.parse_file(arm_file)
        assert len(parsed.content["variable"]) == 2
        # Check location parameter
        loc_var = parsed.content["variable"][0]
        assert "location" in loc_var
        assert loc_var["location"]["default"] == "eastus"

    def test_parse_outputs(self, tmp_path):
        arm_file = tmp_path / "outputs.json"
        arm_file.write_text(json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [],
            "parameters": {},
            "outputs": {
                "storageId": {
                    "type": "string",
                    "value": "[resourceId('Microsoft.Storage/storageAccounts', 'mystg')]"
                }
            }
        }))
        parser = ArmParser()
        parsed = parser.parse_file(arm_file)
        assert len(parsed.content["output"]) == 1
        assert "storageId" in parsed.content["output"][0]

    def test_parse_arm_metadata_suppressions(self, tmp_path):
        arm_file = tmp_path / "suppressed.json"
        arm_file.write_text(json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [{
                "type": "Microsoft.Storage/storageAccounts",
                "apiVersion": "2023-01-01",
                "name": "mystorage",
                "location": "eastus",
                "sku": {"name": "Standard_LRS"},
                "kind": "StorageV2",
                "metadata": {
                    "waf-ignore": "WAF-SEC-017, WAF-REL-013"
                },
                "properties": {}
            }]
        }))
        parser = ArmParser()
        parsed = parser.parse_file(arm_file)
        resource_block = parsed.content["resource"][0]
        label = list(resource_block["azurerm_storage_account"].keys())[0]
        attrs = resource_block["azurerm_storage_account"][label]
        assert attrs["_waf_ignore"] == "WAF-SEC-017, WAF-REL-013"

    def test_parse_fixture_compliant(self):
        fixture = FIXTURES_DIR / "compliant.json"
        if not fixture.exists():
            pytest.skip("Fixture not found")
        parser = ArmParser()
        parsed = parser.parse_file(fixture)
        assert parsed is not None
        assert len(parsed.content["resource"]) >= 3  # storage, kv, vnet, law

    def test_parse_fixture_non_compliant(self):
        fixture = FIXTURES_DIR / "non_compliant.json"
        if not fixture.exists():
            pytest.skip("Fixture not found")
        parser = ArmParser()
        parsed = parser.parse_file(fixture)
        assert parsed is not None
        assert len(parsed.content["resource"]) >= 2


# ============================================================
# ARM → Resource Index Integration Tests
# ============================================================

class TestArmResourceIndex:
    def test_arm_resources_indexed(self, tmp_path):
        """ARM resources should be indexed and queryable like Terraform resources."""
        arm_file = tmp_path / "main.json"
        arm_file.write_text(json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "apiVersion": "2023-01-01",
                    "name": "mystg",
                    "location": "eastus",
                    "sku": {"name": "Standard_GRS"},
                    "kind": "StorageV2",
                    "properties": {
                        "minimumTlsVersion": "TLS1_2",
                        "supportsHttpsTrafficOnly": True
                    }
                },
                {
                    "type": "Microsoft.KeyVault/vaults",
                    "apiVersion": "2023-02-01",
                    "name": "mykv",
                    "location": "eastus",
                    "properties": {
                        "enableRbacAuthorization": True,
                        "enablePurgeProtection": True
                    }
                }
            ]
        }))

        parser = ArmParser()
        parsed = parser.parse_file(arm_file)

        index = ResourceIndex()
        index.build([parsed])

        # Verify resources are indexed with correct Terraform types
        storage_accounts = index.get_resources_by_type("azurerm_storage_account")
        assert len(storage_accounts) == 1
        assert storage_accounts[0].get_attribute("min_tls_version") == "TLS1_2"

        key_vaults = index.get_resources_by_type("azurerm_key_vault")
        assert len(key_vaults) == 1
        assert key_vaults[0].get_attribute("enable_rbac_authorization") is True

    def test_arm_rules_evaluate_on_parsed_resources(self, tmp_path):
        """WAF rules should work on ARM-parsed resources."""
        from iac_checker.rules.waf.security import InfrastructureEncryptionRule

        arm_file = tmp_path / "storage.json"
        arm_file.write_text(json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [{
                "type": "Microsoft.Storage/storageAccounts",
                "apiVersion": "2023-01-01",
                "name": "mystg",
                "location": "eastus",
                "sku": {"name": "Standard_GRS"},
                "kind": "StorageV2",
                "properties": {
                    "encryption": {
                        "requireInfrastructureEncryption": True
                    }
                }
            }]
        }))

        parser = ArmParser()
        parsed = parser.parse_file(arm_file)
        index = ResourceIndex()
        index.build([parsed])

        rule = InfrastructureEncryptionRule()
        storage = index.get_resources_by_type("azurerm_storage_account")[0]
        finding = rule.evaluate(storage, index)
        assert finding is not None
        assert finding.passed is True

    def test_arm_rules_detect_violation(self, tmp_path):
        """WAF rules should detect violations in ARM-parsed resources."""
        from iac_checker.rules.waf.security import InfrastructureEncryptionRule

        arm_file = tmp_path / "storage.json"
        arm_file.write_text(json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [{
                "type": "Microsoft.Storage/storageAccounts",
                "apiVersion": "2023-01-01",
                "name": "mystg",
                "location": "eastus",
                "sku": {"name": "Standard_LRS"},
                "kind": "StorageV2",
                "properties": {}
            }]
        }))

        parser = ArmParser()
        parsed = parser.parse_file(arm_file)
        index = ResourceIndex()
        index.build([parsed])

        rule = InfrastructureEncryptionRule()
        storage = index.get_resources_by_type("azurerm_storage_account")[0]
        finding = rule.evaluate(storage, index)
        assert finding is not None
        assert finding.passed is False
