"""Bicep rule tests — mirrors test_new_rules.py through the Bicep (mocked CLI) pipeline.

For each of the 24 new rules, this creates ARM JSON (as if transpiled from Bicep),
parses through BicepParser with a mocked CLI, and evaluates the same rules.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from iac_checker.parser.bicep.bicep_parser import BicepParser
from iac_checker.parser.resource_index import ResourceIndex


def _arm_json(resources=None, parameters=None, outputs=None):
    """Build ARM JSON string as if produced by 'bicep build --stdout'."""
    return json.dumps({
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": parameters or {},
        "resources": resources or [],
        "outputs": outputs or {},
    })


def _parse_bicep(tmp_path, bicep_content, arm_resources, filename="main.bicep"):
    """Write a .bicep file, mock CLI transpilation with given ARM resources, return ResourceIndex."""
    bicep_file = tmp_path / filename
    bicep_file.write_text(bicep_content, encoding="utf-8")

    parser = BicepParser()
    parser._bicep_available = True

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = _arm_json(resources=arm_resources)

    with patch("iac_checker.parser.bicep.bicep_parser.subprocess.run", return_value=mock_result):
        parsed = parser.parse_file(bicep_file)

    assert parsed is not None, f"Bicep parse failed for {filename}"
    idx = ResourceIndex()
    idx.build([parsed])
    return idx


# ============================================================
# WAF Reliability — WAF-REL-005: Multi-region deployment
# ============================================================

class TestBicepMultiRegionDeployment:
    def test_multi_region_pass(self, tmp_path):
        from iac_checker.rules.waf.reliability import MultiRegionDeploymentRule
        rule = MultiRegionDeploymentRule()
        idx = _parse_bicep(tmp_path,
            "resource rg1 'Microsoft.Resources/resourceGroups@2022-09-01' = { name: 'rg1' location: 'eastus' }",
            arm_resources=[
                {"type": "Microsoft.Resources/resourceGroups", "apiVersion": "2022-09-01",
                 "name": "rg1", "location": "eastus", "properties": {}},
                {"type": "Microsoft.Resources/resourceGroups", "apiVersion": "2022-09-01",
                 "name": "rg2", "location": "westus", "properties": {}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_single_region_fail(self, tmp_path):
        from iac_checker.rules.waf.reliability import MultiRegionDeploymentRule
        rule = MultiRegionDeploymentRule()
        idx = _parse_bicep(tmp_path,
            "resource rg1 'Microsoft.Resources/resourceGroups@2022-09-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Resources/resourceGroups", "apiVersion": "2022-09-01",
                 "name": "rg1", "location": "eastus", "properties": {}},
                {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
                 "name": "st1", "location": "eastus", "sku": {"name": "Standard_LRS"},
                 "kind": "StorageV2", "properties": {}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Reliability — WAF-REL-006: Scaling configuration
# ============================================================

class TestBicepScalingConfig:
    def test_autoscale_present_pass(self, tmp_path):
        from iac_checker.rules.waf.reliability import ScalingConfigRule
        rule = ScalingConfigRule()
        idx = _parse_bicep(tmp_path,
            "resource plan 'Microsoft.Web/serverfarms@2022-09-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Web/serverfarms", "apiVersion": "2022-09-01",
                 "name": "plan1", "location": "eastus", "sku": {"name": "S1"}, "properties": {}},
                {"type": "Microsoft.Insights/autoscaleSettings", "apiVersion": "2022-10-01",
                 "name": "as1", "location": "eastus",
                 "properties": {"targetResourceUri": "azurerm_service_plan.plan1"}},
            ])
        plans = idx.get_resources_by_type("azurerm_service_plan")
        finding = rule.evaluate(plans[0], idx)
        assert finding.passed is True

    def test_autoscale_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.reliability import ScalingConfigRule
        rule = ScalingConfigRule()
        idx = _parse_bicep(tmp_path,
            "resource plan 'Microsoft.Web/serverfarms@2022-09-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Web/serverfarms", "apiVersion": "2022-09-01",
                 "name": "plan1", "location": "eastus", "sku": {"name": "S1"}, "properties": {}},
            ])
        plans = idx.get_resources_by_type("azurerm_service_plan")
        finding = rule.evaluate(plans[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Reliability — WAF-REL-010: Monitoring alerts
# ============================================================

class TestBicepMonitoringAlert:
    def test_alert_present_pass(self, tmp_path):
        from iac_checker.rules.waf.reliability import MonitoringAlertRule
        rule = MonitoringAlertRule()
        idx = _parse_bicep(tmp_path,
            "resource alert 'Microsoft.Insights/metricAlerts@2018-03-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Insights/metricAlerts", "apiVersion": "2018-03-01",
                 "name": "cpu-alert", "location": "global",
                 "properties": {"severity": 2, "enabled": True}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_alert_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.reliability import MonitoringAlertRule
        rule = MonitoringAlertRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-004: Network segmentation
# ============================================================

class TestBicepNetworkSegmentation:
    def test_vnet_with_subnets_pass(self, tmp_path):
        from iac_checker.rules.waf.security import NetworkSegmentationRule
        rule = NetworkSegmentationRule()
        idx = _parse_bicep(tmp_path,
            "resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "vnet1", "location": "eastus",
                 "properties": {
                     "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                     "subnets": [{"name": "web", "properties": {"addressPrefix": "10.0.1.0/24"}}],
                 }},
            ])
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is True

    def test_vnet_with_separate_subnet_pass(self, tmp_path):
        from iac_checker.rules.waf.security import NetworkSegmentationRule
        rule = NetworkSegmentationRule()
        idx = _parse_bicep(tmp_path,
            "resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "vnet1", "location": "eastus",
                 "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
                {"type": "Microsoft.Network/virtualNetworks/subnets", "apiVersion": "2023-05-01",
                 "name": "vnet1/web", "location": "eastus",
                 "properties": {"addressPrefix": "10.0.1.0/24",
                                "virtualNetworkName": "azurerm_virtual_network.vnet1"}},
            ])
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is True

    def test_vnet_no_subnets_fail(self, tmp_path):
        from iac_checker.rules.waf.security import NetworkSegmentationRule
        rule = NetworkSegmentationRule()
        idx = _parse_bicep(tmp_path,
            "resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "vnet1", "location": "eastus",
                 "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
            ])
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-005: Disable local auth
# ============================================================

class TestBicepDisableLocalAuth:
    def test_local_auth_disabled_pass(self, tmp_path):
        from iac_checker.rules.waf.security import DisableLocalAuthRule
        rule = DisableLocalAuthRule()
        idx = _parse_bicep(tmp_path,
            "resource sb 'Microsoft.ServiceBus/namespaces@2022-10-01' = {}",
            arm_resources=[
                {"type": "Microsoft.ServiceBus/namespaces", "apiVersion": "2022-10-01",
                 "name": "sb1", "location": "eastus", "sku": {"name": "Standard"},
                 "properties": {"disableLocalAuth": True}},
            ])
        sbs = idx.get_resources_by_type("azurerm_servicebus_namespace")
        finding = rule.evaluate(sbs[0], idx)
        assert finding.passed is True

    def test_local_auth_enabled_fail(self, tmp_path):
        from iac_checker.rules.waf.security import DisableLocalAuthRule
        rule = DisableLocalAuthRule()
        idx = _parse_bicep(tmp_path,
            "resource sb 'Microsoft.ServiceBus/namespaces@2022-10-01' = {}",
            arm_resources=[
                {"type": "Microsoft.ServiceBus/namespaces", "apiVersion": "2022-10-01",
                 "name": "sb1", "location": "eastus", "sku": {"name": "Standard"},
                 "properties": {"disableLocalAuth": False}},
            ])
        sbs = idx.get_resources_by_type("azurerm_servicebus_namespace")
        finding = rule.evaluate(sbs[0], idx)
        assert finding.passed is False

    def test_local_auth_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.security import DisableLocalAuthRule
        rule = DisableLocalAuthRule()
        idx = _parse_bicep(tmp_path,
            "resource eh 'Microsoft.EventHub/namespaces@2022-10-01' = {}",
            arm_resources=[
                {"type": "Microsoft.EventHub/namespaces", "apiVersion": "2022-10-01",
                 "name": "eh1", "location": "eastus", "sku": {"name": "Standard"},
                 "properties": {}},
            ])
        ehs = idx.get_resources_by_type("azurerm_eventhub_namespace")
        finding = rule.evaluate(ehs[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-010: Defender for Cloud
# ============================================================

class TestBicepDefenderForCloud:
    def test_defender_present_pass(self, tmp_path):
        from iac_checker.rules.waf.security import DefenderForCloudRule
        rule = DefenderForCloudRule()
        idx = _parse_bicep(tmp_path,
            "resource defender 'Microsoft.Security/pricings@2022-03-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Security/pricings", "apiVersion": "2022-03-01",
                 "name": "VirtualMachines",
                 "properties": {"pricingTier": "Standard"}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_defender_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.security import DefenderForCloudRule
        rule = DefenderForCloudRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-015: Infrastructure encryption
# ============================================================

class TestBicepInfrastructureEncryption:
    def test_infra_encryption_enabled_pass(self, tmp_path):
        from iac_checker.rules.waf.security import InfrastructureEncryptionRule
        rule = InfrastructureEncryptionRule()
        idx = _parse_bicep(tmp_path,
            "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
                 "name": "mystg", "location": "eastus",
                 "sku": {"name": "Standard_GRS"}, "kind": "StorageV2",
                 "properties": {"encryption": {"requireInfrastructureEncryption": True}}},
            ])
        stg = idx.get_resources_by_type("azurerm_storage_account")
        finding = rule.evaluate(stg[0], idx)
        assert finding.passed is True

    def test_infra_encryption_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.security import InfrastructureEncryptionRule
        rule = InfrastructureEncryptionRule()
        idx = _parse_bicep(tmp_path,
            "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
                 "name": "mystg", "location": "eastus",
                 "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
                 "properties": {}},
            ])
        stg = idx.get_resources_by_type("azurerm_storage_account")
        finding = rule.evaluate(stg[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Operational — WAF-OPS-006: Module version pinning
# (Bicep modules don't produce ARM module blocks — test no-modules pass)
# ============================================================

class TestBicepModuleVersionPinning:
    def test_no_modules_pass(self, tmp_path):
        from iac_checker.rules.waf.operational import ModuleVersionPinningRule
        rule = ModuleVersionPinningRule()
        idx = _parse_bicep(tmp_path, "// no modules", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_bicep_with_resources_no_modules_pass(self, tmp_path):
        """Bicep files with resources but no modules should pass module pinning."""
        from iac_checker.rules.waf.operational import ModuleVersionPinningRule
        rule = ModuleVersionPinningRule()
        idx = _parse_bicep(tmp_path,
            "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
                 "name": "mystg", "location": "eastus",
                 "sku": {"name": "Standard_LRS"}, "kind": "StorageV2", "properties": {}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_bicep_multi_resources_no_modules_pass(self, tmp_path):
        """Bicep files with multiple resources but no modules should pass."""
        from iac_checker.rules.waf.operational import ModuleVersionPinningRule
        rule = ModuleVersionPinningRule()
        idx = _parse_bicep(tmp_path,
            "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
                 "name": "stg1", "location": "eastus",
                 "sku": {"name": "Standard_LRS"}, "kind": "StorageV2", "properties": {}},
                {"type": "Microsoft.KeyVault/vaults", "apiVersion": "2023-02-01",
                 "name": "kv1", "location": "eastus",
                 "properties": {"enableRbacAuthorization": True}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True


# ============================================================
# WAF Operational — WAF-OPS-009: Lifecycle blocks
# (Bicep has no lifecycle blocks — ARM-parsed KV will fail)
# ============================================================

class TestBicepLifecycleBlock:
    def test_lifecycle_present_pass(self, tmp_path):
        """Bicep resource with lifecycle metadata injected should pass."""
        from iac_checker.rules.waf.operational import LifecycleBlockRule
        rule = LifecycleBlockRule()
        idx = _parse_bicep(tmp_path,
            "resource kv 'Microsoft.KeyVault/vaults@2023-02-01' = {}",
            arm_resources=[
                {"type": "Microsoft.KeyVault/vaults", "apiVersion": "2023-02-01",
                 "name": "kv1", "location": "eastus",
                 "properties": {"enableRbacAuthorization": True,
                                "lifecycle": {"prevent_destroy": True}}},
            ])
        kvs = idx.get_resources_by_type("azurerm_key_vault")
        finding = rule.evaluate(kvs[0], idx)
        assert finding.passed is True

    def test_lifecycle_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.operational import LifecycleBlockRule
        rule = LifecycleBlockRule()
        idx = _parse_bicep(tmp_path,
            "resource kv 'Microsoft.KeyVault/vaults@2023-02-01' = {}",
            arm_resources=[
                {"type": "Microsoft.KeyVault/vaults", "apiVersion": "2023-02-01",
                 "name": "kv1", "location": "eastus",
                 "properties": {"enableRbacAuthorization": True}},
            ])
        kvs = idx.get_resources_by_type("azurerm_key_vault")
        finding = rule.evaluate(kvs[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Operational — WAF-OPS-011: Deployment slots
# ============================================================

class TestBicepDeploymentSlots:
    def test_slot_present_pass(self, tmp_path):
        from iac_checker.rules.waf.operational import DeploymentSlotsRule
        rule = DeploymentSlotsRule()
        idx = _parse_bicep(tmp_path,
            "resource app 'Microsoft.Web/sites@2022-09-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Web/sites", "apiVersion": "2022-09-01",
                 "name": "myapp", "location": "eastus",
                 "properties": {"httpsOnly": True}},
                {"type": "Microsoft.Web/sites/slots", "apiVersion": "2022-09-01",
                 "name": "myapp/staging", "location": "eastus",
                 "properties": {"app_service_id": "azurerm_linux_web_app.myapp.id"}},
            ])
        apps = idx.get_resources_by_type("azurerm_linux_web_app")
        finding = rule.evaluate(apps[0], idx)
        assert finding.passed is True

    def test_slot_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.operational import DeploymentSlotsRule
        rule = DeploymentSlotsRule()
        idx = _parse_bicep(tmp_path,
            "resource app 'Microsoft.Web/sites@2022-09-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Web/sites", "apiVersion": "2022-09-01",
                 "name": "myapp", "location": "eastus",
                 "properties": {"httpsOnly": True}},
            ])
        apps = idx.get_resources_by_type("azurerm_linux_web_app")
        finding = rule.evaluate(apps[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Cost — WAF-COST-004: Budget alerts
# ============================================================

class TestBicepBudgetAlert:
    def test_budget_present_pass(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import BudgetAlertRule
        rule = BudgetAlertRule()
        idx = _parse_bicep(tmp_path,
            "resource budget 'Microsoft.Consumption/budgets@2023-03-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Consumption/budgets", "apiVersion": "2023-03-01",
                 "name": "monthly-budget",
                 "properties": {"amount": 1000}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_budget_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import BudgetAlertRule
        rule = BudgetAlertRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Cost — WAF-COST-005: Reserved instances
# ============================================================

class TestBicepReservedInstances:
    def test_non_prod_vm_pass(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import ReservedInstancesRule
        rule = ReservedInstancesRule()
        idx = _parse_bicep(tmp_path,
            "resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-03-01",
                 "name": "vm-dev", "location": "eastus", "tags": {"env": "dev"},
                 "properties": {"hardwareProfile": {"vmSize": "Standard_D2s_v3"}}},
            ])
        vms = idx.get_resources_by_type("azurerm_linux_virtual_machine")
        finding = rule.evaluate(vms[0], idx)
        assert finding.passed is True

    def test_prod_vm_fail(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import ReservedInstancesRule
        rule = ReservedInstancesRule()
        idx = _parse_bicep(tmp_path,
            "resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-03-01",
                 "name": "vm-prod", "location": "eastus", "tags": {"env": "prod"},
                 "properties": {"hardwareProfile": {"vmSize": "Standard_D4s_v3"}}},
            ])
        vms = idx.get_resources_by_type("azurerm_linux_virtual_machine")
        finding = rule.evaluate(vms[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Cost — WAF-COST-012: Autoscale validation
# ============================================================

class TestBicepAutoscaleValidation:
    def test_valid_autoscale_pass(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import AutoscaleValidationRule
        rule = AutoscaleValidationRule()
        idx = _parse_bicep(tmp_path,
            "resource as 'Microsoft.Insights/autoscaleSettings@2022-10-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Insights/autoscaleSettings", "apiVersion": "2022-10-01",
                 "name": "as1", "location": "eastus",
                 "properties": {
                     "profiles": [{"capacity": {"minimum": 1, "default": 2, "maximum": 10}}],
                     "enabled": True}},
            ])
        autoscale = idx.get_resources_by_type("azurerm_monitor_autoscale_setting")
        finding = rule.evaluate(autoscale[0], idx)
        assert finding.passed is True

    def test_invalid_autoscale_fail(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import AutoscaleValidationRule
        rule = AutoscaleValidationRule()
        idx = _parse_bicep(tmp_path,
            "resource as 'Microsoft.Insights/autoscaleSettings@2022-10-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Insights/autoscaleSettings", "apiVersion": "2022-10-01",
                 "name": "as1", "location": "eastus",
                 "properties": {
                     "profiles": [{"capacity": {"minimum": 10, "default": 5, "maximum": 3}}],
                     "enabled": True}},
            ])
        autoscale = idx.get_resources_by_type("azurerm_monitor_autoscale_setting")
        finding = rule.evaluate(autoscale[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Performance — WAF-PERF-003: Explicit SKU
# ============================================================

class TestBicepExplicitSku:
    def test_sku_set_pass(self, tmp_path):
        from iac_checker.rules.waf.performance import ExplicitSkuRule
        rule = ExplicitSkuRule()
        idx = _parse_bicep(tmp_path,
            "resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-03-01",
                 "name": "vm1", "location": "eastus",
                 "properties": {"hardwareProfile": {"vmSize": "Standard_D2s_v3"}}},
            ])
        vms = idx.get_resources_by_type("azurerm_linux_virtual_machine")
        finding = rule.evaluate(vms[0], idx)
        assert finding.passed is True

    def test_sku_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.performance import ExplicitSkuRule
        rule = ExplicitSkuRule()
        idx = _parse_bicep(tmp_path,
            "resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-03-01",
                 "name": "vm1", "location": "eastus", "properties": {}},
            ])
        vms = idx.get_resources_by_type("azurerm_linux_virtual_machine")
        finding = rule.evaluate(vms[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Performance — WAF-PERF-007: CDN/Caching
# ============================================================

class TestBicepCdnCaching:
    def test_cdn_present_pass(self, tmp_path):
        from iac_checker.rules.waf.performance import CdnCachingRule
        rule = CdnCachingRule()
        idx = _parse_bicep(tmp_path,
            "resource cdn 'Microsoft.Cdn/profiles@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Cdn/profiles", "apiVersion": "2023-05-01",
                 "name": "cdn1", "location": "global",
                 "sku": {"name": "Standard_Microsoft"}, "properties": {}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_cdn_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.performance import CdnCachingRule
        rule = CdnCachingRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-001: Defender for Cloud
# ============================================================

class TestBicepCafDefenderForCloud:
    def test_defender_present_pass(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import CafDefenderForCloudRule
        rule = CafDefenderForCloudRule()
        idx = _parse_bicep(tmp_path,
            "resource def 'Microsoft.Security/pricings@2022-03-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Security/pricings", "apiVersion": "2022-03-01",
                 "name": "VirtualMachines", "properties": {"pricingTier": "Standard"}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_defender_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import CafDefenderForCloudRule
        rule = CafDefenderForCloudRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-002: WAF Policy
# ============================================================

class TestBicepCafWafPolicy:
    def test_waf_policy_present_pass(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import WafPolicyRule
        rule = WafPolicyRule()
        idx = _parse_bicep(tmp_path,
            "resource waf 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
                 "apiVersion": "2023-05-01", "name": "waf-policy", "location": "eastus",
                 "properties": {}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_waf_policy_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import WafPolicyRule
        rule = WafPolicyRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-003: DDoS Protection
# ============================================================

class TestBicepCafDdosProtection:
    def test_ddos_present_pass(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import DdosProtectionRule
        rule = DdosProtectionRule()
        idx = _parse_bicep(tmp_path,
            "resource ddos 'Microsoft.Network/ddosProtectionPlans@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/ddosProtectionPlans", "apiVersion": "2023-05-01",
                 "name": "ddos-plan", "location": "eastus", "properties": {}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_ddos_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import DdosProtectionRule
        rule = DdosProtectionRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-004: Key expiry
# ============================================================

class TestBicepCafKeyExpiry:
    def test_key_with_expiry_pass(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import KeyExpiryRule
        rule = KeyExpiryRule()
        idx = _parse_bicep(tmp_path,
            "resource key 'Microsoft.KeyVault/vaults/keys@2023-02-01' = {}",
            arm_resources=[
                {"type": "Microsoft.KeyVault/vaults/keys", "apiVersion": "2023-02-01",
                 "name": "mykv/mykey", "location": "eastus",
                 "properties": {"attributes": {"exp": 1735689600}}},
            ])
        keys = idx.get_resources_by_type("azurerm_key_vault_key")
        finding = rule.evaluate(keys[0], idx)
        assert finding.passed is True

    def test_key_without_expiry_fail(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import KeyExpiryRule
        rule = KeyExpiryRule()
        idx = _parse_bicep(tmp_path,
            "resource key 'Microsoft.KeyVault/vaults/keys@2023-02-01' = {}",
            arm_resources=[
                {"type": "Microsoft.KeyVault/vaults/keys", "apiVersion": "2023-02-01",
                 "name": "mykv/mykey", "location": "eastus", "properties": {}},
            ])
        keys = idx.get_resources_by_type("azurerm_key_vault_key")
        finding = rule.evaluate(keys[0], idx)
        assert finding.passed is False


# ============================================================
# CAF Management — CAF-MGT-001: Log Analytics workspace
# ============================================================

class TestBicepCafLogAnalytics:
    def test_workspace_present_pass(self, tmp_path):
        from iac_checker.rules.caf.management import LogAnalyticsWorkspaceRule
        rule = LogAnalyticsWorkspaceRule()
        idx = _parse_bicep(tmp_path,
            "resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {}",
            arm_resources=[
                {"type": "Microsoft.OperationalInsights/workspaces", "apiVersion": "2022-10-01",
                 "name": "law-central", "location": "eastus",
                 "properties": {"sku": {"name": "PerGB2018"}}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_workspace_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.management import LogAnalyticsWorkspaceRule
        rule = LogAnalyticsWorkspaceRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Management — CAF-MGT-002: Activity log export
# ============================================================

class TestBicepCafActivityLogExport:
    def test_activity_log_exported_pass(self, tmp_path):
        from iac_checker.rules.caf.management import ActivityLogExportRule
        rule = ActivityLogExportRule()
        idx = _parse_bicep(tmp_path,
            "resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Insights/diagnosticSettings", "apiVersion": "2021-05-01",
                 "name": "activity-log-export",
                 "properties": {"workspaceId": "/subscriptions/00000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law"}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_activity_log_not_exported_fail(self, tmp_path):
        from iac_checker.rules.caf.management import ActivityLogExportRule
        rule = ActivityLogExportRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Governance — CAF-GOV-001: Policy definitions
# ============================================================

class TestBicepCafPolicyDefinition:
    def test_policy_present_pass(self, tmp_path):
        from iac_checker.rules.caf.governance import PolicyDefinitionRule
        rule = PolicyDefinitionRule()
        idx = _parse_bicep(tmp_path,
            "resource policy 'Microsoft.Authorization/policyAssignments@2022-06-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Authorization/policyAssignments", "apiVersion": "2022-06-01",
                 "name": "enforce-tags", "properties": {"displayName": "Enforce Tags"}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_policy_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.governance import PolicyDefinitionRule
        rule = PolicyDefinitionRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Governance — CAF-GOV-002: Subscription locks
# ============================================================

class TestBicepCafSubscriptionLock:
    def test_lock_present_pass(self, tmp_path):
        from iac_checker.rules.caf.governance import SubscriptionLockRule
        rule = SubscriptionLockRule()
        idx = _parse_bicep(tmp_path,
            "resource lock 'Microsoft.Authorization/locks@2020-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Authorization/locks", "apiVersion": "2020-05-01",
                 "name": "no-delete", "properties": {"level": "CanNotDelete"}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_lock_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.governance import SubscriptionLockRule
        rule = SubscriptionLockRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Networking — CAF-NET-001: VNet peering
# ============================================================

class TestBicepCafVnetPeering:
    def test_peering_present_with_multi_vnet_pass(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetPeeringRule
        rule = VnetPeeringRule()
        idx = _parse_bicep(tmp_path,
            "resource hub 'Microsoft.Network/virtualNetworks@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "hub", "location": "eastus",
                 "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "spoke", "location": "eastus",
                 "properties": {"addressSpace": {"addressPrefixes": ["10.1.0.0/16"]}}},
                {"type": "Microsoft.Network/virtualNetworkPeerings", "apiVersion": "2023-05-01",
                 "name": "hub-to-spoke",
                 "properties": {"remoteVirtualNetwork": {"id": "spoke"}}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_multi_vnet_no_peering_fail(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetPeeringRule
        rule = VnetPeeringRule()
        idx = _parse_bicep(tmp_path,
            "resource hub 'Microsoft.Network/virtualNetworks@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "hub", "location": "eastus",
                 "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "spoke", "location": "eastus",
                 "properties": {"addressSpace": {"addressPrefixes": ["10.1.0.0/16"]}}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False

    def test_single_vnet_pass(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetPeeringRule
        rule = VnetPeeringRule()
        idx = _parse_bicep(tmp_path,
            "resource hub 'Microsoft.Network/virtualNetworks@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "hub", "location": "eastus",
                 "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True


# ============================================================
# CAF Networking — CAF-NET-002: Azure Firewall
# ============================================================

class TestBicepCafAzureFirewall:
    def test_firewall_present_pass(self, tmp_path):
        from iac_checker.rules.caf.networking import AzureFirewallRule
        rule = AzureFirewallRule()
        idx = _parse_bicep(tmp_path,
            "resource fw 'Microsoft.Network/firewalls@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/firewalls", "apiVersion": "2023-05-01",
                 "name": "fw-hub", "location": "eastus",
                 "sku": {"name": "AZFW_VNet", "tier": "Standard"}, "properties": {}},
            ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_firewall_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.networking import AzureFirewallRule
        rule = AzureFirewallRule()
        idx = _parse_bicep(tmp_path, "// empty", arm_resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Networking — CAF-NET-010: VNet DNS config
# ============================================================

class TestBicepCafVnetDnsConfig:
    def test_dns_configured_pass(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetDnsConfigRule
        rule = VnetDnsConfigRule()
        idx = _parse_bicep(tmp_path,
            "resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "vnet1", "location": "eastus",
                 "properties": {
                     "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                     "dhcpOptions": {"dnsServers": ["10.0.0.4", "10.0.0.5"]},
                 }},
            ])
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is True

    def test_dns_not_configured_fail(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetDnsConfigRule
        rule = VnetDnsConfigRule()
        idx = _parse_bicep(tmp_path,
            "resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {}",
            arm_resources=[
                {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
                 "name": "vnet1", "location": "eastus",
                 "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
            ])
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is False
