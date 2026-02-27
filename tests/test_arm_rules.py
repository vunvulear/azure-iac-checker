"""ARM template rule tests — mirrors test_new_rules.py through the ARM parsing pipeline.

For each of the 24 new rules, this creates ARM JSON templates, parses them through
ArmParser → ResourceIndex, and evaluates the same rules to confirm they work
identically on ARM-sourced resources.

Rules that are Terraform-only concepts (WAF-OPS-006 module pinning, WAF-OPS-009
lifecycle blocks) are tested with ARM-equivalent scenarios where applicable.
"""

import json
import pytest
from pathlib import Path

from iac_checker.parser.arm.arm_parser import ArmParser
from iac_checker.parser.resource_index import ResourceIndex


def _arm_template(resources=None, parameters=None, outputs=None):
    """Build a minimal ARM template dict."""
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": parameters or {},
        "resources": resources or [],
        "outputs": outputs or {},
    }


def _parse_arm(tmp_path, template_dict, filename="main.json"):
    """Write ARM JSON to disk and parse it, returning a ResourceIndex."""
    arm_file = tmp_path / filename
    arm_file.write_text(json.dumps(template_dict), encoding="utf-8")
    parser = ArmParser()
    parsed = parser.parse_file(arm_file)
    assert parsed is not None, f"ARM parse failed for {filename}"
    idx = ResourceIndex()
    idx.build([parsed])
    return idx


# ============================================================
# WAF Reliability — WAF-REL-005: Multi-region deployment
# ============================================================

class TestArmMultiRegionDeployment:
    def test_multi_region_pass(self, tmp_path):
        from iac_checker.rules.waf.reliability import MultiRegionDeploymentRule
        rule = MultiRegionDeploymentRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Resources/resourceGroups", "apiVersion": "2022-09-01",
             "name": "rg1", "location": "eastus", "properties": {}},
            {"type": "Microsoft.Resources/resourceGroups", "apiVersion": "2022-09-01",
             "name": "rg2", "location": "westus", "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_single_region_fail(self, tmp_path):
        from iac_checker.rules.waf.reliability import MultiRegionDeploymentRule
        rule = MultiRegionDeploymentRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Resources/resourceGroups", "apiVersion": "2022-09-01",
             "name": "rg1", "location": "eastus", "properties": {}},
            {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
             "name": "st1", "location": "eastus", "sku": {"name": "Standard_LRS"},
             "kind": "StorageV2", "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Reliability — WAF-REL-006: Scaling configuration
# ============================================================

class TestArmScalingConfig:
    def test_autoscale_present_pass(self, tmp_path):
        from iac_checker.rules.waf.reliability import ScalingConfigRule
        rule = ScalingConfigRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Web/serverfarms", "apiVersion": "2022-09-01",
             "name": "plan1", "location": "eastus",
             "sku": {"name": "S1"}, "properties": {}},
            {"type": "Microsoft.Insights/autoscaleSettings", "apiVersion": "2022-10-01",
             "name": "as1", "location": "eastus",
             "properties": {"targetResourceUri": "azurerm_service_plan.plan1"}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        plans = idx.get_resources_by_type("azurerm_service_plan")
        assert len(plans) == 1
        finding = rule.evaluate(plans[0], idx)
        assert finding.passed is True

    def test_autoscale_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.reliability import ScalingConfigRule
        rule = ScalingConfigRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Web/serverfarms", "apiVersion": "2022-09-01",
             "name": "plan1", "location": "eastus",
             "sku": {"name": "S1"}, "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        plans = idx.get_resources_by_type("azurerm_service_plan")
        finding = rule.evaluate(plans[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Reliability — WAF-REL-010: Monitoring alerts
# ============================================================

class TestArmMonitoringAlert:
    def test_alert_present_pass(self, tmp_path):
        from iac_checker.rules.waf.reliability import MonitoringAlertRule
        rule = MonitoringAlertRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Insights/metricAlerts", "apiVersion": "2018-03-01",
             "name": "cpu-alert", "location": "global",
             "properties": {"severity": 2, "enabled": True}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_alert_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.reliability import MonitoringAlertRule
        rule = MonitoringAlertRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-004: Network segmentation
# ============================================================

class TestArmNetworkSegmentation:
    def test_vnet_with_subnets_pass(self, tmp_path):
        from iac_checker.rules.waf.security import NetworkSegmentationRule
        rule = NetworkSegmentationRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
             "name": "vnet1", "location": "eastus",
             "properties": {
                 "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                 "subnets": [{"name": "web", "properties": {"addressPrefix": "10.0.1.0/24"}}],
             }},
        ])
        idx = _parse_arm(tmp_path, tpl)
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is True

    def test_vnet_with_separate_subnet_pass(self, tmp_path):
        from iac_checker.rules.waf.security import NetworkSegmentationRule
        rule = NetworkSegmentationRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
             "name": "vnet1", "location": "eastus",
             "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
            {"type": "Microsoft.Network/virtualNetworks/subnets", "apiVersion": "2023-05-01",
             "name": "vnet1/web", "location": "eastus",
             "properties": {"addressPrefix": "10.0.1.0/24",
                            "virtualNetworkName": "azurerm_virtual_network.vnet1"}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is True

    def test_vnet_no_subnets_fail(self, tmp_path):
        from iac_checker.rules.waf.security import NetworkSegmentationRule
        rule = NetworkSegmentationRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
             "name": "vnet1", "location": "eastus",
             "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-005: Disable local auth
# ============================================================

class TestArmDisableLocalAuth:
    def test_local_auth_disabled_pass(self, tmp_path):
        from iac_checker.rules.waf.security import DisableLocalAuthRule
        rule = DisableLocalAuthRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.ServiceBus/namespaces", "apiVersion": "2022-10-01",
             "name": "sb1", "location": "eastus", "sku": {"name": "Standard"},
             "properties": {"disableLocalAuth": True}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        sbs = idx.get_resources_by_type("azurerm_servicebus_namespace")
        finding = rule.evaluate(sbs[0], idx)
        assert finding.passed is True

    def test_local_auth_enabled_fail(self, tmp_path):
        from iac_checker.rules.waf.security import DisableLocalAuthRule
        rule = DisableLocalAuthRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.ServiceBus/namespaces", "apiVersion": "2022-10-01",
             "name": "sb1", "location": "eastus", "sku": {"name": "Standard"},
             "properties": {"disableLocalAuth": False}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        sbs = idx.get_resources_by_type("azurerm_servicebus_namespace")
        finding = rule.evaluate(sbs[0], idx)
        assert finding.passed is False

    def test_local_auth_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.security import DisableLocalAuthRule
        rule = DisableLocalAuthRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.EventHub/namespaces", "apiVersion": "2022-10-01",
             "name": "eh1", "location": "eastus", "sku": {"name": "Standard"},
             "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        ehs = idx.get_resources_by_type("azurerm_eventhub_namespace")
        finding = rule.evaluate(ehs[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-010: Defender for Cloud
# ============================================================

class TestArmDefenderForCloud:
    def test_defender_present_pass(self, tmp_path):
        from iac_checker.rules.waf.security import DefenderForCloudRule
        rule = DefenderForCloudRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Security/pricings", "apiVersion": "2022-03-01",
             "name": "VirtualMachines",
             "properties": {"pricingTier": "Standard"}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_defender_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.security import DefenderForCloudRule
        rule = DefenderForCloudRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-015: Infrastructure encryption
# ============================================================

class TestArmInfrastructureEncryption:
    def test_infra_encryption_enabled_pass(self, tmp_path):
        from iac_checker.rules.waf.security import InfrastructureEncryptionRule
        rule = InfrastructureEncryptionRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
             "name": "mystg", "location": "eastus",
             "sku": {"name": "Standard_GRS"}, "kind": "StorageV2",
             "properties": {"encryption": {"requireInfrastructureEncryption": True}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        stg = idx.get_resources_by_type("azurerm_storage_account")
        finding = rule.evaluate(stg[0], idx)
        assert finding.passed is True

    def test_infra_encryption_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.security import InfrastructureEncryptionRule
        rule = InfrastructureEncryptionRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
             "name": "mystg", "location": "eastus",
             "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
             "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        stg = idx.get_resources_by_type("azurerm_storage_account")
        finding = rule.evaluate(stg[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Operational — WAF-OPS-006: Module version pinning (ARM equivalent)
# ARM has no "modules", but linked templates serve a similar purpose.
# We test the global rule with an empty module list → pass (no modules to check).
# ============================================================

class TestArmModuleVersionPinning:
    def test_no_modules_pass(self, tmp_path):
        from iac_checker.rules.waf.operational import ModuleVersionPinningRule
        rule = ModuleVersionPinningRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_arm_with_resources_no_modules_pass(self, tmp_path):
        """ARM templates with resources but no modules should pass module pinning."""
        from iac_checker.rules.waf.operational import ModuleVersionPinningRule
        rule = ModuleVersionPinningRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
             "name": "mystg", "location": "eastus",
             "sku": {"name": "Standard_LRS"}, "kind": "StorageV2", "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_arm_multi_resources_no_modules_pass(self, tmp_path):
        """ARM templates with multiple resources but no modules should pass."""
        from iac_checker.rules.waf.operational import ModuleVersionPinningRule
        rule = ModuleVersionPinningRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
             "name": "stg1", "location": "eastus",
             "sku": {"name": "Standard_LRS"}, "kind": "StorageV2", "properties": {}},
            {"type": "Microsoft.KeyVault/vaults", "apiVersion": "2023-02-01",
             "name": "kv1", "location": "eastus",
             "properties": {"enableRbacAuthorization": True}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True


# ============================================================
# WAF Operational — WAF-OPS-009: Lifecycle blocks (ARM equivalent)
# ARM has no lifecycle blocks. We test the rule evaluates correctly
# when given an ARM resource (no lifecycle → fail for applicable types).
# ============================================================

class TestArmLifecycleBlock:
    def test_lifecycle_present_pass(self, tmp_path):
        """ARM resource with lifecycle metadata injected should pass."""
        from iac_checker.rules.waf.operational import LifecycleBlockRule
        rule = LifecycleBlockRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.KeyVault/vaults", "apiVersion": "2023-02-01",
             "name": "kv1", "location": "eastus",
             "properties": {"enableRbacAuthorization": True,
                            "lifecycle": {"prevent_destroy": True}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        kvs = idx.get_resources_by_type("azurerm_key_vault")
        finding = rule.evaluate(kvs[0], idx)
        assert finding.passed is True

    def test_lifecycle_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.operational import LifecycleBlockRule
        rule = LifecycleBlockRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.KeyVault/vaults", "apiVersion": "2023-02-01",
             "name": "kv1", "location": "eastus",
             "properties": {"enableRbacAuthorization": True}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        kvs = idx.get_resources_by_type("azurerm_key_vault")
        finding = rule.evaluate(kvs[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Operational — WAF-OPS-011: Deployment slots
# ============================================================

class TestArmDeploymentSlots:
    def test_slot_present_pass(self, tmp_path):
        from iac_checker.rules.waf.operational import DeploymentSlotsRule
        rule = DeploymentSlotsRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Web/sites", "apiVersion": "2022-09-01",
             "name": "myapp", "location": "eastus",
             "properties": {"httpsOnly": True}},
            {"type": "Microsoft.Web/sites/slots", "apiVersion": "2022-09-01",
             "name": "myapp/staging", "location": "eastus",
             "properties": {"app_service_id": "azurerm_linux_web_app.myapp.id"}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        apps = idx.get_resources_by_type("azurerm_linux_web_app")
        finding = rule.evaluate(apps[0], idx)
        assert finding.passed is True

    def test_slot_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.operational import DeploymentSlotsRule
        rule = DeploymentSlotsRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Web/sites", "apiVersion": "2022-09-01",
             "name": "myapp", "location": "eastus",
             "properties": {"httpsOnly": True}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        apps = idx.get_resources_by_type("azurerm_linux_web_app")
        finding = rule.evaluate(apps[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Cost — WAF-COST-004: Budget alerts
# ============================================================

class TestArmBudgetAlert:
    def test_budget_present_pass(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import BudgetAlertRule
        rule = BudgetAlertRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Consumption/budgets", "apiVersion": "2023-03-01",
             "name": "monthly-budget",
             "properties": {"amount": 1000, "timeGrain": "Monthly"}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_budget_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import BudgetAlertRule
        rule = BudgetAlertRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Cost — WAF-COST-005: Reserved instances
# ============================================================

class TestArmReservedInstances:
    def test_non_prod_vm_pass(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import ReservedInstancesRule
        rule = ReservedInstancesRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-03-01",
             "name": "vm-dev", "location": "eastus",
             "tags": {"env": "dev"},
             "properties": {"hardwareProfile": {"vmSize": "Standard_D2s_v3"}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        vms = idx.get_resources_by_type("azurerm_linux_virtual_machine")
        finding = rule.evaluate(vms[0], idx)
        assert finding.passed is True

    def test_prod_vm_fail(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import ReservedInstancesRule
        rule = ReservedInstancesRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-03-01",
             "name": "vm-prod", "location": "eastus",
             "tags": {"env": "prod"},
             "properties": {"hardwareProfile": {"vmSize": "Standard_D4s_v3"}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        vms = idx.get_resources_by_type("azurerm_linux_virtual_machine")
        finding = rule.evaluate(vms[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Cost — WAF-COST-012: Autoscale validation
# ============================================================

class TestArmAutoscaleValidation:
    def test_valid_autoscale_pass(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import AutoscaleValidationRule
        rule = AutoscaleValidationRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Insights/autoscaleSettings", "apiVersion": "2022-10-01",
             "name": "as1", "location": "eastus",
             "properties": {
                 "profiles": [{"capacity": {"minimum": 1, "default": 2, "maximum": 10}}],
                 "enabled": True,
             }},
        ])
        idx = _parse_arm(tmp_path, tpl)
        autoscale = idx.get_resources_by_type("azurerm_monitor_autoscale_setting")
        finding = rule.evaluate(autoscale[0], idx)
        assert finding.passed is True

    def test_invalid_autoscale_fail(self, tmp_path):
        from iac_checker.rules.waf.cost_optimization import AutoscaleValidationRule
        rule = AutoscaleValidationRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Insights/autoscaleSettings", "apiVersion": "2022-10-01",
             "name": "as1", "location": "eastus",
             "properties": {
                 "profiles": [{"capacity": {"minimum": 10, "default": 5, "maximum": 3}}],
                 "enabled": True,
             }},
        ])
        idx = _parse_arm(tmp_path, tpl)
        autoscale = idx.get_resources_by_type("azurerm_monitor_autoscale_setting")
        finding = rule.evaluate(autoscale[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Performance — WAF-PERF-003: Explicit SKU
# ============================================================

class TestArmExplicitSku:
    def test_sku_set_pass(self, tmp_path):
        from iac_checker.rules.waf.performance import ExplicitSkuRule
        rule = ExplicitSkuRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-03-01",
             "name": "vm1", "location": "eastus",
             "properties": {"hardwareProfile": {"vmSize": "Standard_D2s_v3"}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        vms = idx.get_resources_by_type("azurerm_linux_virtual_machine")
        finding = rule.evaluate(vms[0], idx)
        assert finding.passed is True

    def test_sku_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.performance import ExplicitSkuRule
        rule = ExplicitSkuRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-03-01",
             "name": "vm1", "location": "eastus",
             "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        vms = idx.get_resources_by_type("azurerm_linux_virtual_machine")
        finding = rule.evaluate(vms[0], idx)
        assert finding.passed is False


# ============================================================
# WAF Performance — WAF-PERF-007: CDN/Caching
# ============================================================

class TestArmCdnCaching:
    def test_cdn_present_pass(self, tmp_path):
        from iac_checker.rules.waf.performance import CdnCachingRule
        rule = CdnCachingRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Cdn/profiles", "apiVersion": "2023-05-01",
             "name": "cdn1", "location": "global",
             "sku": {"name": "Standard_Microsoft"}, "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_cdn_missing_fail(self, tmp_path):
        from iac_checker.rules.waf.performance import CdnCachingRule
        rule = CdnCachingRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-001: Defender for Cloud
# ============================================================

class TestArmCafDefenderForCloud:
    def test_defender_present_pass(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import CafDefenderForCloudRule
        rule = CafDefenderForCloudRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Security/pricings", "apiVersion": "2022-03-01",
             "name": "VirtualMachines",
             "properties": {"pricingTier": "Standard"}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_defender_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import CafDefenderForCloudRule
        rule = CafDefenderForCloudRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-002: WAF Policy
# ============================================================

class TestArmCafWafPolicy:
    def test_waf_policy_present_pass(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import WafPolicyRule
        rule = WafPolicyRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
             "apiVersion": "2023-05-01", "name": "waf-policy", "location": "eastus",
             "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_waf_policy_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import WafPolicyRule
        rule = WafPolicyRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-003: DDoS Protection
# ============================================================

class TestArmCafDdosProtection:
    def test_ddos_present_pass(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import DdosProtectionRule
        rule = DdosProtectionRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/ddosProtectionPlans", "apiVersion": "2023-05-01",
             "name": "ddos-plan", "location": "eastus", "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_ddos_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import DdosProtectionRule
        rule = DdosProtectionRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-004: Key expiry
# ============================================================

class TestArmCafKeyExpiry:
    def test_key_with_expiry_pass(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import KeyExpiryRule
        rule = KeyExpiryRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.KeyVault/vaults/keys", "apiVersion": "2023-02-01",
             "name": "mykv/mykey", "location": "eastus",
             "properties": {"attributes": {"exp": 1735689600}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        keys = idx.get_resources_by_type("azurerm_key_vault_key")
        finding = rule.evaluate(keys[0], idx)
        assert finding.passed is True

    def test_key_without_expiry_fail(self, tmp_path):
        from iac_checker.rules.caf.security_baseline import KeyExpiryRule
        rule = KeyExpiryRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.KeyVault/vaults/keys", "apiVersion": "2023-02-01",
             "name": "mykv/mykey", "location": "eastus",
             "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        keys = idx.get_resources_by_type("azurerm_key_vault_key")
        finding = rule.evaluate(keys[0], idx)
        assert finding.passed is False


# ============================================================
# CAF Management — CAF-MGT-001: Log Analytics workspace
# ============================================================

class TestArmCafLogAnalytics:
    def test_workspace_present_pass(self, tmp_path):
        from iac_checker.rules.caf.management import LogAnalyticsWorkspaceRule
        rule = LogAnalyticsWorkspaceRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.OperationalInsights/workspaces", "apiVersion": "2022-10-01",
             "name": "law-central", "location": "eastus",
             "properties": {"sku": {"name": "PerGB2018"}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_workspace_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.management import LogAnalyticsWorkspaceRule
        rule = LogAnalyticsWorkspaceRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Management — CAF-MGT-002: Activity log export
# ============================================================

class TestArmCafActivityLogExport:
    def test_activity_log_exported_pass(self, tmp_path):
        from iac_checker.rules.caf.management import ActivityLogExportRule
        rule = ActivityLogExportRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Insights/diagnosticSettings", "apiVersion": "2021-05-01",
             "name": "activity-log-export",
             "properties": {
                 "workspaceId": "/subscriptions/00000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law",
             }},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_activity_log_not_exported_fail(self, tmp_path):
        from iac_checker.rules.caf.management import ActivityLogExportRule
        rule = ActivityLogExportRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Governance — CAF-GOV-001: Policy definitions
# ============================================================

class TestArmCafPolicyDefinition:
    def test_policy_present_pass(self, tmp_path):
        from iac_checker.rules.caf.governance import PolicyDefinitionRule
        rule = PolicyDefinitionRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Authorization/policyAssignments", "apiVersion": "2022-06-01",
             "name": "enforce-tags",
             "properties": {"displayName": "Enforce Tags"}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_policy_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.governance import PolicyDefinitionRule
        rule = PolicyDefinitionRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Governance — CAF-GOV-002: Subscription locks
# ============================================================

class TestArmCafSubscriptionLock:
    def test_lock_present_pass(self, tmp_path):
        from iac_checker.rules.caf.governance import SubscriptionLockRule
        rule = SubscriptionLockRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Authorization/locks", "apiVersion": "2020-05-01",
             "name": "no-delete",
             "properties": {"level": "CanNotDelete"}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_lock_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.governance import SubscriptionLockRule
        rule = SubscriptionLockRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Networking — CAF-NET-001: VNet peering
# ============================================================

class TestArmCafVnetPeering:
    def test_peering_present_with_multi_vnet_pass(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetPeeringRule
        rule = VnetPeeringRule()
        tpl = _arm_template(resources=[
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
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_multi_vnet_no_peering_fail(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetPeeringRule
        rule = VnetPeeringRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
             "name": "hub", "location": "eastus",
             "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
            {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
             "name": "spoke", "location": "eastus",
             "properties": {"addressSpace": {"addressPrefixes": ["10.1.0.0/16"]}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False

    def test_single_vnet_pass(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetPeeringRule
        rule = VnetPeeringRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
             "name": "hub", "location": "eastus",
             "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True


# ============================================================
# CAF Networking — CAF-NET-002: Azure Firewall
# ============================================================

class TestArmCafAzureFirewall:
    def test_firewall_present_pass(self, tmp_path):
        from iac_checker.rules.caf.networking import AzureFirewallRule
        rule = AzureFirewallRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/firewalls", "apiVersion": "2023-05-01",
             "name": "fw-hub", "location": "eastus",
             "sku": {"name": "AZFW_VNet", "tier": "Standard"},
             "properties": {}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_firewall_missing_fail(self, tmp_path):
        from iac_checker.rules.caf.networking import AzureFirewallRule
        rule = AzureFirewallRule()
        tpl = _arm_template(resources=[])
        idx = _parse_arm(tmp_path, tpl)
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Networking — CAF-NET-010: VNet DNS config
# ============================================================

class TestArmCafVnetDnsConfig:
    def test_dns_configured_pass(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetDnsConfigRule
        rule = VnetDnsConfigRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
             "name": "vnet1", "location": "eastus",
             "properties": {
                 "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                 "dhcpOptions": {"dnsServers": ["10.0.0.4", "10.0.0.5"]},
             }},
        ])
        idx = _parse_arm(tmp_path, tpl)
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is True

    def test_dns_not_configured_fail(self, tmp_path):
        from iac_checker.rules.caf.networking import VnetDnsConfigRule
        rule = VnetDnsConfigRule()
        tpl = _arm_template(resources=[
            {"type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01",
             "name": "vnet1", "location": "eastus",
             "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}},
        ])
        idx = _parse_arm(tmp_path, tpl)
        vnets = idx.get_resources_by_type("azurerm_virtual_network")
        finding = rule.evaluate(vnets[0], idx)
        assert finding.passed is False
