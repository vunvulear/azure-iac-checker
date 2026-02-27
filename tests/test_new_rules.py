"""Tests for the 24 new WAF and CAF rules — pass and fail scenarios for each."""

import pytest
from iac_checker.models.enums import Severity
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex


def make_resource(resource_type, name="main", attributes=None, block_type="resource"):
    return TerraformResource(
        resource_type=resource_type,
        name=name,
        attributes=attributes or {},
        file_path="main.tf",
        line_number=1,
        block_type=block_type,
    )


def make_index(resources=None, modules=None):
    idx = ResourceIndex()
    idx.resources = resources or []
    idx.modules = modules or []
    return idx


# ============================================================
# WAF Reliability — WAF-REL-005: Multi-region deployment
# ============================================================

class TestMultiRegionDeploymentRule:
    def test_multi_region_pass(self):
        from iac_checker.rules.waf.reliability import MultiRegionDeploymentRule
        rule = MultiRegionDeploymentRule()
        idx = make_index(resources=[
            make_resource("azurerm_resource_group", name="rg1", attributes={"location": "eastus"}),
            make_resource("azurerm_resource_group", name="rg2", attributes={"location": "westus"}),
        ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_single_region_fail(self):
        from iac_checker.rules.waf.reliability import MultiRegionDeploymentRule
        rule = MultiRegionDeploymentRule()
        idx = make_index(resources=[
            make_resource("azurerm_resource_group", name="rg1", attributes={"location": "eastus"}),
            make_resource("azurerm_storage_account", name="st1", attributes={"location": "eastus"}),
        ])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Reliability — WAF-REL-006: Scaling configuration
# ============================================================

class TestScalingConfigRule:
    def test_autoscale_present_pass(self):
        from iac_checker.rules.waf.reliability import ScalingConfigRule
        rule = ScalingConfigRule()
        plan = make_resource("azurerm_service_plan", name="plan1", attributes={"sku_name": "S1"})
        autoscale = make_resource("azurerm_monitor_autoscale_setting", name="as1", attributes={
            "target_resource_id": "azurerm_service_plan.plan1.id"
        })
        idx = make_index(resources=[plan, autoscale])
        finding = rule.evaluate(plan, idx)
        assert finding.passed is True

    def test_autoscale_missing_fail(self):
        from iac_checker.rules.waf.reliability import ScalingConfigRule
        rule = ScalingConfigRule()
        plan = make_resource("azurerm_service_plan", name="plan1", attributes={"sku_name": "S1"})
        idx = make_index(resources=[plan])
        finding = rule.evaluate(plan, idx)
        assert finding.passed is False


# ============================================================
# WAF Reliability — WAF-REL-010: Monitoring alerts
# ============================================================

class TestMonitoringAlertRule:
    def test_alert_present_pass(self):
        from iac_checker.rules.waf.reliability import MonitoringAlertRule
        rule = MonitoringAlertRule()
        alert = make_resource("azurerm_monitor_metric_alert", name="cpu_alert", attributes={})
        idx = make_index(resources=[alert])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_alert_missing_fail(self):
        from iac_checker.rules.waf.reliability import MonitoringAlertRule
        rule = MonitoringAlertRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-004: Network segmentation
# ============================================================

class TestNetworkSegmentationRule:
    def test_vnet_with_subnets_pass(self):
        from iac_checker.rules.waf.security import NetworkSegmentationRule
        rule = NetworkSegmentationRule()
        vnet = make_resource("azurerm_virtual_network", name="vnet1", attributes={
            "subnet": [{"name": "web", "address_prefix": "10.0.1.0/24"}]
        })
        idx = make_index(resources=[vnet])
        finding = rule.evaluate(vnet, idx)
        assert finding.passed is True

    def test_vnet_with_separate_subnets_pass(self):
        from iac_checker.rules.waf.security import NetworkSegmentationRule
        rule = NetworkSegmentationRule()
        vnet = make_resource("azurerm_virtual_network", name="vnet1", attributes={})
        subnet = make_resource("azurerm_subnet", name="web", attributes={
            "virtual_network_name": "azurerm_virtual_network.vnet1.name"
        })
        idx = make_index(resources=[vnet, subnet])
        finding = rule.evaluate(vnet, idx)
        assert finding.passed is True

    def test_vnet_no_subnets_fail(self):
        from iac_checker.rules.waf.security import NetworkSegmentationRule
        rule = NetworkSegmentationRule()
        vnet = make_resource("azurerm_virtual_network", name="vnet1", attributes={})
        idx = make_index(resources=[vnet])
        finding = rule.evaluate(vnet, idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-005: Disable local auth
# ============================================================

class TestDisableLocalAuthRule:
    def test_local_auth_disabled_pass(self):
        from iac_checker.rules.waf.security import DisableLocalAuthRule
        rule = DisableLocalAuthRule()
        resource = make_resource("azurerm_servicebus_namespace", attributes={
            "local_auth_enabled": False
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_local_auth_enabled_fail(self):
        from iac_checker.rules.waf.security import DisableLocalAuthRule
        rule = DisableLocalAuthRule()
        resource = make_resource("azurerm_servicebus_namespace", attributes={
            "local_auth_enabled": True
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_local_auth_missing_fail(self):
        from iac_checker.rules.waf.security import DisableLocalAuthRule
        rule = DisableLocalAuthRule()
        resource = make_resource("azurerm_eventhub_namespace", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-010: Defender for Cloud
# ============================================================

class TestDefenderForCloudRule:
    def test_defender_present_pass(self):
        from iac_checker.rules.waf.security import DefenderForCloudRule
        rule = DefenderForCloudRule()
        defender = make_resource("azurerm_security_center_subscription_pricing", attributes={
            "tier": "Standard", "resource_type": "VirtualMachines"
        })
        idx = make_index(resources=[defender])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_defender_missing_fail(self):
        from iac_checker.rules.waf.security import DefenderForCloudRule
        rule = DefenderForCloudRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Security — WAF-SEC-015: Infrastructure encryption
# ============================================================

class TestInfrastructureEncryptionRule:
    def test_infra_encryption_enabled_pass(self):
        from iac_checker.rules.waf.security import InfrastructureEncryptionRule
        rule = InfrastructureEncryptionRule()
        resource = make_resource("azurerm_storage_account", attributes={
            "infrastructure_encryption_enabled": True
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_infra_encryption_missing_fail(self):
        from iac_checker.rules.waf.security import InfrastructureEncryptionRule
        rule = InfrastructureEncryptionRule()
        resource = make_resource("azurerm_storage_account", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# ============================================================
# WAF Operational — WAF-OPS-006: Module version pinning
# ============================================================

class TestModuleVersionPinningRule:
    def test_pinned_module_pass(self):
        from iac_checker.rules.waf.operational import ModuleVersionPinningRule
        rule = ModuleVersionPinningRule()
        mod = make_resource("module", name="vnet", attributes={
            "source": "Azure/avm-res-network-virtualnetwork/azurerm",
            "version": "0.4.0",
        }, block_type="module")
        idx = make_index(modules=[mod])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_unpinned_module_fail(self):
        from iac_checker.rules.waf.operational import ModuleVersionPinningRule
        rule = ModuleVersionPinningRule()
        mod = make_resource("module", name="vnet", attributes={
            "source": "Azure/avm-res-network-virtualnetwork/azurerm",
        }, block_type="module")
        idx = make_index(modules=[mod])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False

    def test_git_with_ref_pass(self):
        from iac_checker.rules.waf.operational import ModuleVersionPinningRule
        rule = ModuleVersionPinningRule()
        mod = make_resource("module", name="custom", attributes={
            "source": "git::https://github.com/org/mod.git?ref=v1.0.0",
        }, block_type="module")
        idx = make_index(modules=[mod])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True


# ============================================================
# WAF Operational — WAF-OPS-009: Lifecycle blocks
# ============================================================

class TestLifecycleBlockRule:
    def test_lifecycle_prevent_destroy_pass(self):
        from iac_checker.rules.waf.operational import LifecycleBlockRule
        rule = LifecycleBlockRule()
        resource = make_resource("azurerm_key_vault", attributes={
            "lifecycle": {"prevent_destroy": True}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_lifecycle_missing_fail(self):
        from iac_checker.rules.waf.operational import LifecycleBlockRule
        rule = LifecycleBlockRule()
        resource = make_resource("azurerm_key_vault", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# ============================================================
# WAF Operational — WAF-OPS-011: Deployment slots
# ============================================================

class TestDeploymentSlotsRule:
    def test_slot_present_pass(self):
        from iac_checker.rules.waf.operational import DeploymentSlotsRule
        rule = DeploymentSlotsRule()
        app = make_resource("azurerm_linux_web_app", name="myapp", attributes={})
        slot = make_resource("azurerm_linux_web_app_slot", name="staging", attributes={
            "app_service_id": "azurerm_linux_web_app.myapp.id"
        })
        idx = make_index(resources=[app, slot])
        finding = rule.evaluate(app, idx)
        assert finding.passed is True

    def test_slot_missing_fail(self):
        from iac_checker.rules.waf.operational import DeploymentSlotsRule
        rule = DeploymentSlotsRule()
        app = make_resource("azurerm_linux_web_app", name="myapp", attributes={})
        idx = make_index(resources=[app])
        finding = rule.evaluate(app, idx)
        assert finding.passed is False


# ============================================================
# WAF Cost — WAF-COST-004: Budget alerts
# ============================================================

class TestBudgetAlertRule:
    def test_budget_present_pass(self):
        from iac_checker.rules.waf.cost_optimization import BudgetAlertRule
        rule = BudgetAlertRule()
        budget = make_resource("azurerm_consumption_budget_resource_group", attributes={
            "amount": 1000
        })
        idx = make_index(resources=[budget])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_budget_missing_fail(self):
        from iac_checker.rules.waf.cost_optimization import BudgetAlertRule
        rule = BudgetAlertRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# WAF Cost — WAF-COST-005: Reserved instances
# ============================================================

class TestReservedInstancesRule:
    def test_non_prod_vm_pass(self):
        from iac_checker.rules.waf.cost_optimization import ReservedInstancesRule
        rule = ReservedInstancesRule()
        resource = make_resource("azurerm_linux_virtual_machine", attributes={
            "tags": {"env": "dev"}, "size": "Standard_D2s_v3"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_prod_vm_fail(self):
        from iac_checker.rules.waf.cost_optimization import ReservedInstancesRule
        rule = ReservedInstancesRule()
        resource = make_resource("azurerm_linux_virtual_machine", attributes={
            "tags": {"env": "prod"}, "size": "Standard_D4s_v3"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# ============================================================
# WAF Cost — WAF-COST-012: Autoscale validation
# ============================================================

class TestAutoscaleValidationRule:
    def test_valid_autoscale_pass(self):
        from iac_checker.rules.waf.cost_optimization import AutoscaleValidationRule
        rule = AutoscaleValidationRule()
        resource = make_resource("azurerm_monitor_autoscale_setting", attributes={
            "profile": {"capacity": {"minimum": 1, "default": 2, "maximum": 10}}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_invalid_autoscale_fail(self):
        from iac_checker.rules.waf.cost_optimization import AutoscaleValidationRule
        rule = AutoscaleValidationRule()
        resource = make_resource("azurerm_monitor_autoscale_setting", attributes={
            "profile": {"capacity": {"minimum": 10, "default": 5, "maximum": 3}}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# ============================================================
# WAF Performance — WAF-PERF-003: Explicit SKU
# ============================================================

class TestExplicitSkuRule:
    def test_sku_set_pass(self):
        from iac_checker.rules.waf.performance import ExplicitSkuRule
        rule = ExplicitSkuRule()
        resource = make_resource("azurerm_linux_virtual_machine", attributes={
            "size": "Standard_D2s_v3"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_sku_missing_fail(self):
        from iac_checker.rules.waf.performance import ExplicitSkuRule
        rule = ExplicitSkuRule()
        resource = make_resource("azurerm_linux_virtual_machine", attributes={
            "name": "vm1"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# ============================================================
# WAF Performance — WAF-PERF-007: CDN/Caching
# ============================================================

class TestCdnCachingRule:
    def test_cdn_present_pass(self):
        from iac_checker.rules.waf.performance import CdnCachingRule
        rule = CdnCachingRule()
        cdn = make_resource("azurerm_cdn_profile", attributes={"sku": "Standard_Microsoft"})
        idx = make_index(resources=[cdn])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_cdn_missing_fail(self):
        from iac_checker.rules.waf.performance import CdnCachingRule
        rule = CdnCachingRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-001: Defender for Cloud
# ============================================================

class TestCafDefenderForCloudRule:
    def test_defender_present_pass(self):
        from iac_checker.rules.caf.security_baseline import CafDefenderForCloudRule
        rule = CafDefenderForCloudRule()
        defender = make_resource("azurerm_security_center_subscription_pricing", attributes={
            "tier": "Standard"
        })
        idx = make_index(resources=[defender])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_defender_missing_fail(self):
        from iac_checker.rules.caf.security_baseline import CafDefenderForCloudRule
        rule = CafDefenderForCloudRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-002: WAF Policy
# ============================================================

class TestWafPolicyRule:
    def test_waf_policy_present_pass(self):
        from iac_checker.rules.caf.security_baseline import WafPolicyRule
        rule = WafPolicyRule()
        waf = make_resource("azurerm_web_application_firewall_policy", attributes={
            "name": "waf-policy"
        })
        idx = make_index(resources=[waf])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_waf_policy_missing_fail(self):
        from iac_checker.rules.caf.security_baseline import WafPolicyRule
        rule = WafPolicyRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-003: DDoS Protection
# ============================================================

class TestDdosProtectionRule:
    def test_ddos_present_pass(self):
        from iac_checker.rules.caf.security_baseline import DdosProtectionRule
        rule = DdosProtectionRule()
        ddos = make_resource("azurerm_network_ddos_protection_plan", attributes={
            "name": "ddos-plan"
        })
        idx = make_index(resources=[ddos])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_ddos_missing_fail(self):
        from iac_checker.rules.caf.security_baseline import DdosProtectionRule
        rule = DdosProtectionRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Security — CAF-SEC-004: Key expiry
# ============================================================

class TestKeyExpiryRule:
    def test_key_with_expiry_pass(self):
        from iac_checker.rules.caf.security_baseline import KeyExpiryRule
        rule = KeyExpiryRule()
        resource = make_resource("azurerm_key_vault_key", attributes={
            "name": "mykey",
            "expiration_date": "2025-12-31T00:00:00Z"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_key_without_expiry_fail(self):
        from iac_checker.rules.caf.security_baseline import KeyExpiryRule
        rule = KeyExpiryRule()
        resource = make_resource("azurerm_key_vault_key", attributes={
            "name": "mykey"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# ============================================================
# CAF Management — CAF-MGT-001: Log Analytics workspace
# ============================================================

class TestLogAnalyticsWorkspaceRule:
    def test_workspace_present_pass(self):
        from iac_checker.rules.caf.management import LogAnalyticsWorkspaceRule
        rule = LogAnalyticsWorkspaceRule()
        workspace = make_resource("azurerm_log_analytics_workspace", attributes={
            "name": "law-central"
        })
        idx = make_index(resources=[workspace])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_workspace_missing_fail(self):
        from iac_checker.rules.caf.management import LogAnalyticsWorkspaceRule
        rule = LogAnalyticsWorkspaceRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Management — CAF-MGT-002: Activity log export
# ============================================================

class TestActivityLogExportRule:
    def test_activity_log_exported_pass(self):
        from iac_checker.rules.caf.management import ActivityLogExportRule
        rule = ActivityLogExportRule()
        diag = make_resource("azurerm_monitor_diagnostic_setting", attributes={
            "target_resource_id": "/subscriptions/00000000/providers/Microsoft.Insights/diagnosticSettings/activity-logs"
        })
        idx = make_index(resources=[diag])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_activity_log_not_exported_fail(self):
        from iac_checker.rules.caf.management import ActivityLogExportRule
        rule = ActivityLogExportRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Governance — CAF-GOV-001: Policy definitions
# ============================================================

class TestPolicyDefinitionRule:
    def test_policy_present_pass(self):
        from iac_checker.rules.caf.governance import PolicyDefinitionRule
        rule = PolicyDefinitionRule()
        policy = make_resource("azurerm_policy_assignment", attributes={
            "name": "enforce-tags"
        })
        idx = make_index(resources=[policy])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_policy_missing_fail(self):
        from iac_checker.rules.caf.governance import PolicyDefinitionRule
        rule = PolicyDefinitionRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Governance — CAF-GOV-002: Subscription locks
# ============================================================

class TestSubscriptionLockRule:
    def test_lock_present_pass(self):
        from iac_checker.rules.caf.governance import SubscriptionLockRule
        rule = SubscriptionLockRule()
        lock = make_resource("azurerm_management_lock", attributes={
            "lock_level": "CanNotDelete",
            "scope": "/subscriptions/00000000"
        })
        idx = make_index(resources=[lock])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_lock_missing_fail(self):
        from iac_checker.rules.caf.governance import SubscriptionLockRule
        rule = SubscriptionLockRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Networking — CAF-NET-001: VNet peering
# ============================================================

class TestVnetPeeringRule:
    def test_peering_present_with_multi_vnet_pass(self):
        from iac_checker.rules.caf.networking import VnetPeeringRule
        rule = VnetPeeringRule()
        vnet1 = make_resource("azurerm_virtual_network", name="hub", attributes={})
        vnet2 = make_resource("azurerm_virtual_network", name="spoke", attributes={})
        peering = make_resource("azurerm_virtual_network_peering", name="hub-to-spoke", attributes={})
        idx = make_index(resources=[vnet1, vnet2, peering])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_multi_vnet_no_peering_fail(self):
        from iac_checker.rules.caf.networking import VnetPeeringRule
        rule = VnetPeeringRule()
        vnet1 = make_resource("azurerm_virtual_network", name="hub", attributes={})
        vnet2 = make_resource("azurerm_virtual_network", name="spoke", attributes={})
        idx = make_index(resources=[vnet1, vnet2])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False

    def test_single_vnet_pass(self):
        from iac_checker.rules.caf.networking import VnetPeeringRule
        rule = VnetPeeringRule()
        vnet = make_resource("azurerm_virtual_network", name="hub", attributes={})
        idx = make_index(resources=[vnet])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True


# ============================================================
# CAF Networking — CAF-NET-002: Azure Firewall
# ============================================================

class TestAzureFirewallRule:
    def test_firewall_present_pass(self):
        from iac_checker.rules.caf.networking import AzureFirewallRule
        rule = AzureFirewallRule()
        fw = make_resource("azurerm_firewall", attributes={"name": "fw-hub"})
        idx = make_index(resources=[fw])
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_firewall_missing_fail(self):
        from iac_checker.rules.caf.networking import AzureFirewallRule
        rule = AzureFirewallRule()
        idx = make_index(resources=[])
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# ============================================================
# CAF Networking — CAF-NET-010: VNet DNS config
# ============================================================

class TestVnetDnsConfigRule:
    def test_dns_configured_pass(self):
        from iac_checker.rules.caf.networking import VnetDnsConfigRule
        rule = VnetDnsConfigRule()
        resource = make_resource("azurerm_virtual_network", attributes={
            "dns_servers": ["10.0.0.4", "10.0.0.5"]
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_dns_not_configured_fail(self):
        from iac_checker.rules.caf.networking import VnetDnsConfigRule
        rule = VnetDnsConfigRule()
        resource = make_resource("azurerm_virtual_network", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False
