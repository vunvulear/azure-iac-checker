"""Tests for rule evaluation — WAF and CAF rules against sample resources."""

import pytest
from iac_checker.models.enums import Severity
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import YamlDrivenRule


def make_resource(resource_type, name="main", attributes=None, block_type="resource"):
    return TerraformResource(
        resource_type=resource_type,
        name=name,
        attributes=attributes or {},
        file_path="main.tf",
        line_number=1,
        block_type=block_type,
    )


def make_index(resources=None):
    idx = ResourceIndex()
    idx.resources = resources or []
    return idx


# === YamlDrivenRule Tests ===

class TestYamlDrivenRule:
    def test_equals_operator_pass(self):
        rule = YamlDrivenRule({
            "id": "TEST-001",
            "description": "TLS check",
            "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "min_tls_version", "operator": "equals", "value": "TLS1_2"},
        })
        resource = make_resource("azurerm_storage_account", attributes={"min_tls_version": "TLS1_2"})
        finding = rule.evaluate(resource, make_index())
        assert finding is not None
        assert finding.passed is True

    def test_equals_operator_fail(self):
        rule = YamlDrivenRule({
            "id": "TEST-001",
            "description": "TLS check",
            "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "min_tls_version", "operator": "equals", "value": "TLS1_2"},
        })
        resource = make_resource("azurerm_storage_account", attributes={"min_tls_version": "TLS1_0"})
        finding = rule.evaluate(resource, make_index())
        assert finding is not None
        assert finding.passed is False

    def test_absent_is_violation(self):
        rule = YamlDrivenRule({
            "id": "TEST-002",
            "description": "TLS required",
            "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "min_tls_version", "operator": "equals", "value": "TLS1_2", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding is not None
        assert finding.passed is False

    def test_bool_true_operator(self):
        rule = YamlDrivenRule({
            "id": "TEST-003",
            "description": "HTTPS only",
            "severity": "High",
            "resource_types": ["azurerm_app_service"],
            "check": {"attribute": "https_only", "operator": "bool_true"},
        })
        resource = make_resource("azurerm_app_service", attributes={"https_only": True})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_bool_true_operator_string(self):
        rule = YamlDrivenRule({
            "id": "TEST-003",
            "description": "HTTPS only",
            "severity": "High",
            "resource_types": ["azurerm_app_service"],
            "check": {"attribute": "https_only", "operator": "bool_true"},
        })
        resource = make_resource("azurerm_app_service", attributes={"https_only": "true"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_bool_false_operator(self):
        rule = YamlDrivenRule({
            "id": "TEST-004",
            "description": "No public blobs",
            "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "allow_nested_items_to_be_public", "operator": "bool_false"},
        })
        resource = make_resource("azurerm_storage_account", attributes={"allow_nested_items_to_be_public": False})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_exists_operator(self):
        rule = YamlDrivenRule({
            "id": "TEST-005",
            "description": "Identity exists",
            "severity": "High",
            "resource_types": ["azurerm_linux_web_app"],
            "check": {"attribute": "identity", "operator": "exists"},
        })
        resource = make_resource("azurerm_linux_web_app", attributes={"identity": {"type": "SystemAssigned"}})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_not_applies_to_wrong_type(self):
        rule = YamlDrivenRule({
            "id": "TEST-006",
            "description": "Storage only",
            "severity": "Medium",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "min_tls_version", "operator": "equals", "value": "TLS1_2"},
        })
        resource = make_resource("azurerm_key_vault", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding is None

    def test_contains_operator(self):
        rule = YamlDrivenRule({
            "id": "TEST-007",
            "description": "Contains check",
            "severity": "Low",
            "resource_types": ["azurerm_resource_group"],
            "check": {"attribute": "name", "operator": "contains", "value": "prod"},
        })
        resource = make_resource("azurerm_resource_group", attributes={"name": "rg-myapp-prod-eastus2"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_not_equals_operator(self):
        rule = YamlDrivenRule({
            "id": "TEST-008",
            "description": "Not Premium",
            "severity": "Medium",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "account_tier", "operator": "not_equals", "value": "Premium"},
        })
        resource = make_resource("azurerm_storage_account", attributes={"account_tier": "Standard"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_not_in_operator_pass(self):
        rule = YamlDrivenRule({
            "id": "TEST-009",
            "description": "No Free/Basic SKU",
            "severity": "High",
            "resource_types": ["azurerm_service_plan"],
            "check": {"attribute": "sku_name", "operator": "not_in", "value": ["F1", "B1", "Free"]},
        })
        resource = make_resource("azurerm_service_plan", attributes={"sku_name": "S1"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_not_in_operator_fail(self):
        rule = YamlDrivenRule({
            "id": "TEST-009",
            "description": "No Free/Basic SKU",
            "severity": "High",
            "resource_types": ["azurerm_service_plan"],
            "check": {"attribute": "sku_name", "operator": "not_in", "value": ["F1", "B1", "Free"]},
        })
        resource = make_resource("azurerm_service_plan", attributes={"sku_name": "F1"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_in_operator_with_list(self):
        rule = YamlDrivenRule({
            "id": "TEST-010",
            "description": "Env must be valid",
            "severity": "Medium",
            "resource_types": ["azurerm_resource_group"],
            "check": {"attribute": "tags.env", "operator": "in", "value": ["dev", "prod", "staging"]},
        })
        resource = make_resource("azurerm_resource_group", attributes={"tags": {"env": "prod"}})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_empty_resource_types_applies_to_all(self):
        """YAML rules with empty resource_types should apply to ALL resource types."""
        rule = YamlDrivenRule({
            "id": "TEST-011",
            "description": "costCenter tag required",
            "severity": "Medium",
            "resource_types": [],
            "check": {"attribute": "tags.costCenter", "operator": "exists"},
        })
        assert rule.applies_to_all is True
        resource = make_resource("azurerm_key_vault", attributes={"tags": {"costCenter": "CC-123"}})
        finding = rule.evaluate(resource, make_index())
        assert finding is not None
        assert finding.passed is True

    def test_specific_resource_types_not_applies_to_all(self):
        rule = YamlDrivenRule({
            "id": "TEST-012",
            "description": "TLS check",
            "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "min_tls_version", "operator": "equals", "value": "TLS1_2"},
        })
        assert rule.applies_to_all is False
        # Should not match a different resource type
        resource = make_resource("azurerm_key_vault", attributes={"min_tls_version": "TLS1_2"})
        finding = rule.evaluate(resource, make_index())
        assert finding is None


# === Programmatic Rule Tests ===

class TestReliabilityRules:
    def test_availability_zone_pass(self):
        from iac_checker.rules.waf.reliability import AvailabilityZoneRule
        rule = AvailabilityZoneRule()
        resource = make_resource("azurerm_linux_virtual_machine", attributes={"zone": "1"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_availability_zone_fail(self):
        from iac_checker.rules.waf.reliability import AvailabilityZoneRule
        rule = AvailabilityZoneRule()
        resource = make_resource("azurerm_linux_virtual_machine", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_disaster_recovery_grs_pass(self):
        from iac_checker.rules.waf.reliability import DisasterRecoveryRule
        rule = DisasterRecoveryRule()
        resource = make_resource("azurerm_storage_account", attributes={"account_replication_type": "GRS"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_disaster_recovery_lrs_fail(self):
        from iac_checker.rules.waf.reliability import DisasterRecoveryRule
        rule = DisasterRecoveryRule()
        resource = make_resource("azurerm_storage_account", attributes={"account_replication_type": "LRS"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


class TestSecurityRules:
    def test_hardcoded_secret_detected(self):
        from iac_checker.rules.waf.security import HardcodedSecretRule
        rule = HardcodedSecretRule()
        resource = make_resource("azurerm_mssql_server", attributes={
            "administrator_login_password": "P@ssw0rd123!"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False
        assert finding.severity == Severity.CRITICAL

    def test_hardcoded_secret_variable_ref_pass(self):
        from iac_checker.rules.waf.security import HardcodedSecretRule
        rule = HardcodedSecretRule()
        resource = make_resource("azurerm_mssql_server", attributes={
            "administrator_login_password": "var.db_password"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_key_vault_config_pass(self):
        from iac_checker.rules.waf.security import KeyVaultConfigRule
        rule = KeyVaultConfigRule()
        resource = make_resource("azurerm_key_vault", attributes={
            "enable_rbac_authorization": True,
            "purge_protection_enabled": True,
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_key_vault_config_fail_no_purge(self):
        from iac_checker.rules.waf.security import KeyVaultConfigRule
        rule = KeyVaultConfigRule()
        resource = make_resource("azurerm_key_vault", attributes={
            "enable_rbac_authorization": True,
            "purge_protection_enabled": False,
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


class TestNetworkingRules:
    def test_nsg_wildcard_allow_all_fail(self):
        from iac_checker.rules.caf.networking import NsgWildcardRule
        rule = NsgWildcardRule()
        resource = make_resource("azurerm_network_security_rule", attributes={
            "access": "Allow",
            "source_address_prefix": "*",
            "destination_address_prefix": "*",
            "source_port_range": "*",
            "destination_port_range": "*",
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_nsg_deny_rule_with_wildcard_pass(self):
        from iac_checker.rules.caf.networking import NsgWildcardRule
        rule = NsgWildcardRule()
        resource = make_resource("azurerm_network_security_rule", attributes={
            "access": "Deny",
            "source_address_prefix": "*",
            "destination_address_prefix": "*",
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_nsg_specific_cidr_pass(self):
        from iac_checker.rules.caf.networking import NsgWildcardRule
        rule = NsgWildcardRule()
        resource = make_resource("azurerm_network_security_rule", attributes={
            "access": "Allow",
            "source_address_prefix": "10.0.0.0/24",
            "destination_address_prefix": "10.1.0.0/24",
            "source_port_range": "*",
            "destination_port_range": "443",
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True


class TestTaggingRules:
    def test_mandatory_tags_pass(self):
        from iac_checker.rules.caf.tagging import MandatoryTagsRule
        rule = MandatoryTagsRule()
        resource = make_resource("azurerm_resource_group", attributes={
            "tags": {"env": "prod", "owner": "team-a", "costCenter": "CC-123", "app": "myapp"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_mandatory_tags_missing(self):
        from iac_checker.rules.caf.tagging import MandatoryTagsRule
        rule = MandatoryTagsRule()
        resource = make_resource("azurerm_resource_group", attributes={
            "tags": {"env": "prod"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False
        assert "Missing mandatory tags" in finding.description

    def test_no_tags_block_fails(self):
        from iac_checker.rules.caf.tagging import MandatoryTagsRule
        rule = MandatoryTagsRule()
        resource = make_resource("azurerm_resource_group", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_non_taggable_resource_skipped(self):
        from iac_checker.rules.caf.tagging import MandatoryTagsRule
        rule = MandatoryTagsRule()
        resource = make_resource("azurerm_subnet", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding is None

    def test_tag_value_validation_invalid_env(self):
        from iac_checker.rules.caf.tagging import TagValueValidationRule
        rule = TagValueValidationRule()
        resource = make_resource("azurerm_resource_group", attributes={
            "tags": {"env": "production"}  # should be "prod"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_tag_value_validation_valid_env(self):
        from iac_checker.rules.caf.tagging import TagValueValidationRule
        rule = TagValueValidationRule()
        resource = make_resource("azurerm_resource_group", attributes={
            "tags": {"env": "prod"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True


class TestIdentityRules:
    def test_rbac_owner_at_subscription_fail(self):
        from iac_checker.rules.caf.identity import RbacLeastPrivilegeRule
        rule = RbacLeastPrivilegeRule()
        resource = make_resource("azurerm_role_assignment", attributes={
            "role_definition_name": "Owner",
            "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_rbac_owner_at_rg_pass(self):
        from iac_checker.rules.caf.identity import RbacLeastPrivilegeRule
        rule = RbacLeastPrivilegeRule()
        resource = make_resource("azurerm_role_assignment", attributes={
            "role_definition_name": "Owner",
            "scope": "/subscriptions/00000000/resourceGroups/rg-myapp",
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_rbac_reader_at_subscription_pass(self):
        from iac_checker.rules.caf.identity import RbacLeastPrivilegeRule
        rule = RbacLeastPrivilegeRule()
        resource = make_resource("azurerm_role_assignment", attributes={
            "role_definition_name": "Reader",
            "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_managed_identity_pass(self):
        from iac_checker.rules.caf.identity import ManagedIdentityRule
        rule = ManagedIdentityRule()
        resource = make_resource("azurerm_linux_web_app", attributes={
            "identity": {"type": "SystemAssigned"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_managed_identity_missing_fail(self):
        from iac_checker.rules.caf.identity import ManagedIdentityRule
        rule = ManagedIdentityRule()
        resource = make_resource("azurerm_linux_web_app", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# === WAF Reliability — BackupPolicyRule ===

class TestBackupPolicyRule:
    def test_backup_policy_with_ltr_pass(self):
        from iac_checker.rules.waf.reliability import BackupPolicyRule
        rule = BackupPolicyRule()
        resource = make_resource("azurerm_mssql_database", attributes={
            "long_term_retention_policy": {"weekly_retention": "P1W"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_backup_policy_with_str_pass(self):
        from iac_checker.rules.waf.reliability import BackupPolicyRule
        rule = BackupPolicyRule()
        resource = make_resource("azurerm_mssql_database", attributes={
            "short_term_retention_policy": {"retention_days": 7}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_backup_policy_missing_fail(self):
        from iac_checker.rules.waf.reliability import BackupPolicyRule
        rule = BackupPolicyRule()
        resource = make_resource("azurerm_mssql_database", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# === WAF Security — PrivateEndpointRule ===

class TestPrivateEndpointRule:
    def test_private_endpoint_exists_pass(self):
        from iac_checker.rules.waf.security import PrivateEndpointRule
        rule = PrivateEndpointRule()
        storage = make_resource("azurerm_storage_account", name="mystorage", attributes={})
        pe = make_resource("azurerm_private_endpoint", name="pe_storage", attributes={
            "private_service_connection": {"subresource_names": ["blob"]},
            "target_resource_id": "azurerm_storage_account.mystorage.id",
        })
        idx = make_index(resources=[storage, pe])
        finding = rule.evaluate(storage, idx)
        assert finding.passed is True

    def test_private_endpoint_public_disabled_pass(self):
        from iac_checker.rules.waf.security import PrivateEndpointRule
        rule = PrivateEndpointRule()
        resource = make_resource("azurerm_storage_account", attributes={
            "public_network_access_enabled": False
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_private_endpoint_missing_fail(self):
        from iac_checker.rules.waf.security import PrivateEndpointRule
        rule = PrivateEndpointRule()
        resource = make_resource("azurerm_storage_account", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# === WAF Operational — RemoteBackendRule (global) ===

class TestRemoteBackendRule:
    def test_remote_backend_present_pass(self):
        from iac_checker.rules.waf.operational import RemoteBackendRule
        rule = RemoteBackendRule()
        idx = ResourceIndex()
        idx.backend = [{"azurerm": {"storage_account_name": "tfstate"}}]
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_remote_backend_missing_fail(self):
        from iac_checker.rules.waf.operational import RemoteBackendRule
        rule = RemoteBackendRule()
        idx = ResourceIndex()
        idx.backend = []
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# === WAF Operational — ProvisionerRule ===

class TestProvisionerRule:
    def test_provisioner_absent_pass(self):
        from iac_checker.rules.waf.operational import ProvisionerRule
        rule = ProvisionerRule()
        resource = make_resource("azurerm_linux_virtual_machine", attributes={
            "name": "vm-prod-01", "size": "Standard_D2s_v3"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding is None  # returns None when no provisioner (skip pass)

    def test_provisioner_present_fail(self):
        from iac_checker.rules.waf.operational import ProvisionerRule
        rule = ProvisionerRule()
        resource = make_resource("azurerm_linux_virtual_machine", attributes={
            "provisioner": {"local-exec": {"command": "echo hello"}}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding is not None
        assert finding.passed is False


# === WAF Operational — DiagnosticSettingsRule ===

class TestDiagnosticSettingsRule:
    def test_diagnostic_settings_present_pass(self):
        from iac_checker.rules.waf.operational import DiagnosticSettingsRule
        rule = DiagnosticSettingsRule()
        kv = make_resource("azurerm_key_vault", name="mykv", attributes={})
        diag = make_resource("azurerm_monitor_diagnostic_setting", name="kv_diag", attributes={
            "target_resource_id": "azurerm_key_vault.mykv.id"
        })
        idx = make_index(resources=[kv, diag])
        finding = rule.evaluate(kv, idx)
        assert finding.passed is True

    def test_diagnostic_settings_missing_fail(self):
        from iac_checker.rules.waf.operational import DiagnosticSettingsRule
        rule = DiagnosticSettingsRule()
        kv = make_resource("azurerm_key_vault", name="mykv", attributes={})
        idx = make_index(resources=[kv])
        finding = rule.evaluate(kv, idx)
        assert finding.passed is False


# === WAF Cost — IdleResourceRule ===

class TestIdleResourceRule:
    def test_referenced_public_ip_pass(self):
        from iac_checker.rules.waf.cost_optimization import IdleResourceRule
        rule = IdleResourceRule()
        pip = make_resource("azurerm_public_ip", name="pip1", attributes={})
        lb = make_resource("azurerm_lb", name="lb1", attributes={
            "frontend_ip_configuration": {"public_ip_address_id": "azurerm_public_ip.pip1.id"}
        })
        idx = make_index(resources=[pip, lb])
        finding = rule.evaluate(pip, idx)
        assert finding.passed is True

    def test_unreferenced_public_ip_fail(self):
        from iac_checker.rules.waf.cost_optimization import IdleResourceRule
        rule = IdleResourceRule()
        pip = make_resource("azurerm_public_ip", name="pip_orphan", attributes={})
        idx = make_index(resources=[pip])
        finding = rule.evaluate(pip, idx)
        assert finding.passed is False


# === WAF Performance — StoragePerformanceTierRule ===

class TestStoragePerformanceTierRule:
    def test_tier_set_pass(self):
        from iac_checker.rules.waf.performance import StoragePerformanceTierRule
        rule = StoragePerformanceTierRule()
        resource = make_resource("azurerm_storage_account", attributes={"account_tier": "Standard"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_tier_missing_fail(self):
        from iac_checker.rules.waf.performance import StoragePerformanceTierRule
        rule = StoragePerformanceTierRule()
        resource = make_resource("azurerm_storage_account", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# === WAF Service Guides — AksNodePoolZonesRule ===

class TestAksNodePoolZonesRule:
    def test_aks_zones_set_pass(self):
        from iac_checker.rules.waf.service_guides import AksNodePoolZonesRule
        rule = AksNodePoolZonesRule()
        resource = make_resource("azurerm_kubernetes_cluster", attributes={
            "default_node_pool": {"name": "default", "zones": ["1", "2", "3"]}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_aks_zones_missing_fail(self):
        from iac_checker.rules.waf.service_guides import AksNodePoolZonesRule
        rule = AksNodePoolZonesRule()
        resource = make_resource("azurerm_kubernetes_cluster", attributes={
            "default_node_pool": {"name": "default", "vm_size": "Standard_D2s_v3"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# === WAF Service Guides — SqlPrivateEndpointRule ===

class TestSqlPrivateEndpointRule:
    def test_sql_public_access_disabled_pass(self):
        from iac_checker.rules.waf.service_guides import SqlPrivateEndpointRule
        rule = SqlPrivateEndpointRule()
        resource = make_resource("azurerm_mssql_server", attributes={
            "public_network_access_enabled": False
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_sql_public_access_enabled_fail(self):
        from iac_checker.rules.waf.service_guides import SqlPrivateEndpointRule
        rule = SqlPrivateEndpointRule()
        resource = make_resource("azurerm_mssql_server", attributes={
            "public_network_access_enabled": True
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# === CAF Networking — SubnetNsgRule ===

class TestSubnetNsgRule:
    def test_subnet_with_nsg_association_pass(self):
        from iac_checker.rules.caf.networking import SubnetNsgRule
        rule = SubnetNsgRule()
        subnet = make_resource("azurerm_subnet", name="app_subnet", attributes={"name": "app"})
        assoc = make_resource("azurerm_subnet_network_security_group_association", name="app_nsg", attributes={
            "subnet_id": "azurerm_subnet.app_subnet.id"
        })
        idx = make_index(resources=[subnet, assoc])
        finding = rule.evaluate(subnet, idx)
        assert finding.passed is True

    def test_subnet_without_nsg_fail(self):
        from iac_checker.rules.caf.networking import SubnetNsgRule
        rule = SubnetNsgRule()
        subnet = make_resource("azurerm_subnet", name="app_subnet", attributes={"name": "app"})
        idx = make_index(resources=[subnet])
        finding = rule.evaluate(subnet, idx)
        assert finding.passed is False

    def test_gateway_subnet_exempt_pass(self):
        from iac_checker.rules.caf.networking import SubnetNsgRule
        rule = SubnetNsgRule()
        subnet = make_resource("azurerm_subnet", name="gw", attributes={"name": "GatewaySubnet"})
        idx = make_index(resources=[subnet])
        finding = rule.evaluate(subnet, idx)
        assert finding.passed is True


# === CAF Networking — PrivateEndpointDnsRule ===

class TestPrivateEndpointDnsRule:
    def test_dns_zone_group_present_pass(self):
        from iac_checker.rules.caf.networking import PrivateEndpointDnsRule
        rule = PrivateEndpointDnsRule()
        resource = make_resource("azurerm_private_endpoint", attributes={
            "private_dns_zone_group": {"name": "default", "private_dns_zone_ids": ["zone1"]}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_dns_zone_group_missing_fail(self):
        from iac_checker.rules.caf.networking import PrivateEndpointDnsRule
        rule = PrivateEndpointDnsRule()
        resource = make_resource("azurerm_private_endpoint", attributes={
            "private_service_connection": {"name": "psc"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


# === CAF Naming — NamingConventionRule ===

class TestNamingConventionRule:
    def test_valid_naming_pass(self):
        from iac_checker.rules.caf.naming import NamingConventionRule
        rule = NamingConventionRule()
        resource = make_resource("azurerm_resource_group", attributes={
            "name": "rg-myapp-prod-eastus2"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding is not None
        assert finding.passed is True

    def test_invalid_naming_fail(self):
        from iac_checker.rules.caf.naming import NamingConventionRule
        rule = NamingConventionRule()
        resource = make_resource("azurerm_resource_group", attributes={
            "name": "my-bad-name"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding is not None
        assert finding.passed is False

    def test_dynamic_name_skipped_pass(self):
        from iac_checker.rules.caf.naming import NamingConventionRule
        rule = NamingConventionRule()
        resource = make_resource("azurerm_resource_group", attributes={
            "name": "${var.prefix}-rg"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding is not None
        assert finding.passed is True


# === CAF Naming — NamingRestrictionsRule ===

class TestNamingRestrictionsRule:
    def test_valid_name_pass(self):
        from iac_checker.rules.caf.naming import NamingRestrictionsRule
        rule = NamingRestrictionsRule()
        resource = make_resource("azurerm_storage_account", attributes={
            "name": "stmyappprod01"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding is not None
        assert finding.passed is True

    def test_name_too_long_fail(self):
        from iac_checker.rules.caf.naming import NamingRestrictionsRule
        rule = NamingRestrictionsRule()
        # Storage accounts max 24 chars, lowercase alphanumeric only
        resource = make_resource("azurerm_storage_account", attributes={
            "name": "a" * 25
        })
        finding = rule.evaluate(resource, make_index())
        # Should detect the Azure restriction violation
        assert finding is not None


# === CAF Landing Zone — ResourceGroupOrganizationRule ===

class TestResourceGroupOrganizationRule:
    def test_resource_group_exists_pass(self):
        from iac_checker.rules.caf.landing_zone import ResourceGroupOrganizationRule
        rule = ResourceGroupOrganizationRule()
        resource = make_resource("azurerm_resource_group", attributes={
            "name": "rg-myapp-prod", "location": "eastus2"
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_non_matching_type_skipped(self):
        from iac_checker.rules.caf.landing_zone import ResourceGroupOrganizationRule
        rule = ResourceGroupOrganizationRule()
        resource = make_resource("azurerm_storage_account", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding is None


# === CAF Landing Zone — AvmModuleUsageRule ===

class TestAvmModuleUsageRule:
    def test_avm_module_pass(self):
        from iac_checker.rules.caf.landing_zone import AvmModuleUsageRule
        rule = AvmModuleUsageRule()
        resource = make_resource("module", name="vnet", attributes={
            "source": "Azure/avm-res-network-virtualnetwork/azurerm"
        }, block_type="module")
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_non_avm_module_informational_pass(self):
        from iac_checker.rules.caf.landing_zone import AvmModuleUsageRule
        rule = AvmModuleUsageRule()
        resource = make_resource("module", name="custom", attributes={
            "source": "git::https://github.com/myorg/my-module.git"
        }, block_type="module")
        finding = rule.evaluate(resource, make_index())
        # Non-AVM is informational, not a hard fail
        assert finding.passed is True


# === CAF Governance — ResourceLockRule ===

class TestResourceLockRule:
    def test_resource_lock_present_pass(self):
        from iac_checker.rules.caf.governance import ResourceLockRule
        rule = ResourceLockRule()
        kv = make_resource("azurerm_key_vault", name="mykv", attributes={})
        lock = make_resource("azurerm_management_lock", name="kv_lock", attributes={
            "scope": "azurerm_key_vault.mykv.id",
            "lock_level": "CanNotDelete",
        })
        idx = make_index(resources=[kv, lock])
        finding = rule.evaluate(kv, idx)
        assert finding.passed is True

    def test_resource_lock_missing_fail(self):
        from iac_checker.rules.caf.governance import ResourceLockRule
        rule = ResourceLockRule()
        kv = make_resource("azurerm_key_vault", name="mykv", attributes={})
        idx = make_index(resources=[kv])
        finding = rule.evaluate(kv, idx)
        assert finding.passed is False


# === CAF Governance — DataResidencyRule (global) ===

class TestDataResidencyRule:
    def test_location_policy_present_pass(self):
        from iac_checker.rules.caf.governance import DataResidencyRule
        rule = DataResidencyRule()
        idx = ResourceIndex()
        policy = make_resource("azurerm_policy_assignment", name="allowed_locations", attributes={
            "policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c",
            "parameters": {"allowedLocations": {"value": ["eastus", "eastus2"]}}
        })
        idx.resources = [policy]
        finding = rule.evaluate_global(idx)
        assert finding.passed is True

    def test_location_policy_absent_fail(self):
        from iac_checker.rules.caf.governance import DataResidencyRule
        rule = DataResidencyRule()
        idx = ResourceIndex()
        idx.resources = []
        finding = rule.evaluate_global(idx)
        assert finding.passed is False


# === YAML-Driven Rule Tests (per actual YAML definitions) ===

class TestYamlRulesReliability:
    """Test YAML rules from waf_reliability.yaml."""

    def test_waf_rel_003_managed_disk_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-REL-003", "description": "Managed disks", "severity": "Medium",
            "resource_types": ["azurerm_virtual_machine"],
            "check": {"attribute": "storage_os_disk.managed_disk_type", "operator": "exists", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_virtual_machine", attributes={
            "storage_os_disk": {"managed_disk_type": "Premium_LRS"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_rel_003_managed_disk_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-REL-003", "description": "Managed disks", "severity": "Medium",
            "resource_types": ["azurerm_virtual_machine"],
            "check": {"attribute": "storage_os_disk.managed_disk_type", "operator": "exists", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_virtual_machine", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_rel_009_soft_delete_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-REL-009", "description": "Soft-delete", "severity": "High",
            "resource_types": ["azurerm_key_vault"],
            "check": {"attribute": "purge_protection_enabled", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_key_vault", attributes={"purge_protection_enabled": True})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_rel_009_soft_delete_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-REL-009", "description": "Soft-delete", "severity": "High",
            "resource_types": ["azurerm_key_vault"],
            "check": {"attribute": "purge_protection_enabled", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_key_vault", attributes={"purge_protection_enabled": False})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_rel_012_sla_sku_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-REL-012", "description": "SLA SKU", "severity": "High",
            "resource_types": ["azurerm_service_plan"],
            "check": {"attribute": "sku_name", "operator": "not_in",
                      "value": ["F1", "D1", "B1", "B2", "B3", "Free", "Basic"],
                      "absent_is_violation": False},
        })
        resource = make_resource("azurerm_service_plan", attributes={"sku_name": "S1"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_rel_012_sla_sku_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-REL-012", "description": "SLA SKU", "severity": "High",
            "resource_types": ["azurerm_service_plan"],
            "check": {"attribute": "sku_name", "operator": "not_in",
                      "value": ["F1", "D1", "B1", "B2", "B3", "Free", "Basic"],
                      "absent_is_violation": False},
        })
        resource = make_resource("azurerm_service_plan", attributes={"sku_name": "F1"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


class TestYamlRulesSecurity:
    """Test YAML rules from waf_security.yaml."""

    def test_waf_sec_012_tls_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-SEC-012", "description": "TLS 1.2", "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "min_tls_version", "operator": "equals", "value": "TLS1_2", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={"min_tls_version": "TLS1_2"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_sec_012_tls_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-SEC-012", "description": "TLS 1.2", "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "min_tls_version", "operator": "equals", "value": "TLS1_2", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={"min_tls_version": "TLS1_0"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_sec_013_https_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-SEC-013", "description": "HTTPS", "severity": "High",
            "resource_types": ["azurerm_linux_web_app"],
            "check": {"attribute": "https_only", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_linux_web_app", attributes={"https_only": True})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_sec_013_https_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-SEC-013", "description": "HTTPS", "severity": "High",
            "resource_types": ["azurerm_linux_web_app"],
            "check": {"attribute": "https_only", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_linux_web_app", attributes={"https_only": False})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_sec_016_no_public_blob_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-SEC-016", "description": "No public blobs", "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "allow_nested_items_to_be_public", "operator": "bool_false", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={"allow_nested_items_to_be_public": False})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_sec_016_no_public_blob_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-SEC-016", "description": "No public blobs", "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "allow_nested_items_to_be_public", "operator": "bool_false", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={"allow_nested_items_to_be_public": True})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_sec_017_https_only_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-SEC-017", "description": "HTTPS only", "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "enable_https_traffic_only", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={"enable_https_traffic_only": True})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_sec_017_https_only_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-SEC-017", "description": "HTTPS only", "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "enable_https_traffic_only", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={"enable_https_traffic_only": False})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


class TestYamlRulesCost:
    """Test YAML rules from waf_cost.yaml."""

    def test_waf_cost_001_tag_present_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-COST-001", "description": "Cost tags", "severity": "Medium",
            "resource_types": [],
            "check": {"attribute": "tags.costCenter", "operator": "exists", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={
            "tags": {"costCenter": "CC-123"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_cost_001_tag_missing_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-COST-001", "description": "Cost tags", "severity": "Medium",
            "resource_types": [],
            "check": {"attribute": "tags.costCenter", "operator": "exists", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={"tags": {"env": "prod"}})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_cost_007_not_premium_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-COST-007", "description": "No Premium for dev", "severity": "Medium",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "account_tier", "operator": "not_equals", "value": "Premium", "absent_is_violation": False},
        })
        resource = make_resource("azurerm_storage_account", attributes={"account_tier": "Standard"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_cost_007_premium_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-COST-007", "description": "No Premium for dev", "severity": "Medium",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "account_tier", "operator": "not_equals", "value": "Premium", "absent_is_violation": False},
        })
        resource = make_resource("azurerm_storage_account", attributes={"account_tier": "Premium"})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


class TestYamlRulesPerformance:
    """Test YAML rules from waf_performance.yaml."""

    def test_waf_perf_009_accelerated_networking_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-PERF-009", "description": "Accelerated Networking", "severity": "Low",
            "resource_types": ["azurerm_network_interface"],
            "check": {"attribute": "enable_accelerated_networking", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_network_interface", attributes={"enable_accelerated_networking": True})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_perf_009_accelerated_networking_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-PERF-009", "description": "Accelerated Networking", "severity": "Low",
            "resource_types": ["azurerm_network_interface"],
            "check": {"attribute": "enable_accelerated_networking", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_network_interface", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_perf_005_autoscale_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-PERF-005", "description": "Autoscale", "severity": "High",
            "resource_types": ["azurerm_monitor_autoscale_setting"],
            "check": {"attribute": "profile", "operator": "exists", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_monitor_autoscale_setting", attributes={
            "profile": {"name": "default", "capacity": {"minimum": 1, "maximum": 10, "default": 1}}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_perf_005_autoscale_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-PERF-005", "description": "Autoscale", "severity": "High",
            "resource_types": ["azurerm_monitor_autoscale_setting"],
            "check": {"attribute": "profile", "operator": "exists", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_monitor_autoscale_setting", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False


class TestYamlRulesServiceGuides:
    """Test YAML rules from waf_service_guides.yaml."""

    def test_waf_svc_002_aks_private_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-SVC-002", "description": "AKS private", "severity": "High",
            "resource_types": ["azurerm_kubernetes_cluster"],
            "check": {"attribute": "private_cluster_enabled", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_kubernetes_cluster", attributes={"private_cluster_enabled": True})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_svc_002_aks_private_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-SVC-002", "description": "AKS private", "severity": "High",
            "resource_types": ["azurerm_kubernetes_cluster"],
            "check": {"attribute": "private_cluster_enabled", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_kubernetes_cluster", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_svc_005_app_service_https_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-SVC-005", "description": "App Service HTTPS", "severity": "High",
            "resource_types": ["azurerm_linux_web_app"],
            "check": {"attribute": "https_only", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_linux_web_app", attributes={"https_only": True})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_svc_005_app_service_https_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-SVC-005", "description": "App Service HTTPS", "severity": "High",
            "resource_types": ["azurerm_linux_web_app"],
            "check": {"attribute": "https_only", "operator": "bool_true", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_linux_web_app", attributes={})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_svc_010_storage_firewall_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-SVC-010", "description": "Storage firewall", "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "network_rules.default_action", "operator": "equals", "value": "Deny", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={
            "network_rules": {"default_action": "Deny"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_svc_010_storage_firewall_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-SVC-010", "description": "Storage firewall", "severity": "High",
            "resource_types": ["azurerm_storage_account"],
            "check": {"attribute": "network_rules.default_action", "operator": "equals", "value": "Deny", "absent_is_violation": True},
        })
        resource = make_resource("azurerm_storage_account", attributes={
            "network_rules": {"default_action": "Allow"}
        })
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False

    def test_waf_svc_007_sql_tde_pass(self):
        rule = YamlDrivenRule({
            "id": "WAF-SVC-007", "description": "SQL TDE", "severity": "High",
            "resource_types": ["azurerm_mssql_database"],
            "check": {"attribute": "transparent_data_encryption_enabled", "operator": "bool_true", "absent_is_violation": False},
        })
        resource = make_resource("azurerm_mssql_database", attributes={"transparent_data_encryption_enabled": True})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is True

    def test_waf_svc_007_sql_tde_fail(self):
        rule = YamlDrivenRule({
            "id": "WAF-SVC-007", "description": "SQL TDE", "severity": "High",
            "resource_types": ["azurerm_mssql_database"],
            "check": {"attribute": "transparent_data_encryption_enabled", "operator": "bool_true", "absent_is_violation": False},
        })
        resource = make_resource("azurerm_mssql_database", attributes={"transparent_data_encryption_enabled": False})
        finding = rule.evaluate(resource, make_index())
        assert finding.passed is False
