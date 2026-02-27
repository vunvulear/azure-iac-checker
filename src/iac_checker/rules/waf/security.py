"""WAF Security rules (SE:01–SE:12) — programmatic rules that go beyond YAML checks."""

from typing import List, Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule
from iac_checker.utils.secret_detector import SecretDetector


class PrivateEndpointRule(BaseRule):
    """WAF-SEC-008: Private endpoints used for PaaS services."""

    rule_id = "WAF-SEC-008"
    description = "Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR)"
    severity = Severity.HIGH
    waf_ref = "SE:06"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/security/networking"
    recommendation = (
        "Create azurerm_private_endpoint resources for PaaS services. "
        "Disable public network access where possible."
    )
    resource_types = {
        "azurerm_storage_account",
        "azurerm_mssql_server",
        "azurerm_key_vault",
        "azurerm_container_registry",
        "azurerm_cosmosdb_account",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        # Check if there's a private_endpoint resource referencing this resource
        has_private_endpoint = any(
            pe for pe in index.get_resources_by_type("azurerm_private_endpoint")
            if resource.name in str(pe.attributes)
        )

        # Also check public_network_access_enabled attribute
        public_access = resource.get_attribute("public_network_access_enabled")
        public_disabled = public_access is False or str(public_access).lower() == "false"

        return self._make_finding(resource, passed=(has_private_endpoint or public_disabled))


class HardcodedSecretRule(BaseRule):
    """WAF-SEC-019: No hardcoded secrets in .tf or .tfvars files."""

    rule_id = "WAF-SEC-019"
    description = "No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars"
    severity = Severity.CRITICAL
    waf_ref = "SE:09"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/security/application-secrets"
    recommendation = (
        "Use Azure Key Vault references, sensitive variables, or environment variables. "
        "Never store secrets in Terraform files."
    )
    applies_to_all = True

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        # This rule is special — it scans raw file lines, not parsed resources.
        # The engine should call this via a separate code path using SecretDetector.
        # For per-resource checks, look for password-like attributes with literal values.
        secret_attrs = [
            "admin_password", "administrator_login_password", "password",
            "client_secret", "secret", "shared_key", "access_key",
            "primary_access_key", "secondary_access_key", "connection_string",
        ]

        for attr in secret_attrs:
            value = resource.get_attribute(attr)
            if value and isinstance(value, str) and not value.startswith("${") and not value.startswith("var."):
                return self._make_finding(
                    resource,
                    passed=False,
                    description=f"Hardcoded secret found in attribute '{attr}'"
                )

        return self._make_finding(resource, passed=True)


class KeyVaultConfigRule(BaseRule):
    """WAF-SEC-014: Key Vault with RBAC, soft-delete, and purge protection."""

    rule_id = "WAF-SEC-014"
    description = "Key Vault configured with RBAC authorization, soft-delete, and purge protection"
    severity = Severity.HIGH
    waf_ref = "SE:07"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/security/encryption"
    recommendation = (
        "Set enable_rbac_authorization = true, soft_delete_retention_days >= 7, "
        "and purge_protection_enabled = true on Key Vault."
    )
    resource_types = {"azurerm_key_vault"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        rbac = resource.get_attribute("enable_rbac_authorization")
        purge = resource.get_attribute("purge_protection_enabled")

        rbac_ok = rbac is True or str(rbac).lower() == "true"
        purge_ok = purge is True or str(purge).lower() == "true"

        return self._make_finding(resource, passed=(rbac_ok and purge_ok))


class NetworkSegmentationRule(BaseRule):
    """WAF-SEC-004: Network segmentation — VNets use subnets for isolation."""

    rule_id = "WAF-SEC-004"
    description = "Network segmentation — virtual networks use subnets for workload isolation"
    severity = Severity.HIGH
    waf_ref = "SE:04"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/security/segmentation"
    recommendation = (
        "Segment virtual networks into subnets by function or tier. "
        "Apply NSGs to each subnet for micro-segmentation."
    )
    resource_types = {"azurerm_virtual_network"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        subnet = resource.get_attribute("subnet")
        has_subnets = bool(subnet) if isinstance(subnet, (list, dict)) else False
        # Also check for separate azurerm_subnet resources referencing this VNet
        vnet_ref = f"{resource.resource_type}.{resource.name}"
        has_separate_subnets = any(
            s for s in index.get_resources_by_type("azurerm_subnet")
            if vnet_ref in str(s.attributes)
        )
        return self._make_finding(resource, passed=(has_subnets or has_separate_subnets))


class DisableLocalAuthRule(BaseRule):
    """WAF-SEC-005: Disable local authentication on resources that support it."""

    rule_id = "WAF-SEC-005"
    description = "Local authentication disabled — use Azure AD/Entra ID for authentication"
    severity = Severity.HIGH
    waf_ref = "SE:05"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/security/identity-access"
    recommendation = (
        "Set local_auth_enabled = false on Service Bus, Event Hub, Cognitive Services, "
        "and other resources that support Azure AD authentication."
    )
    resource_types = {
        "azurerm_servicebus_namespace",
        "azurerm_eventhub_namespace",
        "azurerm_cognitive_account",
        "azurerm_search_service",
        "azurerm_signalr_service",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        local_auth = resource.get_attribute("local_auth_enabled")
        disabled = local_auth is False or str(local_auth).lower() == "false"
        return self._make_finding(resource, passed=disabled)


class DefenderForCloudRule(BaseRule):
    """WAF-SEC-010: Microsoft Defender for Cloud enabled."""

    rule_id = "WAF-SEC-010"
    description = "Microsoft Defender for Cloud enabled for threat detection and security monitoring"
    severity = Severity.HIGH
    waf_ref = "SE:10"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/security/monitor-threats"
    recommendation = (
        "Deploy azurerm_security_center_subscription_pricing to enable "
        "Microsoft Defender for Cloud on your subscription."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        """Check if Defender for Cloud is configured."""
        has_defender = bool(
            index.get_resources_by_type("azurerm_security_center_subscription_pricing")
            or index.get_resources_by_type("azurerm_security_center_setting")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="security",
            resource_name="defender_for_cloud",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            waf_ref=self.waf_ref,
            passed=has_defender,
        )


class InfrastructureEncryptionRule(BaseRule):
    """WAF-SEC-015: Storage account infrastructure encryption enabled."""

    rule_id = "WAF-SEC-015"
    description = "Infrastructure encryption enabled on storage accounts for double encryption"
    severity = Severity.MEDIUM
    waf_ref = "SE:08"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/security/encryption"
    recommendation = (
        "Set infrastructure_encryption_enabled = true on storage accounts "
        "for an additional layer of encryption with platform-managed keys."
    )
    resource_types = {"azurerm_storage_account"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        infra_enc = resource.get_attribute("infrastructure_encryption_enabled")
        enabled = infra_enc is True or str(infra_enc).lower() == "true"
        return self._make_finding(resource, passed=enabled)


RULES = [
    PrivateEndpointRule(),
    HardcodedSecretRule(),
    KeyVaultConfigRule(),
    NetworkSegmentationRule(),
    DisableLocalAuthRule(),
    DefenderForCloudRule(),
    InfrastructureEncryptionRule(),
]
