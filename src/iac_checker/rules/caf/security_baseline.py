"""CAF Security Baseline rules — programmatic rules for cloud security posture."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class CafDefenderForCloudRule(BaseRule):
    """CAF-SEC-001: Microsoft Defender for Cloud enabled on subscriptions."""

    rule_id = "CAF-SEC-001"
    description = "Microsoft Defender for Cloud enabled on subscriptions for security posture management"
    severity = Severity.HIGH
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/security"
    recommendation = (
        "Deploy azurerm_security_center_subscription_pricing for each resource type "
        "(VirtualMachines, SqlServers, AppServices, StorageAccounts, KeyVaults, etc.)."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
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
            resource_type="security_baseline",
            resource_name="defender_for_cloud",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            passed=has_defender,
        )


class WafPolicyRule(BaseRule):
    """CAF-SEC-002: Web Application Firewall deployed on internet-facing endpoints."""

    rule_id = "CAF-SEC-002"
    description = "Web Application Firewall (WAF) policy deployed on internet-facing endpoints"
    severity = Severity.HIGH
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/security"
    recommendation = (
        "Deploy azurerm_web_application_firewall_policy and associate it with "
        "Application Gateway or Front Door for internet-facing workloads."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        has_waf = bool(
            index.get_resources_by_type("azurerm_web_application_firewall_policy")
            or index.get_resources_by_type("azurerm_cdn_frontdoor_firewall_policy")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="security_baseline",
            resource_name="waf_policy",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            passed=has_waf,
        )


class DdosProtectionRule(BaseRule):
    """CAF-SEC-003: DDoS Protection Plan for VNets with public endpoints."""

    rule_id = "CAF-SEC-003"
    description = "DDoS Protection Plan configured for virtual networks with public endpoints"
    severity = Severity.HIGH
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/security"
    recommendation = (
        "Deploy azurerm_network_ddos_protection_plan and associate it with "
        "virtual networks that host public-facing workloads."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        has_ddos = bool(
            index.get_resources_by_type("azurerm_network_ddos_protection_plan")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="security_baseline",
            resource_name="ddos_protection",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            passed=has_ddos,
        )


class KeyExpiryRule(BaseRule):
    """CAF-SEC-004: Key Vault keys have expiration dates configured."""

    rule_id = "CAF-SEC-004"
    description = "Key Vault keys have expiration dates configured for key rotation compliance"
    severity = Severity.MEDIUM
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/security"
    recommendation = (
        "Set expiration_date on all azurerm_key_vault_key resources to enforce "
        "automatic key rotation policies."
    )
    resource_types = {"azurerm_key_vault_key"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        expiry = resource.get_attribute("expiration_date")
        has_expiry = expiry is not None and str(expiry).strip() != ""
        return self._make_finding(resource, passed=has_expiry)


RULES = [
    CafDefenderForCloudRule(),
    WafPolicyRule(),
    DdosProtectionRule(),
    KeyExpiryRule(),
]
