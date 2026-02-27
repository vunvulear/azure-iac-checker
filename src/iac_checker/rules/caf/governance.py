"""CAF Governance & Policy rules — Azure Policy and resource lock checks."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class ResourceLockRule(BaseRule):
    """CAF-GOV-013: Resource locks on critical production resources."""

    rule_id = "CAF-GOV-013"
    description = "Resource locks defined on critical production resources"
    severity = Severity.MEDIUM
    caf_ref = "RM01"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/govern/document-cloud-governance-policies"
    recommendation = (
        "Add azurerm_management_lock with lock_level = 'CanNotDelete' on production "
        "databases, key vaults, and hub networking resources."
    )
    resource_types = {
        "azurerm_key_vault",
        "azurerm_mssql_server",
        "azurerm_mssql_database",
        "azurerm_cosmosdb_account",
        "azurerm_virtual_network",  # hub VNet
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        # Check if there's a management lock referencing this resource
        resource_ref = f"{resource.resource_type}.{resource.name}"
        has_lock = any(
            lock for lock in index.get_resources_by_type("azurerm_management_lock")
            if resource_ref in str(lock.attributes)
        )

        return self._make_finding(resource, passed=has_lock)


class DataResidencyRule(BaseRule):
    """CAF-GOV-012: Data residency — resources restricted to approved regions."""

    rule_id = "CAF-GOV-012"
    description = "Data residency — Azure Policy restricts resource deployment to approved regions"
    severity = Severity.HIGH
    caf_ref = "DG02"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/govern/document-cloud-governance-policies"
    recommendation = (
        "Define an Azure Policy assignment (azurerm_policy_assignment) that restricts "
        "resource deployment to approved Azure regions using the 'Allowed locations' built-in policy."
    )
    resource_types = set()  # Global rule — checks for policy existence

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        # This is a global check — not per-resource
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        """Check if an allowed-locations policy assignment exists."""
        policy_assignments = index.get_resources_by_type("azurerm_policy_assignment")
        has_location_policy = any(
            pa for pa in policy_assignments
            if "location" in str(pa.attributes).lower()
            or "allowedLocations" in str(pa.attributes)
        )

        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="governance",
            resource_name="data_residency_policy",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            caf_ref=self.caf_ref,
            passed=has_location_policy,
        )


class PolicyDefinitionRule(BaseRule):
    """CAF-GOV-001: Azure Policy definitions deployed for governance."""

    rule_id = "CAF-GOV-001"
    description = "Azure Policy definitions or policy sets deployed for governance enforcement"
    severity = Severity.MEDIUM
    caf_ref = "DG01"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/govern/document-cloud-governance-policies"
    recommendation = (
        "Deploy azurerm_policy_definition or azurerm_policy_set_definition resources "
        "to codify and enforce organizational governance standards."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        has_policy = bool(
            index.get_resources_by_type("azurerm_policy_definition")
            or index.get_resources_by_type("azurerm_policy_set_definition")
            or index.get_resources_by_type("azurerm_policy_assignment")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="governance",
            resource_name="policy_definitions",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            caf_ref=self.caf_ref,
            passed=has_policy,
        )


class SubscriptionLockRule(BaseRule):
    """CAF-GOV-002: Subscription-level resource locks for critical infrastructure."""

    rule_id = "CAF-GOV-002"
    description = "Subscription-level or resource group-level locks protect critical infrastructure"
    severity = Severity.MEDIUM
    caf_ref = "RM02"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/govern/document-cloud-governance-policies"
    recommendation = (
        "Deploy azurerm_management_lock at the subscription or resource group level "
        "to prevent accidental deletion of critical infrastructure."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        locks = index.get_resources_by_type("azurerm_management_lock")
        has_broad_lock = any(
            lock for lock in locks
            if "subscription" in str(lock.attributes).lower()
            or "resource_group" in str(lock.attributes).lower()
            or lock.get_attribute("lock_level") in ("CanNotDelete", "ReadOnly")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="governance",
            resource_name="subscription_locks",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            caf_ref=self.caf_ref,
            passed=has_broad_lock,
        )


RULES = [
    ResourceLockRule(),
    DataResidencyRule(),
    PolicyDefinitionRule(),
    SubscriptionLockRule(),
]
