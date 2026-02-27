"""CAF Identity & Access Governance rules — RBAC and managed identity checks."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class RbacLeastPrivilegeRule(BaseRule):
    """CAF-IAM-001: RBAC assignments use least-privilege."""

    rule_id = "CAF-IAM-001"
    description = "RBAC assignments use least-privilege — no Owner or Contributor at subscription scope"
    severity = Severity.HIGH
    caf_ref = "RBAC"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/identity-access"
    recommendation = (
        "Avoid Owner or Contributor at subscription scope. "
        "Scope RBAC assignments to resource group or resource level where possible."
    )
    resource_types = {"azurerm_role_assignment"}

    OVERLY_PERMISSIVE_ROLES = {
        "Owner",
        "Contributor",
        "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
        "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        role = resource.get_attribute("role_definition_name", "")
        role_id = resource.get_attribute("role_definition_id", "")
        scope = resource.get_attribute("scope", "")

        is_overly_permissive = (
            str(role) in self.OVERLY_PERMISSIVE_ROLES or
            str(role_id) in self.OVERLY_PERMISSIVE_ROLES
        )

        # Only flag if scoped to subscription level (contains /subscriptions/ but not /resourceGroups/)
        is_subscription_scope = (
            "/subscriptions/" in str(scope) and
            "/resourceGroups/" not in str(scope) and
            "/resourcegroups/" not in str(scope).lower()
        )

        if is_overly_permissive and is_subscription_scope:
            return self._make_finding(
                resource, passed=False,
                description=f"Role '{role or role_id}' assigned at subscription scope"
            )

        return self._make_finding(resource, passed=True)


class ManagedIdentityRule(BaseRule):
    """CAF-IAM-004: Managed identities for service-to-service authentication."""

    rule_id = "CAF-IAM-004"
    description = "Managed identities used for service-to-service authentication"
    severity = Severity.HIGH
    caf_ref = "Identity"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/identity-access"
    recommendation = (
        "Add an identity {} block with type = 'SystemAssigned' or 'UserAssigned' "
        "to enable managed identity on the resource."
    )
    resource_types = {
        "azurerm_linux_web_app",
        "azurerm_windows_web_app",
        "azurerm_app_service",
        "azurerm_function_app",
        "azurerm_linux_function_app",
        "azurerm_kubernetes_cluster",
        "azurerm_container_registry",
        "azurerm_logic_app_standard",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        has_identity = resource.has_attribute("identity")
        return self._make_finding(resource, passed=has_identity)


RULES = [
    RbacLeastPrivilegeRule(),
    ManagedIdentityRule(),
]
