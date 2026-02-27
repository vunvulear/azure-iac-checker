"""CAF Naming Convention rules — programmatic rules using NamingValidator."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule
from iac_checker.utils.naming_validator import NamingValidator, CAF_ABBREVIATIONS


class NamingConventionRule(BaseRule):
    """CAF-NAME-001: Resource names follow CAF naming convention."""

    rule_id = "CAF-NAME-001"
    description = "Resource names follow CAF naming convention"
    severity = Severity.HIGH
    caf_ref = "Naming"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming"
    recommendation = (
        "Follow the pattern: <abbreviation>-<workload>-<env>-<region>-<instance>. "
        "See https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations"
    )
    applies_to_all = True

    def __init__(self):
        self._validator = NamingValidator()

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if resource.block_type != "resource":
            return None
        if resource.resource_type not in CAF_ABBREVIATIONS:
            return None

        # In Terraform, the resource "name" in HCL is the local name, not the Azure name.
        # The actual Azure name is usually in the "name" attribute.
        azure_name = resource.get_attribute("name")
        if not azure_name or not isinstance(azure_name, str):
            return None

        # Skip dynamic names (contain interpolation)
        if "${" in azure_name or "var." in azure_name:
            return self._make_finding(resource, passed=True)

        is_valid, error = self._validator.validate_name(resource.resource_type, azure_name)
        if not is_valid:
            return self._make_finding(
                resource, passed=False,
                description=f"Naming violation for '{azure_name}': {error}"
            )
        return self._make_finding(resource, passed=True)


class NamingRestrictionsRule(BaseRule):
    """CAF-NAME-004: Names within Azure character limits and allowed character sets."""

    rule_id = "CAF-NAME-004"
    description = "Names within Azure character limits and allowed character sets"
    severity = Severity.HIGH
    caf_ref = "Naming"
    doc_url = "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules"
    recommendation = "Check Azure naming rules per resource type for allowed characters and length limits."
    applies_to_all = True

    def __init__(self):
        self._validator = NamingValidator()

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if resource.block_type != "resource":
            return None

        azure_name = resource.get_attribute("name")
        if not azure_name or not isinstance(azure_name, str):
            return None
        if "${" in azure_name or "var." in azure_name:
            return None

        is_valid, error = self._validator.validate_name(resource.resource_type, azure_name)
        if not is_valid and "Azure restrictions" in (error or ""):
            return self._make_finding(
                resource, passed=False,
                description=f"Azure naming restriction violated for '{azure_name}': {error}"
            )
        return self._make_finding(resource, passed=True)


RULES = [
    NamingConventionRule(),
    NamingRestrictionsRule(),
]
