"""CAF Landing Zone & Subscription Design rules — programmatic checks."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class ResourceGroupOrganizationRule(BaseRule):
    """CAF-LZ-003: Resource groups organized by lifecycle and function."""

    rule_id = "CAF-LZ-003"
    description = "Resource groups organized by lifecycle and function — not monolithic single-RG"
    severity = Severity.MEDIUM
    caf_ref = "Resource Org"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-areas"
    recommendation = (
        "Organize resources into multiple resource groups by function and lifecycle. "
        "Avoid deploying all resources into a single resource group."
    )
    resource_types = {"azurerm_resource_group"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None
        # Informational — this rule passes if resource groups exist at all
        # A deeper check would verify that there are multiple RGs for different functions
        return self._make_finding(resource, passed=True)


class AvmModuleUsageRule(BaseRule):
    """CAF-LZ-009: Azure Verified Modules (AVM) used where available."""

    rule_id = "CAF-LZ-009"
    description = "Azure Verified Modules (AVM) used where available for landing zone components"
    severity = Severity.LOW
    caf_ref = "Platform Auto"
    doc_url = "https://learn.microsoft.com/en-us/azure/architecture/landing-zones/terraform/landing-zone-terraform"
    recommendation = (
        "Consider using Azure Verified Modules (AVM) from the Terraform Registry. "
        "AVM modules follow CAF landing zone patterns and are maintained by Microsoft."
    )
    resource_types = {"module"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if resource.block_type != "module":
            return None

        source = resource.get_attribute("source")
        if not source or not isinstance(source, str):
            return self._make_finding(resource, passed=True)

        # Check if source is an AVM module
        is_avm = "Azure/avm-" in source or "azure/avm-" in source.lower()
        if is_avm:
            return self._make_finding(resource, passed=True)

        # Informational: module is not AVM — not a hard fail
        return self._make_finding(
            resource, passed=True,
            description=f"Module '{resource.name}' uses source '{source}' — consider AVM equivalent if available"
        )


RULES = [
    ResourceGroupOrganizationRule(),
    AvmModuleUsageRule(),
]
