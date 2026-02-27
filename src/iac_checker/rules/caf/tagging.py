"""CAF Tagging Strategy rules — validates 5 foundational tag categories."""

from typing import List, Optional, Set

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule

# Resource types that do NOT support tags in Azure
NON_TAGGABLE_TYPES = {
    "azurerm_subnet",
    "azurerm_subnet_network_security_group_association",
    "azurerm_subnet_route_table_association",
    "azurerm_virtual_network_peering",
    "azurerm_network_interface_security_group_association",
    "azurerm_role_assignment",
    "azurerm_role_definition",
    "azurerm_management_lock",
    "azurerm_monitor_diagnostic_setting",
    "azurerm_private_dns_a_record",
    "azurerm_private_dns_cname_record",
}


class MandatoryTagsRule(BaseRule):
    """CAF-TAG-012: All taggable resources have minimum mandatory tags."""

    rule_id = "CAF-TAG-012"
    description = "All taggable resources have minimum mandatory tags: env, owner, costCenter, app"
    severity = Severity.HIGH
    caf_ref = "Mandatory"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging"
    recommendation = (
        "Add mandatory tags to all taggable resources. Minimum set: env, owner, costCenter, app. "
        "Configure the mandatory set in .iac-checker.yaml."
    )
    applies_to_all = True

    def __init__(self, mandatory_tags: List[str] = None):
        self._mandatory = mandatory_tags or ["env", "owner", "costCenter", "app"]

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if resource.block_type != "resource":
            return None
        if resource.resource_type in NON_TAGGABLE_TYPES:
            return None

        tags = resource.get_attribute("tags")
        if tags is None or not isinstance(tags, dict):
            return self._make_finding(
                resource, passed=False,
                description=f"No tags block defined — missing mandatory tags: {', '.join(self._mandatory)}"
            )

        missing = [t for t in self._mandatory if t not in tags]
        if missing:
            return self._make_finding(
                resource, passed=False,
                description=f"Missing mandatory tags: {', '.join(missing)}"
            )

        return self._make_finding(resource, passed=True)


class TagValueValidationRule(BaseRule):
    """CAF-TAG-009: Tag values follow allowed-value lists."""

    rule_id = "CAF-TAG-009"
    description = "Tag values follow defined allowed-value lists"
    severity = Severity.MEDIUM
    caf_ref = "Validation"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging"
    recommendation = "Ensure env tag uses one of: dev, staging, test, qa, prod."
    applies_to_all = True

    ALLOWED_ENV_VALUES = {"dev", "staging", "test", "qa", "prod", "uat", "sandbox"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if resource.block_type != "resource":
            return None
        if resource.resource_type in NON_TAGGABLE_TYPES:
            return None

        tags = resource.get_attribute("tags")
        if not isinstance(tags, dict):
            return None

        env_value = tags.get("env") or tags.get("environment")
        if env_value and isinstance(env_value, str):
            if "${" not in env_value and "var." not in env_value:
                if env_value.lower() not in self.ALLOWED_ENV_VALUES:
                    return self._make_finding(
                        resource, passed=False,
                        description=f"Tag 'env' has invalid value '{env_value}'. Allowed: {', '.join(sorted(self.ALLOWED_ENV_VALUES))}"
                    )

        return self._make_finding(resource, passed=True)


RULES = [
    MandatoryTagsRule(),
    TagValueValidationRule(),
]
