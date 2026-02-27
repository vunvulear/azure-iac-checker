"""WAF Service Guide rules — per-service best practices (programmatic)."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class AksNodePoolZonesRule(BaseRule):
    """WAF-SVC-003: AKS node pools spread across Availability Zones."""

    rule_id = "WAF-SVC-003"
    description = "AKS node pools spread across Availability Zones"
    severity = Severity.HIGH
    waf_ref = "RE:05"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-kubernetes-service"
    recommendation = (
        "Set availability_zones or zones on default_node_pool and additional node pools."
    )
    resource_types = {"azurerm_kubernetes_cluster"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        default_pool = resource.get_attribute("default_node_pool")
        if isinstance(default_pool, dict):
            zones = default_pool.get("zones") or default_pool.get("availability_zones")
        elif isinstance(default_pool, list) and default_pool:
            pool = default_pool[0] if isinstance(default_pool[0], dict) else {}
            zones = pool.get("zones") or pool.get("availability_zones")
        else:
            zones = None

        return self._make_finding(resource, passed=bool(zones))


class SqlPrivateEndpointRule(BaseRule):
    """WAF-SVC-009: SQL Database with private endpoint — no public access for production."""

    rule_id = "WAF-SVC-009"
    description = "SQL Database configured with private endpoint — no public access for production"
    severity = Severity.HIGH
    waf_ref = "SE:06"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-sql-database-well-architected-framework"
    recommendation = (
        "Set public_network_access_enabled = false on azurerm_mssql_server and "
        "create an azurerm_private_endpoint for the SQL server."
    )
    resource_types = {"azurerm_mssql_server"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        public_access = resource.get_attribute("public_network_access_enabled")
        public_disabled = public_access is False or str(public_access).lower() == "false"
        return self._make_finding(resource, passed=public_disabled)


RULES = [
    AksNodePoolZonesRule(),
    SqlPrivateEndpointRule(),
]
