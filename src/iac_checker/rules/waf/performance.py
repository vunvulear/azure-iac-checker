"""WAF Performance Efficiency rules (PE:01–PE:12) — programmatic rules."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class StoragePerformanceTierRule(BaseRule):
    """WAF-PERF-011: Storage account performance tier appropriate."""

    rule_id = "WAF-PERF-011"
    description = "Storage account performance tier appropriate — Premium for IOPS-intensive, Standard for general use"
    severity = Severity.MEDIUM
    waf_ref = "PE:08"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/performance-efficiency/optimize-data-performance"
    recommendation = (
        "Review storage account tier. Use Premium for IOPS-intensive workloads. "
        "Standard is sufficient for general-purpose storage."
    )
    resource_types = {"azurerm_storage_account"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None
        # This is informational — just verify tier is explicitly set
        tier = resource.get_attribute("account_tier")
        return self._make_finding(resource, passed=(tier is not None))


class ExplicitSkuRule(BaseRule):
    """WAF-PERF-003: Right-size services — explicit SKU/size configured."""

    rule_id = "WAF-PERF-003"
    description = "Explicit SKU or size configured — right-sizing validated for performance"
    severity = Severity.MEDIUM
    waf_ref = "PE:03"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/performance-efficiency/select-services"
    recommendation = (
        "Always explicitly set the SKU or size on resources. "
        "Relying on defaults may result in under- or over-provisioned resources."
    )
    resource_types = {
        "azurerm_linux_virtual_machine",
        "azurerm_windows_virtual_machine",
        "azurerm_service_plan",
        "azurerm_app_service_plan",
        "azurerm_redis_cache",
        "azurerm_cosmosdb_account",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        has_sku = (
            resource.has_attribute("size")
            or resource.has_attribute("sku_name")
            or resource.has_attribute("sku")
            or resource.has_attribute("vm_size")
        )
        return self._make_finding(resource, passed=has_sku)


class CdnCachingRule(BaseRule):
    """WAF-PERF-007: CDN or caching layer for web applications."""

    rule_id = "WAF-PERF-007"
    description = "CDN or caching layer configured for web-facing applications"
    severity = Severity.LOW
    waf_ref = "PE:07"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/performance-efficiency/optimize-code-infrastructure"
    recommendation = (
        "Deploy Azure Front Door, CDN, or Redis Cache to improve response times "
        "and reduce load on backend services for web-facing workloads."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        """Check if any CDN or caching infrastructure is present."""
        has_cdn = bool(
            index.get_resources_by_type("azurerm_cdn_profile")
            or index.get_resources_by_type("azurerm_cdn_endpoint")
            or index.get_resources_by_type("azurerm_frontdoor")
            or index.get_resources_by_type("azurerm_cdn_frontdoor_profile")
            or index.get_resources_by_type("azurerm_redis_cache")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="performance",
            resource_name="cdn_caching",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            waf_ref=self.waf_ref,
            passed=has_cdn,
        )


RULES = [
    StoragePerformanceTierRule(),
    ExplicitSkuRule(),
    CdnCachingRule(),
]
