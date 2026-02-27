"""WAF Cost Optimization rules (CO:01–CO:14) — programmatic rules."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class IdleResourceRule(BaseRule):
    """WAF-COST-011: Detect idle or underutilized resources."""

    rule_id = "WAF-COST-011"
    description = "Idle or underutilized resources detected — standalone public IPs, unattached disks"
    severity = Severity.MEDIUM
    waf_ref = "CO:09"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/optimize-flow-costs"
    recommendation = (
        "Review standalone public IPs, unattached managed disks, and empty resource groups. "
        "Remove idle resources or attach them to active workloads."
    )
    resource_types = {"azurerm_public_ip", "azurerm_managed_disk"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        # Check if a public IP or managed disk is referenced by another resource
        resource_ref = f"{resource.resource_type}.{resource.name}"
        is_referenced = any(
            resource_ref in str(r.attributes)
            for r in index.resources
            if r.fqn != resource.fqn
        )

        return self._make_finding(resource, passed=is_referenced)


class BudgetAlertRule(BaseRule):
    """WAF-COST-004: Spending guardrails — budget alerts defined."""

    rule_id = "WAF-COST-004"
    description = "Spending guardrails — budget alerts defined for cost management"
    severity = Severity.MEDIUM
    waf_ref = "CO:04"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/set-spending-guardrails"
    recommendation = (
        "Deploy azurerm_consumption_budget_resource_group or "
        "azurerm_consumption_budget_subscription to receive alerts when costs exceed thresholds."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        has_budget = bool(
            index.get_resources_by_type("azurerm_consumption_budget_resource_group")
            or index.get_resources_by_type("azurerm_consumption_budget_subscription")
            or index.get_resources_by_type("azurerm_consumption_budget")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="cost",
            resource_name="budget_alerts",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            waf_ref=self.waf_ref,
            passed=has_budget,
        )


class ReservedInstancesRule(BaseRule):
    """WAF-COST-005: Reserved instances considered for long-running VMs."""

    rule_id = "WAF-COST-005"
    description = "Reserved instances or savings plans considered for long-running compute"
    severity = Severity.LOW
    waf_ref = "CO:05"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/get-best-rates"
    recommendation = (
        "For production VMs running 24/7, purchase Azure Reserved Instances "
        "or Savings Plans for up to 72% cost savings vs. pay-as-you-go."
    )
    resource_types = {
        "azurerm_linux_virtual_machine",
        "azurerm_windows_virtual_machine",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None
        # Informational: flag all standalone production VMs as candidates for reservations
        tags = resource.get_attribute("tags")
        is_prod = False
        if isinstance(tags, dict):
            env = tags.get("env", tags.get("environment", ""))
            is_prod = str(env).lower() in ("prod", "production")
        if is_prod:
            return self._make_finding(
                resource, passed=False,
                description=f"Production VM '{resource.name}' — consider Reserved Instance or Savings Plan"
            )
        return self._make_finding(resource, passed=True)


class AutoscaleValidationRule(BaseRule):
    """WAF-COST-012: Autoscale min ≤ default ≤ max validation."""

    rule_id = "WAF-COST-012"
    description = "Autoscale configuration valid — minimum ≤ default ≤ maximum instance counts"
    severity = Severity.HIGH
    waf_ref = "CO:12"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/optimize-scaling-costs"
    recommendation = (
        "Ensure autoscale profile capacity has minimum ≤ default ≤ maximum. "
        "Setting minimum too high wastes cost; setting maximum too low blocks scaling."
    )
    resource_types = {"azurerm_monitor_autoscale_setting"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        profile = resource.get_attribute("profile")
        if not isinstance(profile, dict):
            return self._make_finding(resource, passed=True)

        capacity = profile.get("capacity") if isinstance(profile, dict) else None
        if not isinstance(capacity, dict):
            return self._make_finding(resource, passed=True)

        try:
            min_val = int(capacity.get("minimum", 0))
            max_val = int(capacity.get("maximum", 0))
            default_val = int(capacity.get("default", 0))
            valid = min_val <= default_val <= max_val and min_val < max_val
        except (ValueError, TypeError):
            valid = True  # Can't validate dynamic values

        return self._make_finding(resource, passed=valid)


RULES = [
    IdleResourceRule(),
    BudgetAlertRule(),
    ReservedInstancesRule(),
    AutoscaleValidationRule(),
]
