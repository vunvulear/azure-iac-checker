"""WAF Reliability rules (RE:01–RE:10) — programmatic rules that go beyond YAML checks."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class AvailabilityZoneRule(BaseRule):
    """WAF-REL-002: Resources deployed across multiple Availability Zones."""

    rule_id = "WAF-REL-002"
    description = "Resources deployed across multiple Availability Zones where supported"
    severity = Severity.HIGH
    waf_ref = "RE:05"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/reliability/redundancy"
    recommendation = (
        "Set the 'zones' attribute to deploy across multiple Availability Zones. "
        "For VMs use 'zone', for VMSS/AKS use 'zones'."
    )
    resource_types = {
        "azurerm_linux_virtual_machine",
        "azurerm_windows_virtual_machine",
        "azurerm_virtual_machine",
        "azurerm_public_ip",
        "azurerm_lb",
        "azurerm_managed_disk",
        "azurerm_kubernetes_cluster",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        has_zone = resource.has_attribute("zone") or resource.has_attribute("zones")
        return self._make_finding(resource, passed=has_zone)


class BackupPolicyRule(BaseRule):
    """WAF-REL-008: Backup policies defined for databases, VMs, and storage."""

    rule_id = "WAF-REL-008"
    description = "Backup policies defined for databases, VMs, and storage accounts"
    severity = Severity.HIGH
    waf_ref = "RE:07"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/reliability/self-preservation"
    recommendation = (
        "Configure backup policies using azurerm_backup_policy_vm, "
        "azurerm_mssql_database long_term_retention_policy, or storage account blob_properties.delete_retention_policy."
    )
    resource_types = {
        "azurerm_mssql_database",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        has_ltr = resource.has_attribute("long_term_retention_policy")
        has_str = resource.has_attribute("short_term_retention_policy")
        return self._make_finding(resource, passed=(has_ltr or has_str))


class DisasterRecoveryRule(BaseRule):
    """WAF-REL-013: Disaster recovery configuration present."""

    rule_id = "WAF-REL-013"
    description = "Disaster recovery configuration present — paired regions, geo-redundant backups"
    severity = Severity.HIGH
    waf_ref = "RE:09"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/reliability/disaster-recovery"
    recommendation = (
        "Configure geo-redundant storage (GRS/GZRS), SQL geo-replication, "
        "or Recovery Services Vault with cross-region replication."
    )
    resource_types = {
        "azurerm_storage_account",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        replication = resource.get_attribute("account_replication_type", "")
        geo_redundant = str(replication).upper() in ("GRS", "RAGRS", "GZRS", "RAGZRS")
        return self._make_finding(resource, passed=geo_redundant)


class MultiRegionDeploymentRule(BaseRule):
    """WAF-REL-005: Multi-region deployment for critical workloads."""

    rule_id = "WAF-REL-005"
    description = "Multi-region deployment considered — resources deployed to paired regions for resiliency"
    severity = Severity.MEDIUM
    waf_ref = "RE:05"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/reliability/redundancy"
    recommendation = (
        "Deploy critical workloads across paired Azure regions. "
        "Use Azure Traffic Manager or Front Door for global load balancing."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        """Check if resources are deployed to more than one region."""
        locations = set()
        for r in index.resources:
            loc = r.get_attribute("location")
            if loc and isinstance(loc, str) and "${" not in loc and "var." not in loc:
                locations.add(loc.lower())
        has_multi_region = len(locations) > 1
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="reliability",
            resource_name="multi_region",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            waf_ref=self.waf_ref,
            passed=has_multi_region,
        )


class ScalingConfigRule(BaseRule):
    """WAF-REL-006: Scaling configuration — auto-scale or scale sets used."""

    rule_id = "WAF-REL-006"
    description = "Scaling configuration present — VMSS or auto-scale settings used for scalable workloads"
    severity = Severity.MEDIUM
    waf_ref = "RE:06"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/reliability/scaling"
    recommendation = (
        "Use Virtual Machine Scale Sets (VMSS) instead of standalone VMs. "
        "Configure azurerm_monitor_autoscale_setting for App Service and VMSS."
    )
    resource_types = {"azurerm_service_plan", "azurerm_app_service_plan"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        resource_ref = f"{resource.resource_type}.{resource.name}"
        has_autoscale = any(
            a for a in index.get_resources_by_type("azurerm_monitor_autoscale_setting")
            if resource_ref in str(a.attributes)
        )
        return self._make_finding(resource, passed=has_autoscale)


class MonitoringAlertRule(BaseRule):
    """WAF-REL-010: Monitoring and alerting — Azure Monitor alert rules defined."""

    rule_id = "WAF-REL-010"
    description = "Monitoring and alerting configured — Azure Monitor alert rules defined"
    severity = Severity.MEDIUM
    waf_ref = "RE:10"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/reliability/monitoring-alerting-strategy"
    recommendation = (
        "Define azurerm_monitor_metric_alert or azurerm_monitor_activity_log_alert "
        "resources to detect and respond to failures."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        """Check if any monitoring alert rules are defined."""
        has_alerts = bool(
            index.get_resources_by_type("azurerm_monitor_metric_alert")
            or index.get_resources_by_type("azurerm_monitor_activity_log_alert")
            or index.get_resources_by_type("azurerm_monitor_scheduled_query_rules_alert")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="reliability",
            resource_name="monitoring_alerts",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            waf_ref=self.waf_ref,
            passed=has_alerts,
        )


# All programmatic rules in this module
RULES = [
    AvailabilityZoneRule(),
    BackupPolicyRule(),
    DisasterRecoveryRule(),
    MultiRegionDeploymentRule(),
    ScalingConfigRule(),
    MonitoringAlertRule(),
]
