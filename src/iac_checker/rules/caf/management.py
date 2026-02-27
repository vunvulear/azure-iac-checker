"""CAF Management & Monitoring rules — programmatic rules for observability."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class LogAnalyticsWorkspaceRule(BaseRule):
    """CAF-MGT-001: Log Analytics workspace deployed for centralized logging."""

    rule_id = "CAF-MGT-001"
    description = "Log Analytics workspace deployed for centralized logging and monitoring"
    severity = Severity.HIGH
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/management"
    recommendation = (
        "Deploy an azurerm_log_analytics_workspace as a central log sink. "
        "Route diagnostic settings from all resources to this workspace."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        has_workspace = bool(
            index.get_resources_by_type("azurerm_log_analytics_workspace")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="management",
            resource_name="log_analytics",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            passed=has_workspace,
        )


class ActivityLogExportRule(BaseRule):
    """CAF-MGT-002: Activity log exported to Log Analytics."""

    rule_id = "CAF-MGT-002"
    description = "Activity log exported to Log Analytics for audit and compliance"
    severity = Severity.MEDIUM
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/management"
    recommendation = (
        "Deploy azurerm_monitor_diagnostic_setting targeting the subscription "
        "activity log to forward events to a Log Analytics workspace."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        diag_settings = index.get_resources_by_type("azurerm_monitor_diagnostic_setting")
        has_activity_export = any(
            "subscription" in str(ds.attributes).lower()
            or "activity" in str(ds.attributes).lower()
            for ds in diag_settings
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="management",
            resource_name="activity_log_export",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            passed=has_activity_export,
        )


RULES = [
    LogAnalyticsWorkspaceRule(),
    ActivityLogExportRule(),
]
