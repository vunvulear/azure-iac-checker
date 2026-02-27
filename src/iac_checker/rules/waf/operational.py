"""WAF Operational Excellence rules (OE:01–OE:11) — programmatic rules."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class RemoteBackendRule(BaseRule):
    """WAF-OPS-005: Terraform state stored remotely with locking."""

    rule_id = "WAF-OPS-005"
    description = "Terraform state stored remotely (Azure Storage backend with locking)"
    severity = Severity.HIGH
    waf_ref = "OE:05"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/infrastructure-as-code-design"
    recommendation = (
        "Configure a backend 'azurerm' block in the terraform {} config to store state "
        "in Azure Storage with state locking enabled."
    )
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        # This is a global rule — checked in engine._evaluate_global()
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        """Check if backend is configured."""
        has_backend = bool(index.backend)
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="terraform {}",
            line_number=0,
            resource_type="terraform",
            resource_name="backend",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            waf_ref=self.waf_ref,
            passed=has_backend,
        )


class ProvisionerRule(BaseRule):
    """WAF-OPS-020: No local-exec or remote-exec provisioners."""

    rule_id = "WAF-OPS-020"
    description = "No local-exec or remote-exec provisioners — prefer native Terraform resources"
    severity = Severity.MEDIUM
    waf_ref = "OE:05"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/infrastructure-as-code-design"
    recommendation = (
        "Replace local-exec and remote-exec provisioners with native Terraform resources "
        "or data sources. Provisioners make plans non-deterministic."
    )
    applies_to_all = True

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        has_provisioner = (
            resource.has_attribute("provisioner") or
            "local-exec" in str(resource.attributes) or
            "remote-exec" in str(resource.attributes)
        )
        if has_provisioner:
            return self._make_finding(resource, passed=False)
        return None  # Skip reporting pass for this global check


class DiagnosticSettingsRule(BaseRule):
    """WAF-OPS-010: Diagnostic settings enabled on all resources."""

    rule_id = "WAF-OPS-010"
    description = "Diagnostic settings and logging enabled on all resources that support them"
    severity = Severity.MEDIUM
    waf_ref = "OE:07"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/observability"
    recommendation = (
        "Create azurerm_monitor_diagnostic_setting resources for each service that supports diagnostics. "
        "Send logs to a centralized Log Analytics workspace."
    )
    resource_types = {
        "azurerm_key_vault",
        "azurerm_kubernetes_cluster",
        "azurerm_mssql_server",
        "azurerm_storage_account",
        "azurerm_linux_web_app",
        "azurerm_windows_web_app",
        "azurerm_app_service",
        "azurerm_function_app",
        "azurerm_linux_function_app",
        "azurerm_application_gateway",
        "azurerm_firewall",
        "azurerm_public_ip",
        "azurerm_network_security_group",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        # Check if there's a diagnostic_setting resource referencing this resource
        resource_ref = f"{resource.resource_type}.{resource.name}"
        has_diag = any(
            ds for ds in index.get_resources_by_type("azurerm_monitor_diagnostic_setting")
            if resource_ref in str(ds.attributes)
        )

        return self._make_finding(resource, passed=has_diag)


class ModuleVersionPinningRule(BaseRule):
    """WAF-OPS-006: Module sources pinned to specific versions."""

    rule_id = "WAF-OPS-006"
    description = "Module sources pinned to specific versions for supply chain security"
    severity = Severity.MEDIUM
    waf_ref = "OE:06"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/workload-supply-chain"
    recommendation = (
        "Pin module versions using the 'version' attribute in module blocks. "
        "Avoid using unpinned registry modules or unversioned git sources."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        """Check if all modules have version pins."""
        unpinned = []
        for mod in index.modules:
            source = mod.get_attribute("source")
            version = mod.get_attribute("version")
            if source and isinstance(source, str):
                # Registry modules need a version attribute
                if "registry.terraform.io" in source or "/" in source and "::" not in source:
                    if not version:
                        unpinned.append(mod.name)
                # Git sources need a ref
                elif "git::" in source and "?ref=" not in source:
                    unpinned.append(mod.name)

        passed = len(unpinned) == 0
        desc = self.description
        if unpinned:
            desc = f"Unpinned modules: {', '.join(unpinned[:5])}"
        return Finding(
            rule_id=self.rule_id,
            description=desc,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="operational",
            resource_name="module_versions",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            waf_ref=self.waf_ref,
            passed=passed,
        )


class LifecycleBlockRule(BaseRule):
    """WAF-OPS-009: Lifecycle blocks protect critical resources."""

    rule_id = "WAF-OPS-009"
    description = "Lifecycle blocks used to protect critical resources from accidental deletion"
    severity = Severity.LOW
    waf_ref = "OE:09"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/automate-tasks"
    recommendation = (
        "Add lifecycle { prevent_destroy = true } on critical resources like "
        "databases, Key Vaults, and storage accounts."
    )
    resource_types = {
        "azurerm_key_vault",
        "azurerm_mssql_server",
        "azurerm_mssql_database",
        "azurerm_cosmosdb_account",
        "azurerm_storage_account",
    }

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        lifecycle = resource.get_attribute("lifecycle")
        has_prevent = False
        if isinstance(lifecycle, dict):
            has_prevent = lifecycle.get("prevent_destroy") is True
        return self._make_finding(resource, passed=has_prevent)


class DeploymentSlotsRule(BaseRule):
    """WAF-OPS-011: Deployment slots used for safe deployments on App Service."""

    rule_id = "WAF-OPS-011"
    description = "Deployment slots configured for safe, zero-downtime deployments on App Service"
    severity = Severity.MEDIUM
    waf_ref = "OE:11"
    doc_url = "https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/safe-deployments"
    recommendation = (
        "Create azurerm_linux_web_app_slot or azurerm_windows_web_app_slot resources "
        "for staging deployments with swap-based zero-downtime releases."
    )
    resource_types = {"azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_app_service"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        resource_ref = f"{resource.resource_type}.{resource.name}"
        has_slot = any(
            s for s in (
                index.get_resources_by_type("azurerm_linux_web_app_slot")
                + index.get_resources_by_type("azurerm_windows_web_app_slot")
                + index.get_resources_by_type("azurerm_app_service_slot")
            )
            if resource_ref in str(s.attributes)
        )
        return self._make_finding(resource, passed=has_slot)


RULES = [
    RemoteBackendRule(),
    ProvisionerRule(),
    DiagnosticSettingsRule(),
    ModuleVersionPinningRule(),
    LifecycleBlockRule(),
    DeploymentSlotsRule(),
]
