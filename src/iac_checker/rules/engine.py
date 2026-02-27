"""Rules engine — orchestrates rule loading, evaluation, and finding collection."""

import logging
from pathlib import Path
from typing import List

from iac_checker.config.loader import CheckerConfig
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.registry import RuleRegistry

logger = logging.getLogger(__name__)


class RulesEngine:
    def __init__(self, config: CheckerConfig):
        self.config = config
        self.registry = RuleRegistry()
        self._load_rules()

    @property
    def rules_count(self) -> int:
        return self.registry.count

    def _load_rules(self) -> None:
        """Load all rule definitions from YAML files and Python modules."""
        definitions_dir = Path(__file__).parent / "definitions"
        self.registry.load_yaml_definitions(definitions_dir)
        yaml_count = self.registry.count
        self.registry.load_programmatic_rules()
        prog_count = self.registry.count - yaml_count
        logger.debug(
            "Loaded %d YAML rules + %d programmatic rules = %d total",
            yaml_count, prog_count, self.registry.count,
        )

    def evaluate(self, index: ResourceIndex) -> List[Finding]:
        """Run all enabled rules against all resources and collect findings."""
        findings: List[Finding] = []

        for resource in index.resources:
            resource_findings = self._evaluate_resource(resource, index)
            findings.extend(resource_findings)

        # Also evaluate global rules (e.g., backend config, provider versions)
        global_findings = self._evaluate_global(index)
        findings.extend(global_findings)

        return findings

    def _evaluate_resource(self, resource: TerraformResource, index: ResourceIndex) -> List[Finding]:
        """Evaluate all applicable rules against a single resource."""
        findings = []
        applicable_rules = self.registry.get_rules_for_resource_type(resource.resource_type)

        # Get inline suppressions for this resource (Terraform # / Bicep //)
        suppressions = index.get_inline_suppressions(resource.file_path, resource.line_number)

        # Also check ARM metadata-based suppressions
        suppressions.extend(index.get_arm_metadata_suppressions(resource))

        for rule in applicable_rules:
            # Skip disabled rules
            if not self.config.is_rule_enabled(rule.rule_id):
                continue

            finding = rule.evaluate(resource, index)
            if finding is None:
                continue

            # Apply severity override from config
            severity_override = self.config.get_severity_override(rule.rule_id)
            if severity_override:
                finding.severity = severity_override

            # Apply inline suppression
            if rule.rule_id in suppressions:
                finding.suppressed = True
                finding.suppression_reason = "Suppressed via inline comment"

            findings.append(finding)

        return findings

    def _evaluate_global(self, index: ResourceIndex) -> List[Finding]:
        """Evaluate rules that apply globally (not per-resource)."""
        findings = []

        for rule in self.registry.get_global_rules():
            if not self.config.is_rule_enabled(rule.rule_id):
                continue

            finding = rule.evaluate_global(index)
            if finding is None:
                continue

            severity_override = self.config.get_severity_override(rule.rule_id)
            if severity_override:
                finding.severity = severity_override

            findings.append(finding)

        return findings
