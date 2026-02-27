"""Base rule class — all WAF and CAF rules inherit from this."""

from abc import ABC, abstractmethod
from typing import List, Optional, Set

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex


class BaseRule(ABC):
    """Abstract base class for all compliance rules."""

    rule_id: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    waf_ref: str = ""
    caf_ref: str = ""
    doc_url: str = ""
    recommendation: str = ""
    resource_types: Set[str] = set()  # azurerm_* types this rule applies to
    applies_to_all: bool = False  # if True, runs against all resources

    @abstractmethod
    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        """
        Evaluate a single resource against this rule.

        Returns:
            Finding with passed=False if violation found.
            Finding with passed=True if check passed.
            None if rule does not apply to this resource.
        """
        ...

    def applies_to(self, resource: TerraformResource) -> bool:
        """Check if this rule applies to the given resource type."""
        if self.applies_to_all:
            return True
        return resource.resource_type in self.resource_types

    def _make_finding(self, resource: TerraformResource, passed: bool,
                      description: str = None) -> Finding:
        """Helper to create a Finding from a resource evaluation."""
        return Finding(
            rule_id=self.rule_id,
            description=description or self.description,
            severity=self.severity,
            file_path=resource.file_path,
            line_number=resource.line_number,
            resource_type=resource.resource_type,
            resource_name=resource.name,
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            waf_ref=self.waf_ref,
            caf_ref=self.caf_ref,
            passed=passed,
        )


class YamlDrivenRule(BaseRule):
    """A rule driven by YAML definition — checks a single attribute value."""

    def __init__(self, definition: dict):
        self.rule_id = definition["id"]
        self.description = definition["description"]
        self.severity = Severity(definition["severity"])
        self.waf_ref = definition.get("waf_ref", "")
        self.caf_ref = definition.get("caf_ref", "")
        self.doc_url = definition.get("doc_url", "")
        self.recommendation = definition.get("recommendation", "")
        self.resource_types = set(definition.get("resource_types", []))
        self.applies_to_all = len(self.resource_types) == 0
        self.check = definition.get("check", {})

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        check = self.check
        attribute = check.get("attribute", "")
        operator = check.get("operator", "exists")
        expected = check.get("value")
        absent_is_violation = check.get("absent_is_violation", True)

        actual = resource.get_attribute(attribute)

        if actual is None:
            if absent_is_violation:
                return self._make_finding(resource, passed=False,
                    description=f"{self.description} — attribute `{attribute}` is missing")
            return self._make_finding(resource, passed=True)

        passed = self._check_value(actual, operator, expected)
        return self._make_finding(resource, passed=passed)

    def _check_value(self, actual, operator: str, expected) -> bool:
        """Evaluate the attribute value against the expected value."""
        if operator == "equals":
            return str(actual).lower() == str(expected).lower()
        elif operator == "not_equals":
            return str(actual).lower() != str(expected).lower()
        elif operator == "contains":
            return expected in str(actual)
        elif operator == "not_contains":
            return expected not in str(actual)
        elif operator == "exists":
            return actual is not None
        elif operator == "not_exists":
            return actual is None
        elif operator == "in":
            if isinstance(expected, list):
                return actual in expected
            return str(actual) in str(expected)
        elif operator == "not_in":
            if isinstance(expected, list):
                return actual not in expected
            return str(actual) not in str(expected)
        elif operator == "greater_than":
            return float(actual) > float(expected)
        elif operator == "bool_true":
            return actual is True or str(actual).lower() == "true"
        elif operator == "bool_false":
            return actual is False or str(actual).lower() == "false"
        return False
