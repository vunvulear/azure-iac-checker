"""Rule registry — discovers and manages all available rules."""

import importlib
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from iac_checker.rules.base_rule import BaseRule, YamlDrivenRule

# Programmatic rule modules to auto-load
_PROGRAMMATIC_MODULES = [
    "iac_checker.rules.waf.reliability",
    "iac_checker.rules.waf.security",
    "iac_checker.rules.waf.cost_optimization",
    "iac_checker.rules.waf.operational",
    "iac_checker.rules.waf.performance",
    "iac_checker.rules.waf.service_guides",
    "iac_checker.rules.caf.naming",
    "iac_checker.rules.caf.tagging",
    "iac_checker.rules.caf.landing_zone",
    "iac_checker.rules.caf.networking",
    "iac_checker.rules.caf.identity",
    "iac_checker.rules.caf.governance",
    "iac_checker.rules.caf.security_baseline",
    "iac_checker.rules.caf.management",
]


class RuleRegistry:
    """Registry of all compliance rules, loaded from YAML definitions and Python modules."""

    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}

    def register(self, rule: BaseRule) -> None:
        """Register a single rule instance."""
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Optional[BaseRule]:
        return self._rules.get(rule_id)

    @property
    def all_rules(self) -> List[BaseRule]:
        return list(self._rules.values())

    @property
    def count(self) -> int:
        return len(self._rules)

    def load_yaml_definitions(self, definitions_dir: Path) -> None:
        """Load all YAML rule definitions from a directory."""
        if not definitions_dir.exists():
            return

        for yaml_file in sorted(definitions_dir.glob("*.yaml")):
            self._load_yaml_file(yaml_file)

    def _load_yaml_file(self, yaml_file: Path) -> None:
        """Load rules from a single YAML file."""
        with open(yaml_file, "r", encoding="utf-8") as f:
            definitions = yaml.safe_load(f)

        if not definitions or not isinstance(definitions, list):
            return

        for definition in definitions:
            if "id" not in definition:
                continue
            # Skip custom-handler rules — they are implemented as programmatic Python rules
            check = definition.get("check", {})
            if isinstance(check, dict) and check.get("type") == "custom":
                continue
            rule = YamlDrivenRule(definition)
            self.register(rule)

    def get_rules_for_resource_type(self, resource_type: str) -> List[BaseRule]:
        """Get all rules applicable to a given resource type."""
        return [
            r for r in self._rules.values()
            if r.applies_to_all or resource_type in r.resource_types
        ]

    def load_programmatic_rules(self) -> None:
        """Load all programmatic rule classes from WAF/CAF Python modules."""
        for module_name in _PROGRAMMATIC_MODULES:
            try:
                mod = importlib.import_module(module_name)
                rules = getattr(mod, "RULES", [])
                for rule in rules:
                    if isinstance(rule, BaseRule) and rule.rule_id:
                        self.register(rule)
            except ImportError as e:
                pass  # Skip unavailable modules gracefully

    def get_global_rules(self) -> List[BaseRule]:
        """Get rules that have an evaluate_global method."""
        return [
            r for r in self._rules.values()
            if hasattr(r, "evaluate_global") and callable(getattr(r, "evaluate_global"))
        ]

    def filter_by_prefix(self, prefix: str) -> List[BaseRule]:
        """Get all rules whose ID starts with a prefix (e.g., 'WAF-SEC', 'CAF-TAG')."""
        return [r for r in self._rules.values() if r.rule_id.startswith(prefix)]
