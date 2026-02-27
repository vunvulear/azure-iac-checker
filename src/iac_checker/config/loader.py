"""Configuration loader — reads YAML config and merges with defaults."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from iac_checker.config.defaults import DEFAULTS
from iac_checker.models.enums import Severity

logger = logging.getLogger(__name__)


@dataclass
class RuleOverride:
    enabled: bool = True
    severity: Optional[Severity] = None
    pattern: Optional[str] = None


@dataclass
class CheckerConfig:
    exclude_paths: List[str] = field(default_factory=lambda: [".terraform/", "examples/", "tests/"])
    severity_threshold: Severity = Severity.HIGH
    production_strict_mode: bool = True
    environment_detection: str = "tag"

    # WAF settings
    waf_pillars: List[str] = field(default_factory=list)
    service_guides_enabled: bool = True
    service_guides_services: List[str] = field(default_factory=list)

    # CAF tagging
    mandatory_tags: Dict[str, List[str]] = field(default_factory=dict)

    # CAF naming
    naming_convention: str = "{abbreviation}-{workload}-{env}-{region}-{instance}"
    abbreviations_source: str = "microsoft"
    naming_delimiter: str = "-"
    enforce_lowercase: bool = True

    # Governance
    governance_categories: List[str] = field(default_factory=list)

    # AVM
    check_avm_alternatives: bool = False
    avm_preferred_source: str = "Azure/avm-"

    # Rule overrides
    rule_overrides: Dict[str, RuleOverride] = field(default_factory=dict)

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled (default: True)."""
        override = self.rule_overrides.get(rule_id)
        if override is not None:
            return override.enabled
        return True

    def get_severity_override(self, rule_id: str) -> Optional[Severity]:
        """Get severity override for a rule, if any."""
        override = self.rule_overrides.get(rule_id)
        if override and override.severity:
            return override.severity
        return None


class ConfigLoader:
    @staticmethod
    def load(config_path: str) -> CheckerConfig:
        """Load config from YAML file, merge with defaults."""
        raw = dict(DEFAULTS)

        path = Path(config_path)
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    user_config = yaml.safe_load(f) or {}
                if not isinstance(user_config, dict):
                    logger.warning("Config file %s is not a YAML mapping, using defaults", path)
                    user_config = {}
                raw = ConfigLoader._deep_merge(raw, user_config)
                logger.debug("Loaded config from %s", path)
            except yaml.YAMLError as exc:
                logger.warning("Failed to parse config %s: %s. Using defaults.", path, exc)
        else:
            logger.debug("No config file at %s, using defaults", path)

        return ConfigLoader._build_config(raw)

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Recursively merge override into base."""
        result = dict(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigLoader._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    @staticmethod
    def _build_config(raw: dict) -> CheckerConfig:
        """Build a CheckerConfig from raw dict."""
        config = CheckerConfig()

        # Scan settings
        scan = raw.get("scan", {})
        config.exclude_paths = scan.get("exclude_paths", config.exclude_paths)
        try:
            config.severity_threshold = Severity(scan.get("severity_threshold", "High"))
        except ValueError:
            logger.warning(
                "Invalid severity_threshold '%s', defaulting to High",
                scan.get("severity_threshold"),
            )
            config.severity_threshold = Severity.HIGH
        config.production_strict_mode = scan.get("production_strict_mode", True)
        config.environment_detection = scan.get("environment_detection", "tag")

        # WAF settings
        waf = raw.get("waf", {})
        config.waf_pillars = waf.get("pillars", [])
        sg = waf.get("service_guides", {})
        config.service_guides_enabled = sg.get("enabled", True)
        config.service_guides_services = sg.get("services", [])

        # Tags — collect mandatory tags from all categories
        tags = raw.get("tags", {})
        config.mandatory_tags = {}
        for category, settings in tags.items():
            if isinstance(settings, dict) and "mandatory" in settings:
                config.mandatory_tags[category] = settings["mandatory"]

        # Naming
        naming = raw.get("naming", {})
        config.naming_convention = naming.get("convention", config.naming_convention)
        config.abbreviations_source = naming.get("abbreviations_source", "microsoft")
        config.naming_delimiter = naming.get("delimiter", "-")
        config.enforce_lowercase = naming.get("enforce_lowercase", True)

        # Governance
        gov = raw.get("governance", {})
        config.governance_categories = gov.get("enforce_categories", [])

        # AVM
        avm = raw.get("avm", {})
        config.check_avm_alternatives = avm.get("check_avm_alternatives", False)
        config.avm_preferred_source = avm.get("preferred_source", "Azure/avm-")

        # Rule overrides
        rules = raw.get("rules", {})
        for rule_id, overrides in rules.items():
            if isinstance(overrides, dict):
                severity = None
                if "severity" in overrides:
                    try:
                        severity = Severity(overrides["severity"])
                    except ValueError:
                        logger.warning(
                            "Invalid severity '%s' for rule %s, ignoring override",
                            overrides["severity"], rule_id,
                        )
                config.rule_overrides[rule_id] = RuleOverride(
                    enabled=overrides.get("enabled", True),
                    severity=severity,
                    pattern=overrides.get("pattern"),
                )

        return config
