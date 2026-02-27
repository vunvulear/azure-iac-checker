"""Tests for configuration loader."""

import pytest
import yaml
from pathlib import Path

from iac_checker.config.loader import ConfigLoader, CheckerConfig, RuleOverride
from iac_checker.config.defaults import DEFAULTS
from iac_checker.models.enums import Severity


class TestCheckerConfig:
    def test_default_config(self):
        config = CheckerConfig()
        assert config.severity_threshold == Severity.HIGH
        assert config.production_strict_mode is True
        assert ".terraform/" in config.exclude_paths

    def test_is_rule_enabled_default(self):
        config = CheckerConfig()
        assert config.is_rule_enabled("WAF-SEC-001") is True

    def test_is_rule_disabled(self):
        config = CheckerConfig()
        config.rule_overrides["WAF-SVC-002"] = RuleOverride(enabled=False)
        assert config.is_rule_enabled("WAF-SVC-002") is False

    def test_get_severity_override(self):
        config = CheckerConfig()
        config.rule_overrides["WAF-SEC-007"] = RuleOverride(severity=Severity.MEDIUM)
        assert config.get_severity_override("WAF-SEC-007") == Severity.MEDIUM

    def test_get_severity_override_none(self):
        config = CheckerConfig()
        assert config.get_severity_override("WAF-SEC-001") is None


class TestConfigLoader:
    def test_load_nonexistent_file_returns_defaults(self):
        config = ConfigLoader.load("nonexistent.yaml")
        assert isinstance(config, CheckerConfig)
        assert config.severity_threshold == Severity.HIGH

    def test_load_from_yaml(self, tmp_path):
        yaml_content = {
            "scan": {
                "severity_threshold": "Medium",
                "exclude_paths": [".terraform/", "vendor/"],
            },
            "rules": {
                "WAF-SEC-007": {"enabled": True, "severity": "Low"},
                "WAF-SVC-002": {"enabled": False},
            },
            "tags": {
                "functional": {"mandatory": ["app", "env", "tier"]},
                "accounting": {"mandatory": ["costCenter"]},
            },
            "naming": {
                "enforce_lowercase": False,
            },
            "avm": {
                "check_avm_alternatives": True,
            },
        }

        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(yaml_content))

        config = ConfigLoader.load(str(config_file))

        assert config.severity_threshold == Severity.MEDIUM
        assert "vendor/" in config.exclude_paths
        assert config.is_rule_enabled("WAF-SVC-002") is False
        assert config.get_severity_override("WAF-SEC-007") == Severity.LOW
        assert config.mandatory_tags["functional"] == ["app", "env", "tier"]
        assert config.enforce_lowercase is False
        assert config.check_avm_alternatives is True

    def test_deep_merge(self):
        base = {"a": {"b": 1, "c": 2}, "d": 3}
        override = {"a": {"b": 10, "e": 5}, "f": 6}
        result = ConfigLoader._deep_merge(base, override)
        assert result == {"a": {"b": 10, "c": 2, "e": 5}, "d": 3, "f": 6}

    def test_deep_merge_overwrite_non_dict(self):
        base = {"a": [1, 2, 3]}
        override = {"a": [4, 5]}
        result = ConfigLoader._deep_merge(base, override)
        assert result == {"a": [4, 5]}

    def test_defaults_structure(self):
        assert "scan" in DEFAULTS
        assert "waf" in DEFAULTS
        assert "tags" in DEFAULTS
        assert "naming" in DEFAULTS
        assert "governance" in DEFAULTS
        assert "avm" in DEFAULTS
        assert "rules" in DEFAULTS

    def test_invalid_severity_threshold_falls_back_to_high(self):
        """Invalid severity_threshold in config should fall back to High."""
        config = ConfigLoader._build_config({
            "scan": {"severity_threshold": "InvalidValue"},
        })
        assert config.severity_threshold == Severity.HIGH

    def test_invalid_rule_severity_override_ignored(self):
        """Invalid severity in rule override should leave severity as None."""
        config = ConfigLoader._build_config({
            "rules": {
                "WAF-SEC-001": {"enabled": True, "severity": "InvalidSev"},
            },
        })
        override = config.rule_overrides.get("WAF-SEC-001")
        assert override is not None
        assert override.enabled is True
        assert override.severity is None

    def test_non_dict_yaml_config_uses_defaults(self, tmp_path):
        """A YAML file containing a non-dict (e.g., a list) should use defaults."""
        config_file = tmp_path / "bad.yaml"
        config_file.write_text("- item1\n- item2\n")
        config = ConfigLoader.load(str(config_file))
        assert config.severity_threshold == Severity.HIGH
