"""Tests for models: enums, finding, resource."""

import pytest
from iac_checker.models.enums import Severity, Pillar, CafDomain
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource


# === Severity Tests ===

class TestSeverity:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "Critical"
        assert Severity.HIGH.value == "High"
        assert Severity.MEDIUM.value == "Medium"
        assert Severity.LOW.value == "Low"

    def test_severity_rank_ordering(self):
        assert Severity.CRITICAL.rank < Severity.HIGH.rank
        assert Severity.HIGH.rank < Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank < Severity.LOW.rank

    def test_severity_emoji(self):
        assert Severity.CRITICAL.emoji == "🔴"
        assert Severity.HIGH.emoji == "🟠"
        assert Severity.MEDIUM.emoji == "🟡"
        assert Severity.LOW.emoji == "🔵"

    def test_severity_from_string(self):
        assert Severity("Critical") == Severity.CRITICAL
        assert Severity("High") == Severity.HIGH

    def test_severity_invalid_raises(self):
        with pytest.raises(ValueError):
            Severity("Unknown")


class TestPillar:
    def test_pillar_values(self):
        assert Pillar.RELIABILITY.value == "Reliability"
        assert Pillar.SECURITY.value == "Security"
        assert Pillar.COST_OPTIMIZATION.value == "Cost Optimization"
        assert Pillar.OPERATIONAL_EXCELLENCE.value == "Operational Excellence"
        assert Pillar.PERFORMANCE_EFFICIENCY.value == "Performance Efficiency"
        assert Pillar.SERVICE_GUIDES.value == "Service Guides"


class TestCafDomain:
    def test_domain_values(self):
        assert CafDomain.NAMING.value == "Naming Conventions"
        assert CafDomain.TAGGING.value == "Tagging Strategy"
        assert CafDomain.GOVERNANCE.value == "Governance & Policy"


# === Finding Tests ===

class TestFinding:
    def _make_finding(self, **kwargs):
        defaults = dict(
            rule_id="WAF-SEC-001",
            description="Test finding",
            severity=Severity.HIGH,
            file_path="main.tf",
            line_number=10,
            resource_type="azurerm_storage_account",
            resource_name="main",
            recommendation="Fix it",
            doc_url="https://example.com",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_location(self):
        f = self._make_finding(file_path="modules/db/main.tf", line_number=42)
        assert f.location == "modules/db/main.tf:42"

    def test_resource_fqn(self):
        f = self._make_finding(resource_type="azurerm_key_vault", resource_name="kv1")
        assert f.resource_fqn == "azurerm_key_vault.kv1"

    def test_framework_ref_waf(self):
        f = self._make_finding(waf_ref="SE:07")
        assert f.framework_ref == "SE:07"

    def test_framework_ref_caf(self):
        f = self._make_finding(waf_ref="", caf_ref="Naming")
        assert f.framework_ref == "Naming"

    def test_framework_ref_none(self):
        f = self._make_finding(waf_ref="", caf_ref="")
        assert f.framework_ref == "—"

    def test_defaults(self):
        f = self._make_finding()
        assert f.passed is False
        assert f.suppressed is False
        assert f.suppression_reason == ""


# === TerraformResource Tests ===

class TestTerraformResource:
    def _make_resource(self, attributes=None):
        return TerraformResource(
            resource_type="azurerm_storage_account",
            name="main",
            attributes=attributes or {},
            file_path="main.tf",
            line_number=1,
        )

    def test_fqn(self):
        r = self._make_resource()
        assert r.fqn == "azurerm_storage_account.main"

    def test_get_attribute_simple(self):
        r = self._make_resource({"min_tls_version": "TLS1_2"})
        assert r.get_attribute("min_tls_version") == "TLS1_2"

    def test_get_attribute_nested(self):
        r = self._make_resource({"network_rules": {"default_action": "Deny"}})
        assert r.get_attribute("network_rules.default_action") == "Deny"

    def test_get_attribute_nested_list(self):
        r = self._make_resource({"network_rules": [{"default_action": "Deny"}]})
        assert r.get_attribute("network_rules.default_action") == "Deny"

    def test_get_attribute_missing_returns_default(self):
        r = self._make_resource({})
        assert r.get_attribute("nonexistent") is None
        assert r.get_attribute("nonexistent", "fallback") == "fallback"

    def test_get_attribute_deep_missing(self):
        r = self._make_resource({"a": {"b": "c"}})
        assert r.get_attribute("a.b.x") is None

    def test_has_attribute_true(self):
        r = self._make_resource({"min_tls_version": "TLS1_2"})
        assert r.has_attribute("min_tls_version") is True

    def test_has_attribute_false(self):
        r = self._make_resource({})
        assert r.has_attribute("min_tls_version") is False

    def test_has_attribute_none_value(self):
        r = self._make_resource({"key": None})
        # None is a valid value — attribute exists
        assert r.has_attribute("key") is True

    def test_block_type_default(self):
        r = self._make_resource()
        assert r.block_type == "resource"
