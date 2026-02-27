"""Tests for the CAF naming convention validator."""

import pytest
from iac_checker.utils.naming_validator import NamingValidator, CAF_ABBREVIATIONS, VALID_ENVIRONMENTS


class TestNamingValidator:
    def setup_method(self):
        self.validator = NamingValidator()

    # === CAF Prefix Tests ===

    def test_valid_resource_group_name(self):
        valid, error = self.validator.validate_name(
            "azurerm_resource_group", "rg-myapp-prod-eastus2-001"
        )
        assert valid is True
        assert error is None

    def test_invalid_resource_group_prefix(self):
        valid, error = self.validator.validate_name(
            "azurerm_resource_group", "myapp-prod-eastus2"
        )
        assert valid is False
        assert "rg" in error

    def test_valid_key_vault_name(self):
        valid, error = self.validator.validate_name(
            "azurerm_key_vault", "kv-myapp-prod-eus2-001"
        )
        assert valid is True

    def test_invalid_key_vault_too_long(self):
        valid, error = self.validator.validate_name(
            "azurerm_key_vault", "kv-" + "a" * 25
        )
        assert valid is False
        assert "too long" in error

    def test_invalid_key_vault_too_short(self):
        valid, error = self.validator.validate_name(
            "azurerm_key_vault", "kv"
        )
        assert valid is False
        assert "too short" in error

    def test_valid_storage_account_name(self):
        valid, error = self.validator.validate_name(
            "azurerm_storage_account", "stmyappprodeus2001"
        )
        assert valid is True

    def test_invalid_storage_account_with_hyphens(self):
        valid, error = self.validator.validate_name(
            "azurerm_storage_account", "st-myapp-prod"
        )
        assert valid is False

    def test_invalid_storage_account_uppercase(self):
        valid, error = self.validator.validate_name(
            "azurerm_storage_account", "stMyAppProd"
        )
        assert valid is False

    def test_invalid_storage_account_too_long(self):
        valid, error = self.validator.validate_name(
            "azurerm_storage_account", "a" * 25
        )
        assert valid is False
        assert "too long" in error

    def test_valid_vnet_name(self):
        valid, error = self.validator.validate_name(
            "azurerm_virtual_network", "vnet-hub-prod-eastus2-001"
        )
        assert valid is True

    def test_invalid_vnet_prefix(self):
        valid, error = self.validator.validate_name(
            "azurerm_virtual_network", "network-hub-prod"
        )
        assert valid is False
        assert "vnet" in error

    def test_valid_aks_name(self):
        valid, error = self.validator.validate_name(
            "azurerm_kubernetes_cluster", "aks-myapp-prod-eastus2-001"
        )
        assert valid is True

    # === Environment Component Tests ===

    def test_environment_component_found(self):
        valid, error = self.validator.check_environment_component("rg-myapp-prod-eastus2")
        assert valid is True

    def test_environment_component_dev(self):
        valid, error = self.validator.check_environment_component("rg-myapp-dev-eastus2")
        assert valid is True

    def test_environment_component_missing(self):
        valid, error = self.validator.check_environment_component("rg-myapp-eastus2")
        assert valid is False
        assert "No recognized environment" in error

    # === Abbreviation Coverage ===

    def test_abbreviation_map_has_common_types(self):
        assert "azurerm_resource_group" in CAF_ABBREVIATIONS
        assert "azurerm_storage_account" in CAF_ABBREVIATIONS
        assert "azurerm_key_vault" in CAF_ABBREVIATIONS
        assert "azurerm_kubernetes_cluster" in CAF_ABBREVIATIONS
        assert "azurerm_virtual_network" in CAF_ABBREVIATIONS

    def test_valid_environments(self):
        assert "dev" in VALID_ENVIRONMENTS
        assert "staging" in VALID_ENVIRONMENTS
        assert "prod" in VALID_ENVIRONMENTS
        assert "test" in VALID_ENVIRONMENTS
        assert "qa" in VALID_ENVIRONMENTS

    # === Unknown resource type (no abbreviation) ===

    def test_unknown_resource_type_passes(self):
        valid, error = self.validator.validate_name(
            "azurerm_some_new_resource", "anything-goes"
        )
        assert valid is True
