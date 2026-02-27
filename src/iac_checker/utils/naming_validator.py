"""Naming validator — validates resource names against CAF conventions."""

import re
from typing import Dict, Optional, Tuple

# CAF recommended abbreviations (subset of most common ones)
# Full list: https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations
CAF_ABBREVIATIONS: Dict[str, str] = {
    "azurerm_resource_group": "rg",
    "azurerm_virtual_network": "vnet",
    "azurerm_subnet": "snet",
    "azurerm_network_security_group": "nsg",
    "azurerm_public_ip": "pip",
    "azurerm_load_balancer": "lb",
    "azurerm_application_gateway": "agw",
    "azurerm_virtual_machine": "vm",
    "azurerm_linux_virtual_machine": "vm",
    "azurerm_windows_virtual_machine": "vm",
    "azurerm_virtual_machine_scale_set": "vmss",
    "azurerm_kubernetes_cluster": "aks",
    "azurerm_container_registry": "cr",
    "azurerm_app_service": "app",
    "azurerm_linux_web_app": "app",
    "azurerm_windows_web_app": "app",
    "azurerm_function_app": "func",
    "azurerm_linux_function_app": "func",
    "azurerm_storage_account": "st",
    "azurerm_key_vault": "kv",
    "azurerm_mssql_server": "sql",
    "azurerm_mssql_database": "sqldb",
    "azurerm_cosmosdb_account": "cosmos",
    "azurerm_redis_cache": "redis",
    "azurerm_log_analytics_workspace": "law",
    "azurerm_application_insights": "appi",
    "azurerm_frontdoor": "fd",
    "azurerm_cdn_frontdoor_profile": "afd",
    "azurerm_firewall": "afw",
    "azurerm_route_table": "rt",
    "azurerm_private_endpoint": "pep",
    "azurerm_private_dns_zone": "pdnsz",
    "azurerm_user_assigned_identity": "id",
    "azurerm_automation_account": "aa",
    "azurerm_eventhub_namespace": "evhns",
    "azurerm_servicebus_namespace": "sbns",
}

# Azure naming restrictions per resource type
NAMING_RESTRICTIONS: Dict[str, Dict] = {
    "azurerm_storage_account": {
        "min_length": 3,
        "max_length": 24,
        "pattern": r"^[a-z0-9]+$",
        "description": "Lowercase letters and numbers only, no hyphens, 3-24 chars",
    },
    "azurerm_key_vault": {
        "min_length": 3,
        "max_length": 24,
        "pattern": r"^[a-zA-Z][a-zA-Z0-9-]+$",
        "description": "Alphanumeric and hyphens, must start with letter, 3-24 chars",
    },
    "azurerm_resource_group": {
        "min_length": 1,
        "max_length": 90,
        "pattern": r"^[a-zA-Z0-9._\-()]+$",
        "description": "Alphanumeric, periods, underscores, hyphens, parentheses, 1-90 chars",
    },
}

# Valid environment values
VALID_ENVIRONMENTS = {"dev", "staging", "test", "qa", "prod", "uat", "sandbox"}


class NamingValidator:
    """Validates Azure resource names against CAF naming conventions."""

    def __init__(self, convention: str = "{abbreviation}-{workload}-{env}-{region}-{instance}",
                 delimiter: str = "-", enforce_lowercase: bool = True):
        self.convention = convention
        self.delimiter = delimiter
        self.enforce_lowercase = enforce_lowercase

    def validate_name(self, resource_type: str, resource_name: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a resource name against CAF conventions.

        Returns:
            (is_valid, error_message)
        """
        expected_prefix = CAF_ABBREVIATIONS.get(resource_type)

        # Check lowercase
        if self.enforce_lowercase and resource_name != resource_name.lower():
            # Storage accounts and some resources require lowercase
            if resource_type in NAMING_RESTRICTIONS:
                restriction = NAMING_RESTRICTIONS[resource_type]
                if not re.match(restriction["pattern"], resource_name):
                    return False, f"Name does not match Azure restrictions: {restriction['description']}"

        # Check Azure-specific restrictions
        if resource_type in NAMING_RESTRICTIONS:
            restriction = NAMING_RESTRICTIONS[resource_type]
            if len(resource_name) < restriction["min_length"]:
                return False, f"Name too short (min {restriction['min_length']} chars)"
            if len(resource_name) > restriction["max_length"]:
                return False, f"Name too long (max {restriction['max_length']} chars)"
            if not re.match(restriction["pattern"], resource_name):
                return False, f"Name does not match: {restriction['description']}"

        # Check CAF prefix
        if expected_prefix:
            if self.delimiter in resource_name:
                parts = resource_name.split(self.delimiter)
                if parts[0] != expected_prefix:
                    return False, (
                        f"Expected CAF prefix '{expected_prefix}' for {resource_type}, "
                        f"got '{parts[0]}'"
                    )
            elif resource_type != "azurerm_storage_account":
                # Storage accounts can't use hyphens, so prefix check is different
                if not resource_name.startswith(expected_prefix):
                    return False, (
                        f"Expected name to start with CAF abbreviation '{expected_prefix}' "
                        f"for {resource_type}"
                    )

        return True, None

    def check_environment_component(self, name: str) -> Tuple[bool, Optional[str]]:
        """Check if the name contains a valid environment component."""
        parts = name.split(self.delimiter)
        for part in parts:
            if part.lower() in VALID_ENVIRONMENTS:
                return True, None
        return False, f"No recognized environment component in name (expected one of: {', '.join(sorted(VALID_ENVIRONMENTS))})"
