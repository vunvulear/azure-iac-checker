"""Azure resource model — parsed from Terraform HCL, ARM JSON, or Bicep."""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class TerraformResource:
    resource_type: str
    name: str
    attributes: Dict[str, Any]
    file_path: str
    line_number: int
    block_type: str = "resource"  # resource, data, module, variable, output, provider
    source_format: str = "terraform"  # terraform, arm, bicep

    @property
    def fqn(self) -> str:
        """Fully qualified name: e.g., azurerm_storage_account.main"""
        return f"{self.resource_type}.{self.name}"

    def get_attribute(self, key: str, default: Any = None) -> Any:
        """Get a nested attribute using dot notation: 'network_rules.default_action'"""
        keys = key.split(".")
        value = self.attributes
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            elif isinstance(value, list) and value:
                value = value[0].get(k, default) if isinstance(value[0], dict) else default
            else:
                return default
        return value

    def has_attribute(self, key: str) -> bool:
        """Check if an attribute exists (even if value is None/empty)."""
        return self.get_attribute(key, _SENTINEL) is not _SENTINEL


_SENTINEL = object()
