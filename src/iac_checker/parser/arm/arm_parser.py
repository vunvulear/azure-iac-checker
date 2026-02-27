"""ARM template parser — parses Azure Resource Manager JSON templates."""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from iac_checker.parser.base_parser import BaseParser
from iac_checker.parser.parsed_file import ParsedFile
from iac_checker.parser.arm.type_mapper import arm_type_to_terraform
from iac_checker.parser.arm.property_mapper import flatten_arm_resource

logger = logging.getLogger(__name__)

ARM_SCHEMA_PREFIX = "https://schema.management.azure.com"


class ArmParser(BaseParser):
    """Parser for ARM template JSON files."""

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() != ".json":
            return False
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            return self._is_arm_template(data)
        except (json.JSONDecodeError, OSError):
            return False

    def parse_file(self, file_path: Path) -> Optional[ParsedFile]:
        try:
            raw_text = file_path.read_text(encoding="utf-8")
            raw_lines = raw_text.splitlines()
            data = json.loads(raw_text)

            if not self._is_arm_template(data):
                return None

            content = self._transform(data, raw_lines)
            return ParsedFile(
                file_path=file_path,
                content=content,
                raw_lines=raw_lines,
            )
        except Exception as e:
            logger.warning("Failed to parse ARM template %s: %s", file_path, e)
            return None

    def parse_arm_string(self, json_string: str, file_path: Path) -> Optional[ParsedFile]:
        """Parse an ARM JSON string directly (used by Bicep parser)."""
        try:
            raw_lines = json_string.splitlines()
            data = json.loads(json_string)
            content = self._transform(data, raw_lines)
            return ParsedFile(
                file_path=file_path,
                content=content,
                raw_lines=raw_lines,
            )
        except Exception as e:
            logger.warning("Failed to parse ARM JSON string for %s: %s", file_path, e)
            return None

    @staticmethod
    def _is_arm_template(data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        schema = data.get("$schema", "")
        return ARM_SCHEMA_PREFIX in str(schema)

    def _transform(self, data: Dict[str, Any], raw_lines: List[str]) -> Dict[str, Any]:
        """Transform ARM JSON into ParsedFile.content matching HCL internal format."""
        content: Dict[str, Any] = {
            "resource": [],
            "variable": [],
            "output": [],
            "data": [],
            "module": [],
            "terraform": [],
        }

        # --- Resources ---
        for arm_res in data.get("resources", []):
            arm_type = arm_res.get("type", "")
            arm_name = arm_res.get("name", "unknown")
            tf_type = arm_type_to_terraform(arm_type)

            # Sanitize name for use as a Terraform-style label
            label = self._sanitize_name(arm_name)

            # Flatten ARM properties → Terraform-like attributes
            attrs = flatten_arm_resource(arm_type, arm_res)

            # Preserve API version as metadata
            api_version = arm_res.get("apiVersion", "")
            if api_version:
                attrs["_api_version"] = api_version

            # Handle ARM metadata-based suppressions
            metadata = arm_res.get("metadata", {})
            if isinstance(metadata, dict):
                waf_ignore = metadata.get("waf-ignore", "")
                caf_ignore = metadata.get("caf-ignore", "")
                if waf_ignore:
                    attrs["_waf_ignore"] = waf_ignore
                if caf_ignore:
                    attrs["_caf_ignore"] = caf_ignore

            # Find line number for this resource in the JSON
            line = self._find_resource_line(raw_lines, arm_type, arm_name)

            # Add as HCL-compatible resource block
            content["resource"].append({tf_type: {label: attrs}})

            # Process nested/child resources
            for child in arm_res.get("resources", []):
                child_type = f"{arm_type}/{child.get('type', '')}"
                child_name = child.get("name", "unknown")
                child_tf_type = arm_type_to_terraform(child_type)
                child_label = self._sanitize_name(f"{label}_{child_name}")
                child_attrs = flatten_arm_resource(child_type, child)
                content["resource"].append({child_tf_type: {child_label: child_attrs}})

        # --- Parameters → Variables ---
        for param_name, param_def in data.get("parameters", {}).items():
            attrs = {}
            if "defaultValue" in param_def:
                attrs["default"] = param_def["defaultValue"]
            if "type" in param_def:
                attrs["type"] = param_def["type"]
            if "metadata" in param_def and isinstance(param_def["metadata"], dict):
                attrs["description"] = param_def["metadata"].get("description", "")
            content["variable"].append({param_name: attrs})

        # --- Outputs ---
        for output_name, output_def in data.get("outputs", {}).items():
            attrs = {}
            if "value" in output_def:
                attrs["value"] = output_def["value"]
            if "type" in output_def:
                attrs["type"] = output_def["type"]
            content["output"].append({output_name: attrs})

        return content

    @staticmethod
    def _sanitize_name(name: str) -> str:
        """Convert an ARM resource name (may contain expressions) into a safe label."""
        # Strip ARM expression markers
        clean = name.strip("[]")
        # Remove common ARM functions
        for func in ("parameters(", "variables(", "concat(", "format(", "resourceId(",
                      "uniqueString(", "toLower(", "toUpper("):
            clean = clean.replace(func, "")
        # Remove quotes and parens
        clean = clean.replace("'", "").replace('"', "").replace("(", "").replace(")", "")
        # Replace non-alphanumeric with underscore
        clean = re.sub(r"[^a-zA-Z0-9]", "_", clean)
        # Collapse multiple underscores and strip
        clean = re.sub(r"_+", "_", clean).strip("_")
        return clean.lower() or "unnamed"

    @staticmethod
    def _find_resource_line(raw_lines: List[str], arm_type: str, arm_name: str) -> int:
        """Find the approximate line number for a resource in the JSON."""
        # Search for the type string
        type_lower = arm_type.lower()
        for i, line in enumerate(raw_lines, start=1):
            if type_lower in line.lower() and "type" in line.lower():
                return i
        # Fallback: search for the name
        for i, line in enumerate(raw_lines, start=1):
            if arm_name in line:
                return i
        return 1
