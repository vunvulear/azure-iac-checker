"""IaC file scanner — recursively discovers .tf, .tfvars, .json (ARM), and .bicep files."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# Extension → format mapping
_EXTENSION_FORMATS: Dict[str, str] = {
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".json": "arm",
    ".bicep": "bicep",
}

# Format → extensions mapping
_FORMAT_EXTENSIONS: Dict[str, Set[str]] = {
    "terraform": {".tf", ".tfvars"},
    "arm": {".json"},
    "bicep": {".bicep"},
}


class IacScanner:
    """Multi-format IaC file scanner for Terraform, ARM, and Bicep."""

    def __init__(self, root_path: Path, exclude_paths: List[str] = None,
                 formats: Set[str] = None):
        self.root_path = root_path
        self.exclude_paths = exclude_paths or []
        self.formats = formats or {"terraform", "arm", "bicep"}

    def discover(self) -> Dict[str, List[Path]]:
        """Discover all IaC files grouped by format.

        Returns: {"terraform": [...], "arm": [...], "bicep": [...]}
        """
        result: Dict[str, List[Path]] = {fmt: [] for fmt in self.formats}

        # Build the set of extensions to look for
        extensions: Set[str] = set()
        for fmt in self.formats:
            extensions.update(_FORMAT_EXTENSIONS.get(fmt, set()))

        for path in self.root_path.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in extensions:
                continue
            if self._is_excluded(path):
                continue

            fmt = _EXTENSION_FORMATS.get(path.suffix.lower())
            if fmt is None or fmt not in self.formats:
                continue

            # For .json files, check if it's actually an ARM template
            if fmt == "arm" and not self._is_arm_template(path):
                continue

            result[fmt].append(path)

        for fmt in result:
            result[fmt] = sorted(result[fmt])

        return result

    def _is_excluded(self, path: Path) -> bool:
        """Check if a file path matches any exclusion pattern."""
        rel_path = str(path.relative_to(self.root_path)).replace("\\", "/")
        for exclude in self.exclude_paths:
            exclude_normalized = exclude.rstrip("/")
            if rel_path.startswith(exclude_normalized):
                return True
        return False

    @staticmethod
    def _is_arm_template(path: Path) -> bool:
        """Check if a JSON file is an ARM template (has management.azure.com schema)."""
        try:
            text = path.read_text(encoding="utf-8")
            if "schema.management.azure.com" not in text:
                return False
            data = json.loads(text)
            schema = data.get("$schema", "")
            return "schema.management.azure.com" in schema
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return False


# Backward-compatible alias
TerraformScanner = IacScanner
