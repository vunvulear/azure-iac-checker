"""ParsedFile model — represents a parsed IaC file with its content and metadata."""

from pathlib import Path
from typing import Any, Dict, List


class ParsedFile:
    """Represents a parsed IaC file (Terraform HCL, ARM JSON, or Bicep) with its content and metadata."""

    def __init__(self, file_path: Path, content: Dict[str, Any], raw_lines: List[str],
                 source_format: str = "terraform"):
        self.file_path = file_path
        self.content = content
        self.raw_lines = raw_lines
        self.source_format = source_format

    def find_line_number(self, block_type: str, resource_type: str, name: str) -> int:
        """Find the approximate line number for a resource block."""
        if block_type == "resource":
            pattern = f'resource "{resource_type}" "{name}"'
        elif block_type == "data":
            pattern = f'data "{resource_type}" "{name}"'
        elif block_type == "module":
            pattern = f'module "{name}"'
        elif block_type == "variable":
            pattern = f'variable "{name}"'
        elif block_type == "output":
            pattern = f'output "{name}"'
        else:
            pattern = f'{block_type} "{name}"'

        for i, line in enumerate(self.raw_lines, start=1):
            if pattern in line:
                return i
        return 1
