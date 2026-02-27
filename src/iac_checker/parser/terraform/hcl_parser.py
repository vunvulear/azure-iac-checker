"""HCL parser — parses Terraform files using python-hcl2."""

import logging
from pathlib import Path
from typing import List, Optional

import hcl2

from iac_checker.parser.parsed_file import ParsedFile
from iac_checker.parser.base_parser import BaseParser

logger = logging.getLogger(__name__)


class HclParser(BaseParser):
    """Parser for Terraform HCL (.tf, .tfvars) files."""

    _HCL_EXTENSIONS = {".tf", ".tfvars"}

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self._HCL_EXTENSIONS

    def parse_file(self, file_path: Path) -> Optional[ParsedFile]:
        """Parse a single Terraform file."""
        try:
            raw_text = file_path.read_text(encoding="utf-8")
            raw_lines = raw_text.splitlines()

            with open(file_path, "r", encoding="utf-8") as f:
                content = hcl2.load(f)

            return ParsedFile(
                file_path=file_path,
                content=content,
                raw_lines=raw_lines,
                source_format="terraform",
            )
        except Exception as e:
            logger.warning("Failed to parse %s: %s", file_path, e)
            return None
