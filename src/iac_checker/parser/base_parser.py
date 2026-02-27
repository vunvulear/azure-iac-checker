"""Abstract base parser — all IaC format parsers inherit from this."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from iac_checker.parser.parsed_file import ParsedFile


class BaseParser(ABC):
    """Abstract base for all IaC parsers (Terraform HCL, ARM JSON, Bicep)."""

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Return True if this parser handles the given file."""
        ...

    @abstractmethod
    def parse_file(self, file_path: Path) -> Optional[ParsedFile]:
        """Parse a single file into a ParsedFile."""
        ...

    def parse_files(self, file_paths: List[Path]) -> List[ParsedFile]:
        """Parse a list of files, returning only successfully parsed ones."""
        parsed = []
        for path in file_paths:
            if self.can_parse(path):
                result = self.parse_file(path)
                if result:
                    parsed.append(result)
        return parsed
