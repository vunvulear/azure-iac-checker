"""Bicep parser — transpiles .bicep files to ARM JSON, then parses them."""

import logging
import subprocess
from pathlib import Path
from typing import Optional

from iac_checker.parser.base_parser import BaseParser
from iac_checker.parser.arm.arm_parser import ArmParser
from iac_checker.parser.parsed_file import ParsedFile

logger = logging.getLogger(__name__)


class BicepParser(BaseParser):
    """Parser for Bicep files — transpiles to ARM JSON then delegates to ArmParser."""

    def __init__(self, bicep_cli_path: str = "bicep"):
        self._bicep_cli = bicep_cli_path
        self._arm_parser = ArmParser()
        self._bicep_available: Optional[bool] = None

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == ".bicep"

    def is_bicep_cli_available(self) -> bool:
        """Check if the Bicep CLI is installed and accessible."""
        if self._bicep_available is not None:
            return self._bicep_available

        # Try "bicep --version" first, then "az bicep version"
        for cmd in ([self._bicep_cli, "--version"], ["az", "bicep", "version"]):
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    self._bicep_available = True
                    # If "az bicep" works, use that as the build command
                    if cmd[0] == "az":
                        self._bicep_cli = "az_bicep"
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        self._bicep_available = False
        logger.warning(
            "Bicep CLI not found. Install with 'az bicep install' or "
            "download from https://github.com/Azure/bicep/releases. "
            "Skipping .bicep files."
        )
        return False

    def parse_file(self, file_path: Path) -> Optional[ParsedFile]:
        if not self.is_bicep_cli_available():
            return None

        try:
            # Transpile .bicep → ARM JSON
            arm_json = self._transpile_to_arm(file_path)
            if arm_json is None:
                return None

            # Parse the ARM JSON using ArmParser
            parsed = self._arm_parser.parse_arm_string(arm_json, file_path)
            if parsed is None:
                return None

            # Replace raw_lines with original .bicep content (for suppression comment parsing)
            original_text = file_path.read_text(encoding="utf-8")
            parsed.raw_lines = original_text.splitlines()

            return parsed
        except Exception as e:
            logger.warning("Failed to parse Bicep file %s: %s", file_path, e)
            return None

    def _transpile_to_arm(self, file_path: Path) -> Optional[str]:
        """Transpile a .bicep file to ARM JSON string using the Bicep CLI."""
        try:
            if self._bicep_cli == "az_bicep":
                cmd = ["az", "bicep", "build", "--file", str(file_path), "--stdout"]
            else:
                cmd = [self._bicep_cli, "build", str(file_path), "--stdout"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                return result.stdout

            logger.warning(
                "Bicep build failed for %s: %s",
                file_path, result.stderr.strip()
            )
            return None
        except subprocess.TimeoutExpired:
            logger.warning("Bicep build timed out for %s", file_path)
            return None
        except FileNotFoundError:
            logger.warning("Bicep CLI not found at '%s'", self._bicep_cli)
            self._bicep_available = False
            return None
