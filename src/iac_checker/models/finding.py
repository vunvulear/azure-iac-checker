"""Finding model — represents a single compliance violation or pass."""

from dataclasses import dataclass, field
from typing import Optional

from iac_checker.models.enums import Severity


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: Severity
    file_path: str
    line_number: int
    resource_type: str
    resource_name: str
    recommendation: str
    doc_url: str
    waf_ref: str = ""
    caf_ref: str = ""
    passed: bool = False
    suppressed: bool = False
    suppression_reason: str = ""

    @property
    def location(self) -> str:
        return f"{self.file_path}:{self.line_number}"

    @property
    def resource_fqn(self) -> str:
        return f"{self.resource_type}.{self.resource_name}"

    @property
    def framework_ref(self) -> str:
        """Return the WAF or CAF reference ID."""
        return self.waf_ref or self.caf_ref or "—"
