"""Abstract base reporter interface."""

from abc import ABC, abstractmethod
from typing import List

from iac_checker.models.finding import Finding


class BaseReporter(ABC):
    @abstractmethod
    def generate(self, findings: List[Finding]) -> str:
        """Generate the report content as a string."""
        ...
