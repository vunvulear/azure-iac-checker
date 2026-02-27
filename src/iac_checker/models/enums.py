"""Enumerations for severity levels, WAF pillars, and CAF domains."""

from enum import Enum


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (lower = more severe)."""
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }[self]

    @property
    def emoji(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
        }[self]


class Pillar(Enum):
    RELIABILITY = "Reliability"
    SECURITY = "Security"
    COST_OPTIMIZATION = "Cost Optimization"
    OPERATIONAL_EXCELLENCE = "Operational Excellence"
    PERFORMANCE_EFFICIENCY = "Performance Efficiency"
    SERVICE_GUIDES = "Service Guides"


class CafDomain(Enum):
    NAMING = "Naming Conventions"
    TAGGING = "Tagging Strategy"
    LANDING_ZONE = "Landing Zone & Subscription"
    NETWORKING = "Networking"
    IDENTITY = "Identity & Access"
    GOVERNANCE = "Governance & Policy"
