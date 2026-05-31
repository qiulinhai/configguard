"""Risk scoring models for v0.3."""
from enum import Enum
from typing import Optional
from pydantic import BaseModel


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskScore(BaseModel):
    """Risk score output from RiskEngine.

    This is computed from findings - it does NOT modify or replace findings.
    RiskEngine is a pure post-processing layer.
    """
    score: int  # 0-100
    level: RiskLevel
    finding_count: int
    severity_breakdown: dict[str, int]  # e.g., {"HIGH": 2, "MEDIUM": 1}
    category_breakdown: dict[str, int]  # e.g., {"snmp-security": 30, "management-plane": 25}
    context_coverage: int  # number of unique contexts with findings


class RiskEngineResult(BaseModel):
    """Complete risk evaluation result."""
    risk_score: RiskScore
    findings: list  # original findings (unchanged)
    device_type: str = "Cisco IOS"  # extensible
    evaluation_metadata: dict  # scoring details