"""Risk Scoring Model v0.4 — Composite Risk with Attack Path Integration.

v0.4 Risk Model builds on v0.3 by integrating attack path information from the
SecurityKnowledgeGraph to compute composite risk scores that reflect:

1. Base Severity: Intrinsic severity of the security issue
2. Attack Path Depth: How many hops from initial exposure to target
3. Exposure Multiplier: How reachable is the vulnerable resource
4. Privilege Gain Weight: What privileges does an attacker gain
5. Cross-Domain Chain Bonus: Multi-domain attack chains are more severe
6. Business Impact: Mapping to CIS/NIST controls

Risk Formula:
    composite_risk = normalize(
        base_severity * severity_weight
        + attack_path_depth_factor * path_length
        + exposure_multiplier * reachability
        + privilege_gain_weight * privilege_score
        + cross_domain_bonus * domain_count
        + business_impact_factor
    )

Mathematical Properties:
    - Deterministic: same inputs always produce same score
    - Bounded: [0, 100]
    - Monotonic: more severe conditions → higher score
    - Explainable: each component is individually visible
    - Adjustable: weights are tunable via configuration

Usage:
    from configguard.risk.v04 import CompositeRiskEngine

    engine = CompositeRiskEngine()
    risk_result = engine.evaluate(findings, kg=knowledge_graph)
    print(risk_result.composite_score)  # 0-100
    print(risk_result.risk_factors)      # Breakdown by factor
    print(risk_result.attack_paths)      # Top attack paths by risk
"""
from dataclasses import dataclass, field
from typing import TypedDict
from enum import Enum
from typing import Optional
from pydantic import BaseModel


class RiskLevel(str, Enum):
    """Risk level classification."""
    CRITICAL = "CRITICAL"   # Score >= 85
    HIGH = "HIGH"          # Score >= 65
    MEDIUM = "MEDIUM"       # Score >= 40
    LOW = "LOW"             # Score >= 20
    INFO = "INFO"           # Score < 20


class RiskFactor(TypedDict):
    """A component of the composite risk score."""
    name: str           # e.g., "attack_path_depth"
    value: float         # Raw value before weighting
    weight: float        # Weight multiplier
    contribution: float # value * weight
    description: str     # Human-readable explanation


class AttackPathRisk(TypedDict):
    """Risk assessment for a specific attack path."""
    path_id: str
    path_length: int
    entry_point: str
    terminal_node: str
    risk_score: int
    relationship_chain: list[str]
    privilege_gain: int          # 0-10
    cross_domain: bool
    business_impact: str | None


class CompositeRiskResult(BaseModel):
    """Complete composite risk assessment result v0.4."""
    composite_score: int                    # 0-100
    risk_level: RiskLevel
    risk_factors: list[RiskFactor]          # Breakdown by factor
    attack_paths: list[AttackPathRisk]     # Top attack paths
    top_risk_finding_id: str | None
    exposure_score: int                     # 0-100
    privilege_score: int                    # 0-100
    business_impact_score: int             # 0-100
    metadata: dict


# ---------------------------------------------------------------------------
# Risk Formula Constants
# ---------------------------------------------------------------------------
# Severity weights (base contribution)
SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 20,
    "LOW": 10,
    "INFO": 5,
}

# Attack path depth weights
PATH_DEPTH_WEIGHTS: dict[int, float] = {
    1: 0,      # Single resource, no path
    2: 10,     # One hop
    3: 20,     # Two hops
    4: 30,     # Three hops
    5: 40,     # Four+ hops (capped)
}

# Exposure multipliers (how reachable is the resource)
EXPOSURE_MULTIPLIERS: dict[str, float] = {
    "internet-exposed": 1.5,
    "mgmt-plane": 1.3,
    "internal": 1.0,
    "isolated": 0.8,
    "air-gapped": 0.5,
}

# Privilege gain weights (what does attacker gain)
PRIVILEGE_GAIN_WEIGHTS: dict[str, float] = {
    "admin": 30,           # Full admin access
    "write": 20,            # Write access to config
    "read": 10,             # Read access to sensitive data
    "execute": 15,          # Execute code
    "none": 0,              # No privilege gain
}

# Cross-domain bonus (multi-domain attack chains)
CROSS_DOMAIN_BONUS: float = 15.0  # Per additional domain

# Business impact weights (CIS/NIST mapping)
BUSINESS_IMPACT_WEIGHTS: dict[str, float] = {
    "confidentiality": 20,
    "integrity": 25,
    "availability": 15,
    "compliance": 20,
}

# Maximum values for normalization
MAX_BASE_SCORE = 100
MAX_PATH_SCORE = 50
MAX_EXPOSURE_SCORE = 30
MAX_PRIVILEGE_SCORE = 40
MAX_BUSINESS_SCORE = 30
MAX_TOTAL = MAX_BASE_SCORE + MAX_PATH_SCORE + MAX_EXPOSURE_SCORE + MAX_PRIVILEGE_SCORE + MAX_BUSINESS_SCORE
