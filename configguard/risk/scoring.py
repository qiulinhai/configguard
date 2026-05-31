"""Risk scoring logic for v0.3.

This module contains pure scoring functions - no side effects,
no external dependencies, deterministic output.
"""
from typing import TypedDict

from configguard.models import Finding, Severity


class SeverityWeight(TypedDict):
    """Base weights for severity levels."""
    HIGH: int
    MEDIUM: int
    LOW: int
    INFO: int


# Base severity weights (configurable)
BASE_WEIGHTS: SeverityWeight = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 1,
    "INFO": 0,
}

# Category multipliers (management-plane issues are more critical)
CATEGORY_MULTIPLIERS: dict[str, float] = {
    "management-plane": 1.5,
    "authentication": 1.3,
    "snmp-security": 1.2,
    "interface-hygiene": 1.0,
    "logging": 1.0,
}


def compute_base_score(findings: list[Finding]) -> int:
    """Compute base risk score from findings.

    Score = sum of (severity_weight * category_multiplier) for each finding
    """
    total = 0
    for finding in findings:
        severity_weight = BASE_WEIGHTS.get(finding.severity.value, 0)
        category_mult = CATEGORY_MULTIPLIERS.get(finding.category, 1.0)
        total += int(severity_weight * category_mult)
    return total


def compute_context_multiplier(findings: list[Finding]) -> float:
    """Apply context density multiplier.

    If multiple findings share the same context_key, apply +20% multiplier.
    This rewards holistic security (single context = better posture).
    """
    context_counts: dict[str, int] = {}
    for f in findings:
        if f.block_name:
            ctx = f.block_name
            context_counts[ctx] = context_counts.get(ctx, 0) + 1

    # If findings are spread across many contexts, slightly higher risk
    unique_contexts = len(context_counts)
    finding_count = len(findings)

    if finding_count == 0:
        return 0.0

    # More contexts with fewer findings each = higher multiplier (fragmented risk)
    if unique_contexts > 1 and finding_count > unique_contexts:
        return 1.0 + (0.1 * (unique_contexts - 1))

    return 1.0


def normalize_score(score: int) -> int:
    """Normalize score to 0-100 range.

    Uses sigmoid-like normalization to prevent extreme scores
    while maintaining relative ordering.
    """
    if score <= 0:
        return 0
    if score >= 100:
        return 100
    return score


def compute_risk_level(score: int) -> str:
    """Determine risk level from normalized score."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def compute_severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    """Compute count and weighted score by severity."""
    breakdown: dict[str, int] = {}
    for f in findings:
        weight = BASE_WEIGHTS.get(f.severity.value, 0)
        if f.severity.value not in breakdown:
            breakdown[f.severity.value] = 0
        breakdown[f.severity.value] += weight
    return breakdown


def compute_category_breakdown(findings: list[Finding]) -> dict[str, int]:
    """Compute count and weighted score by category."""
    breakdown: dict[str, int] = {}
    for f in findings:
        weight = BASE_WEIGHTS.get(f.severity.value, 0)
        mult = CATEGORY_MULTIPLIERS.get(f.category, 1.0)
        if f.category not in breakdown:
            breakdown[f.category] = 0
        breakdown[f.category] += int(weight * mult)
    return breakdown


def compute_context_coverage(findings: list[Finding]) -> int:
    """Count unique contexts that have findings."""
    contexts = set()
    for f in findings:
        if f.block_name:
            contexts.add(f.block_name)
    return len(contexts)