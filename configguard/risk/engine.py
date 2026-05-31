"""Risk Engine - post-processing layer for risk scoring.

v0.3 Risk Engine is a PURE post-processing layer:
- Reads findings from RuleEngine (unchanged)
- Computes risk score without modifying findings
- Returns structured RiskScore output
- Deterministic: same input findings always produce same score
"""
from configguard.models import Finding
from configguard.risk.model import RiskScore, RiskLevel, RiskEngineResult
from configguard.risk.scoring import (
    compute_base_score,
    compute_context_multiplier,
    normalize_score,
    compute_risk_level,
    compute_severity_breakdown,
    compute_category_breakdown,
    compute_context_coverage,
)


class RiskEngine:
    """Compute risk score from findings.

    This is a post-processing layer - it does NOT:
    - Generate new findings
    - Modify existing findings
    - Replace rule evaluation
    - Introduce non-determinism

    Usage:
        findings = engine.evaluate_with_contexts(contexts, rules)
        risk_result = risk_engine.evaluate(findings)
        print(risk_result.risk_score.score)
    """

    def evaluate(self, findings: list[Finding]) -> RiskEngineResult:
        """Evaluate risk score from findings.

        Args:
            findings: List of Finding objects from RuleEngine

        Returns:
            RiskEngineResult with risk score and breakdowns
        """
        if not findings:
            return self._empty_result(findings)

        # Compute base score
        base_score = compute_base_score(findings)

        # Apply context multiplier
        context_mult = compute_context_multiplier(findings)
        raw_score = int(base_score * context_mult)

        # Normalize to 0-100
        normalized = normalize_score(raw_score)

        # Determine risk level
        level = compute_risk_level(normalized)

        # Build breakdowns
        severity_breakdown = compute_severity_breakdown(findings)
        category_breakdown = compute_category_breakdown(findings)
        context_coverage = compute_context_coverage(findings)

        risk_score = RiskScore(
            score=normalized,
            level=RiskLevel(level),
            finding_count=len(findings),
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
            context_coverage=context_coverage,
        )

        return RiskEngineResult(
            risk_score=risk_score,
            findings=[f.model_dump() for f in findings],
            evaluation_metadata={
                "base_score": base_score,
                "context_multiplier": context_mult,
                "raw_score": raw_score,
                "normalization_applied": raw_score != normalized,
            },
        )

    def _empty_result(self, findings: list[Finding]) -> RiskEngineResult:
        """Return empty result when no findings."""
        return RiskEngineResult(
            risk_score=RiskScore(
                score=0,
                level=RiskLevel("LOW"),
                finding_count=0,
                severity_breakdown={},
                category_breakdown={},
                context_coverage=0,
            ),
            findings=[f.model_dump() for f in findings],
            evaluation_metadata={
                "base_score": 0,
                "context_multiplier": 0,
                "raw_score": 0,
            },
        )