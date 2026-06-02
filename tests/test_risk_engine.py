"""Unit tests for configguard.risk.engine — RiskEngine post-processing layer."""
import pytest

from configguard.models import Finding, FindingStatus, Severity
from configguard.risk.engine import RiskEngine


def make_finding(
    severity: Severity,
    category: str = "logging",
    block_name: str | None = None,
) -> Finding:
    return Finding(
        rule_id="TEST-001",
        rule_name="Test rule",
        category=category,
        severity=severity,
        status=FindingStatus.FAIL,
        evidence="evidence",
        block_name=block_name,
    )


class TestEmptyFindings:
    def test_empty_list_returns_low_risk_zero_score(self):
        result = RiskEngine().evaluate([])
        assert result.risk_score.score == 0
        assert result.risk_score.level.value == "LOW"
        assert result.risk_score.finding_count == 0
        assert result.risk_score.severity_breakdown == {}
        assert result.risk_score.category_breakdown == {}
        assert result.risk_score.context_coverage == 0

    def test_empty_result_evaluation_metadata_present(self):
        result = RiskEngine().evaluate([])
        meta = result.evaluation_metadata
        assert meta["base_score"] == 0
        assert meta["context_multiplier"] == 0
        assert meta["raw_score"] == 0

    def test_empty_findings_list_preserved(self):
        result = RiskEngine().evaluate([])
        assert result.findings == []


class TestSingleFinding:
    def test_single_high_in_management_plane(self):
        # HIGH (10) * mgmt-plane (1.5) = 15 → 1.0 multiplier → 15
        findings = [make_finding(Severity.HIGH, category="management-plane")]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 15
        assert result.risk_score.level.value == "LOW"  # 15 < 25
        assert result.risk_score.finding_count == 1

    def test_single_low_finding(self):
        findings = [make_finding(Severity.LOW, category="logging")]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 1
        assert result.risk_score.level.value == "LOW"


class TestMultipleFindings:
    def test_mixed_severities_weight_correctly(self):
        # HIGH mgmt-plane: 10*1.5=15, MEDIUM auth: 5*1.3=6, LOW logging: 1*1.0=1
        # base = 22, single context → multiplier 1.0 → raw 22
        findings = [
            make_finding(Severity.HIGH, category="management-plane", block_name="ctx_a"),
            make_finding(Severity.MEDIUM, category="authentication", block_name="ctx_a"),
            make_finding(Severity.LOW, category="logging", block_name="ctx_a"),
        ]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 22
        assert result.risk_score.severity_breakdown == {"HIGH": 10, "MEDIUM": 5, "LOW": 1}
        assert "management-plane" in result.risk_score.category_breakdown

    def test_findings_split_across_contexts_increases_score(self):
        # 4 HIGH findings across 3 contexts → multiplier 1.2 → inflated score
        # base = 4 * 10 = 40, * 1.2 = 48
        findings = [
            make_finding(Severity.HIGH, block_name="ctx_a"),
            make_finding(Severity.HIGH, block_name="ctx_a"),
            make_finding(Severity.HIGH, block_name="ctx_b"),
            make_finding(Severity.HIGH, block_name="ctx_c"),
        ]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 48
        assert result.risk_score.context_coverage == 3

    def test_score_capped_at_100(self):
        # Build enough findings to exceed 100
        findings = [
            make_finding(Severity.HIGH, category="management-plane")
            for _ in range(20)
        ]
        # base = 20 * 15 = 300 → normalize to 100
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 100
        assert result.risk_score.level.value == "CRITICAL"


class TestRiskLevelThresholds:
    def test_single_high_in_mgmt_plane_is_low(self):
        # 1 HIGH * mgmt-plane(1.5) = 15 → LOW (15 < 25)
        findings = [make_finding(Severity.HIGH, category="management-plane")]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 15
        assert result.risk_score.level.value == "LOW"

    def test_three_high_in_mgmt_plane_is_medium(self):
        # 3 HIGH * mgmt-plane(1.5) = 45 → MEDIUM (25 ≤ 45 < 50)
        findings = [
            make_finding(Severity.HIGH, category="management-plane")
            for _ in range(3)
        ]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 45
        assert result.risk_score.level.value == "MEDIUM"

    def test_four_high_in_mgmt_plane_is_high(self):
        # 4 HIGH * mgmt-plane(1.5) = 60 → HIGH (50 ≤ 60 < 75)
        findings = [
            make_finding(Severity.HIGH, category="management-plane")
            for _ in range(4)
        ]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 60
        assert result.risk_score.level.value == "HIGH"

    def test_five_high_in_mgmt_plane_is_critical(self):
        # 5 HIGH * mgmt-plane(1.5) = 75 → CRITICAL (>= 75)
        findings = [
            make_finding(Severity.HIGH, category="management-plane")
            for _ in range(5)
        ]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 75
        assert result.risk_score.level.value == "CRITICAL"

    def test_saturation_caps_at_100_critical(self):
        # 20 HIGH mgmt-plane = 300, normalized to 100
        findings = [
            make_finding(Severity.HIGH, category="management-plane")
            for _ in range(20)
        ]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.score == 100
        assert result.risk_score.level.value == "CRITICAL"


class TestBreakdowns:
    def test_severity_breakdown_sums_weights(self):
        findings = [
            make_finding(Severity.HIGH),
            make_finding(Severity.HIGH),
            make_finding(Severity.MEDIUM),
        ]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.severity_breakdown == {"HIGH": 20, "MEDIUM": 5}

    def test_category_breakdown_groups_by_category(self):
        findings = [
            make_finding(Severity.HIGH, category="management-plane"),
            make_finding(Severity.LOW, category="logging"),
        ]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.category_breakdown == {
            "management-plane": 15,
            "logging": 1,
        }

    def test_context_coverage_unique_count(self):
        findings = [
            make_finding(Severity.HIGH, block_name="a"),
            make_finding(Severity.HIGH, block_name="a"),
            make_finding(Severity.HIGH, block_name="b"),
        ]
        result = RiskEngine().evaluate(findings)
        assert result.risk_score.context_coverage == 2


class TestEvaluationMetadata:
    def test_metadata_includes_base_and_multiplier(self):
        findings = [make_finding(Severity.HIGH, category="management-plane")]
        result = RiskEngine().evaluate(findings)
        meta = result.evaluation_metadata
        assert meta["base_score"] == 15
        assert meta["context_multiplier"] == 1.0
        assert meta["raw_score"] == 15
        assert meta["normalization_applied"] is False

    def test_findings_are_serialized_in_result(self):
        findings = [make_finding(Severity.HIGH)]
        result = RiskEngine().evaluate(findings)
        assert len(result.findings) == 1
        assert result.findings[0]["rule_id"] == "TEST-001"
        assert result.findings[0]["severity"] == "HIGH"

    def test_result_is_deterministic(self):
        findings = [
            make_finding(Severity.HIGH, block_name="x"),
            make_finding(Severity.MEDIUM, block_name="y"),
        ]
        r1 = RiskEngine().evaluate(findings)
        r2 = RiskEngine().evaluate(findings)
        assert r1.risk_score.score == r2.risk_score.score
        assert r1.risk_score.level == r2.risk_score.level
