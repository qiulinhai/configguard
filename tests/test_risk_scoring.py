"""Unit tests for configguard.risk.scoring — pure scoring functions."""
import pytest

from configguard.models import Finding, FindingStatus, Severity
from configguard.risk.scoring import (
    BASE_WEIGHTS,
    CATEGORY_MULTIPLIERS,
    compute_base_score,
    compute_category_breakdown,
    compute_context_coverage,
    compute_context_multiplier,
    compute_risk_level,
    compute_severity_breakdown,
    normalize_score,
)


def make_finding(severity: Severity, category: str = "logging", block_name: str | None = None) -> Finding:
    return Finding(
        rule_id="TEST-001",
        rule_name="Test rule",
        category=category,
        severity=severity,
        status=FindingStatus.FAIL,
        evidence="evidence text",
        block_name=block_name,
    )


class TestNormalizeScore:
    def test_negative_returns_zero(self):
        assert normalize_score(-5) == 0

    def test_zero_returns_zero(self):
        assert normalize_score(0) == 0

    def test_value_in_range_passes_through(self):
        assert normalize_score(42) == 42

    def test_above_100_capped_at_100(self):
        assert normalize_score(150) == 100
        assert normalize_score(100) == 100


class TestComputeRiskLevel:
    @pytest.mark.parametrize("score,expected", [
        (0, "LOW"),
        (24, "LOW"),
        (25, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (74, "HIGH"),
        (75, "CRITICAL"),
        (100, "CRITICAL"),
    ])
    def test_thresholds(self, score, expected):
        assert compute_risk_level(score) == expected


class TestComputeBaseScore:
    def test_empty_findings_returns_zero(self):
        assert compute_base_score([]) == 0

    def test_single_high_finding_in_management_plane(self):
        # HIGH=10 * mgmt-plane multiplier 1.5 = 15
        f = make_finding(Severity.HIGH, category="management-plane")
        assert compute_base_score([f]) == 15

    def test_multiple_findings_sum_weights(self):
        findings = [
            make_finding(Severity.HIGH, category="management-plane"),  # 10 * 1.5 = 15
            make_finding(Severity.MEDIUM, category="authentication"),  # 5 * 1.3 = 6
            make_finding(Severity.LOW, category="logging"),  # 1 * 1.0 = 1
        ]
        assert compute_base_score(findings) == 22

    def test_unknown_category_defaults_to_multiplier_one(self):
        f = make_finding(Severity.HIGH, category="some-unknown-category")
        assert compute_base_score([f]) == 10

    def test_unknown_severity_contributes_zero(self):
        # INFO is not in BASE_WEIGHTS, so contributes 0
        f = make_finding(Severity.INFO, category="management-plane")
        assert compute_base_score([f]) == 0


class TestComputeContextMultiplier:
    def test_empty_findings_returns_zero(self):
        assert compute_context_multiplier([]) == 0.0

    def test_single_finding_single_context_returns_one(self):
        f = make_finding(Severity.HIGH, block_name="vty_0_4")
        assert compute_context_multiplier([f]) == 1.0

    def test_findings_without_block_name_ignored(self):
        # Findings with block_name=None should not contribute to context counts
        findings = [
            make_finding(Severity.HIGH, block_name=None),
            make_finding(Severity.HIGH, block_name=None),
        ]
        assert compute_context_multiplier(findings) == 1.0

    def test_fragmented_contexts_increase_multiplier(self):
        # 4 findings across 3 contexts → finding_count(4) > unique_contexts(3) triggers branch
        # multiplier = 1.0 + 0.1 * (3 - 1) = 1.2
        findings = [
            make_finding(Severity.HIGH, block_name="ctx_a"),
            make_finding(Severity.HIGH, block_name="ctx_a"),
            make_finding(Severity.HIGH, block_name="ctx_b"),
            make_finding(Severity.HIGH, block_name="ctx_c"),
        ]
        assert compute_context_multiplier(findings) == pytest.approx(1.2)

    def test_consolidated_contexts_keep_multiplier_one(self):
        # 3 findings in same context, finding_count (3) == unique_contexts (1)
        # so the "fragmented" branch is not taken
        findings = [
            make_finding(Severity.HIGH, block_name="ctx_a"),
            make_finding(Severity.HIGH, block_name="ctx_a"),
            make_finding(Severity.HIGH, block_name="ctx_a"),
        ]
        assert compute_context_multiplier(findings) == 1.0


class TestComputeSeverityBreakdown:
    def test_empty_returns_empty_dict(self):
        assert compute_severity_breakdown([]) == {}

    def test_groups_and_sums_weights_by_severity(self):
        findings = [
            make_finding(Severity.HIGH),
            make_finding(Severity.HIGH),
            make_finding(Severity.MEDIUM),
        ]
        result = compute_severity_breakdown(findings)
        assert result == {"HIGH": 20, "MEDIUM": 5}

    def test_severity_breakdown_matches_base_weights(self):
        # Verify the breakdown uses the same weights as BASE_WEIGHTS
        findings = [make_finding(Severity.LOW)]
        result = compute_severity_breakdown(findings)
        assert result == {"LOW": BASE_WEIGHTS["LOW"]}


class TestComputeCategoryBreakdown:
    def test_empty_returns_empty_dict(self):
        assert compute_category_breakdown([]) == {}

    def test_groups_by_category_with_multipliers(self):
        findings = [
            make_finding(Severity.HIGH, category="management-plane"),  # 10 * 1.5 = 15
            make_finding(Severity.MEDIUM, category="management-plane"),  # 5 * 1.5 = 7
            make_finding(Severity.LOW, category="logging"),  # 1 * 1.0 = 1
        ]
        result = compute_category_breakdown(findings)
        assert result == {"management-plane": 22, "logging": 1}


class TestComputeContextCoverage:
    def test_empty_returns_zero(self):
        assert compute_context_coverage([]) == 0

    def test_unique_contexts_counted(self):
        findings = [
            make_finding(Severity.HIGH, block_name="ctx_a"),
            make_finding(Severity.HIGH, block_name="ctx_a"),
            make_finding(Severity.HIGH, block_name="ctx_b"),
            make_finding(Severity.HIGH, block_name="ctx_c"),
        ]
        assert compute_context_coverage(findings) == 3

    def test_findings_without_block_name_ignored(self):
        findings = [
            make_finding(Severity.HIGH, block_name=None),
            make_finding(Severity.HIGH, block_name=None),
        ]
        assert compute_context_coverage(findings) == 0

    def test_uses_known_multipliers(self):
        # Sanity check: the constants we depend on haven't drifted
        assert CATEGORY_MULTIPLIERS["management-plane"] == 1.5
        assert BASE_WEIGHTS["HIGH"] == 10
