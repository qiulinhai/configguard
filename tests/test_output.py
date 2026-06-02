"""Tests for ConfigGuard output generators."""
import pytest
import json
from configguard.output.json import generate_json_report
from configguard.output.markdown import generate_markdown_report
from configguard.models import Finding, Severity, FindingStatus
from configguard.risk.engine import RiskEngine
from configguard.risk.model import RiskLevel, RiskScore, RiskEngineResult

FINDINGS = [
    Finding(
        rule_id="CISCO-MGMT-001",
        rule_name="Disable Telnet",
        category="management-plane",
        severity=Severity.HIGH,
        status=FindingStatus.FAIL,
        evidence="transport input telnet ssh",
    )
]

def test_json_report_structure():
    report = generate_json_report(
        findings=FINDINGS,
        config_name="test_config.txt",
        rules_version="0.1.0",
    )
    data = json.loads(report)

    assert data["version"] == "0.1.0"
    assert data["summary"]["total"] == 1
    assert data["summary"]["fail"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "CISCO-MGMT-001"

def test_markdown_report_structure():
    report = generate_markdown_report(FINDINGS, "test_config.txt")
    assert "# ConfigGuard Security Audit Report" in report
    assert "## Summary" in report
    assert "Disable Telnet" in report
    assert "[HIGH] Disable Telnet" in report


# ---------- Markdown report: compliance block ----------

def test_markdown_report_without_risk_result_omits_compliance_block():
    """Backward-compat: no risk_result means no compliance block."""
    report = generate_markdown_report(FINDINGS, "test_config.txt")
    assert "## Compliance Assessment" not in report

def test_markdown_report_with_risk_result_includes_compliance_block():
    risk = _synthetic_risk_result(FINDINGS)
    report = generate_markdown_report(FINDINGS, "test_config.txt", risk_result=risk)
    assert "## Compliance Assessment" in report
    assert "Overall Status:" in report
    assert "Compliance Score:" in report
    assert "Risk Areas:" in report

def test_markdown_report_compliance_status_uses_icon_for_failures():
    risk = _synthetic_risk_result(FINDINGS)  # 1 FAIL
    report = generate_markdown_report(FINDINGS, "test_config.txt", risk_result=risk)
    assert "NON-COMPLIANT" in report
    assert "❌" in report

def test_markdown_report_compliance_status_uses_icon_for_clean():
    pass_finding = Finding(
        rule_id="CISCO-AUTH-001",
        rule_name="AAA Required",
        category="authentication",
        severity=Severity.HIGH,
        status=FindingStatus.PASS,
        evidence="aaa new-model configured",
    )
    risk = _synthetic_risk_result([pass_finding])
    report = generate_markdown_report([pass_finding], "clean.txt", risk_result=risk)
    assert "COMPLIANT" in report
    assert "✅" in report

def test_markdown_report_compliance_block_appears_before_summary():
    """The compliance summary is the headline — it must come before the raw counts."""
    risk = _synthetic_risk_result(FINDINGS)
    report = generate_markdown_report(FINDINGS, "test_config.txt", risk_result=risk)
    compliance_idx = report.index("## Compliance Assessment")
    summary_idx = report.index("## Summary")
    assert compliance_idx < summary_idx

def test_markdown_report_compliance_score_uses_over_100_format():
    risk = _synthetic_risk_result(FINDINGS)
    report = generate_markdown_report(FINDINGS, "test_config.txt", risk_result=risk)
    assert "/100" in report


# ---------- JSON report: compliance block ----------

def _synthetic_risk_result(findings):
    """Build a RiskEngineResult by running the real engine (smallest faithful option)."""
    return RiskEngine().evaluate(findings)

def test_json_report_without_risk_result_omits_compliance_block():
    """When no risk_result is passed (backward compat), no compliance fields appear."""
    report = generate_json_report(
        findings=FINDINGS,
        config_name="test_config.txt",
        rules_version="0.1.0",
    )
    data = json.loads(report)
    assert "compliance" not in data
    assert "risk_assessment" not in data

def test_json_report_with_risk_result_includes_compliance_block():
    risk = _synthetic_risk_result(FINDINGS)
    report = generate_json_report(
        findings=FINDINGS,
        config_name="test_config.txt",
        rules_version="0.1.0",
        risk_result=risk,
    )
    data = json.loads(report)
    assert "compliance" in data
    assert "risk_assessment" in data

def test_json_report_compliance_block_shape():
    risk = _synthetic_risk_result(FINDINGS)
    data = json.loads(generate_json_report(
        findings=FINDINGS,
        config_name="test_config.txt",
        rules_version="0.1.0",
        risk_result=risk,
    ))
    block = data["compliance"]
    assert set(block.keys()) == {"status", "score", "level", "risk_areas"}
    assert block["status"] in ("COMPLIANT", "NON-COMPLIANT")
    assert isinstance(block["score"], int)
    assert 0 <= block["score"] <= 100
    assert block["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(block["risk_areas"], list)

def test_json_report_compliance_status_non_compliant_when_failures():
    risk = _synthetic_risk_result(FINDINGS)  # one FAIL
    data = json.loads(generate_json_report(
        findings=FINDINGS,
        config_name="test_config.txt",
        rules_version="0.1.0",
        risk_result=risk,
    ))
    assert data["compliance"]["status"] == "NON-COMPLIANT"

def test_json_report_compliance_status_compliant_when_no_failures():
    pass_finding = Finding(
        rule_id="CISCO-AUTH-001",
        rule_name="AAA Required",
        category="authentication",
        severity=Severity.HIGH,
        status=FindingStatus.PASS,
        evidence="aaa new-model configured",
    )
    risk = _synthetic_risk_result([pass_finding])
    data = json.loads(generate_json_report(
        findings=[pass_finding],
        config_name="clean.txt",
        rules_version="0.1.0",
        risk_result=risk,
    ))
    assert data["compliance"]["status"] == "COMPLIANT"

def test_json_report_risk_assessment_block_shape():
    risk = _synthetic_risk_result(FINDINGS)
    data = json.loads(generate_json_report(
        findings=FINDINGS,
        config_name="test_config.txt",
        rules_version="0.1.0",
        risk_result=risk,
    ))
    block = data["risk_assessment"]
    assert set(block.keys()) == {
        "score", "level", "finding_count",
        "severity_breakdown", "category_breakdown", "context_coverage",
    }
    assert isinstance(block["severity_breakdown"], dict)
    assert isinstance(block["category_breakdown"], dict)
    assert isinstance(block["context_coverage"], int)
