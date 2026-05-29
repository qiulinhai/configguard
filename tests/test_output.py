"""Tests for ConfigGuard output generators."""
import pytest
import json
from configguard.output.json import generate_json_report
from configguard.output.markdown import generate_markdown_report
from configguard.models import Finding, Severity, FindingStatus

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