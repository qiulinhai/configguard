"""Tests for ConfigGuard models."""
import pytest
from configguard.models import Finding, ConfigIR, RuleMatch, Severity, FindingStatus, Block

def test_finding_model():
    finding = Finding(
        rule_id="TEST-001",
        rule_name="Test Rule",
        category="test",
        severity=Severity.HIGH,
        status=FindingStatus.FAIL,
        evidence="some config line",
    )
    assert finding.rule_id == "TEST-001"
    assert finding.severity == Severity.HIGH
    assert finding.status == FindingStatus.FAIL

def test_config_ir_structure():
    ir = ConfigIR(
        raw_lines=["line vty 0 4", "transport input telnet"],
        blocks=[],
        normalized={"services": {"telnet": {"status": "enabled"}}},
    )
    assert len(ir.raw_lines) == 2
    assert ir.normalized["services"]["telnet"]["status"] == "enabled"

def test_block_model():
    block = Block(type="line", name="vty 0 4", commands=["transport input telnet ssh"])
    assert block.type == "line"
    assert "transport input telnet ssh" in block.commands