"""Tests for ConfigGuard rule engine."""
import pytest
from configguard.engine import RuleEngine, Rule
from configguard.models import ConfigIR, Block, FindingStatus
from configguard.parser import CiscoIOSParser

SAMPLE_IR = ConfigIR(
    raw_lines=["line vty 0 4", "transport input telnet ssh"],
    blocks=[
        Block(type="line", name="vty 0 4", commands=["transport input telnet ssh"])
    ],
    normalized={"services": {"telnet": {"status": "enabled"}}},
)

def test_rule_engine_loads_rules():
    engine = RuleEngine("configguard/rules")
    assert len(engine.rules) > 0

def test_rule_engine_detects_telnet():
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(SAMPLE_IR)
    telnet_findings = [f for f in findings if f.rule_id == "CISCO-MGMT-001"]
    assert len(telnet_findings) == 1
    assert telnet_findings[0].status == FindingStatus.FAIL

def test_rule_engine_passes_when_no_telnet():
    clean_ir = ConfigIR(
        raw_lines=["line vty 0 4", "transport input ssh"],
        blocks=[Block(type="line", name="vty 0 4", commands=["transport input ssh"])],
        normalized={"services": {"ssh": {"status": "enabled"}}},
    )
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(clean_ir)
    telnet_findings = [f for f in findings if "telnet" in f.rule_id.lower()]
    assert len(telnet_findings) == 0


def test_telnet_case(load_test_case):
    case = load_test_case("case_001_telnet_enabled")
    parser = CiscoIOSParser(case["config"])
    ir = parser.parse()
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(ir)

    expected_rule_ids = [f["rule_id"] for f in case["expected"]["findings"]]
    actual_rule_ids = [f.rule_id for f in findings]

    for rule_id in expected_rule_ids:
        matching = [f for f in findings if f.rule_id == rule_id]
        assert len(matching) == 1
        assert matching[0].status.value == "FAIL"


def test_snmp_v2c_case(load_test_case):
    case = load_test_case("case_002_snmp_v2c")
    parser = CiscoIOSParser(case["config"])
    ir = parser.parse()
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(ir)

    expected_rule_ids = [f["rule_id"] for f in case["expected"]["findings"]]
    actual_rule_ids = [f.rule_id for f in findings]

    for rule_id in expected_rule_ids:
        matching = [f for f in findings if f.rule_id == rule_id]
        assert len(matching) >= 1
        assert matching[0].status.value == "FAIL"


def test_missing_aaa_case(load_test_case):
    case = load_test_case("case_003_missing_aaa")
    parser = CiscoIOSParser(case["config"])
    ir = parser.parse()
    engine = RuleEngine("configguard/rules")
    findings = engine.evaluate(ir)

    aaa_findings = [f for f in findings if f.rule_id == "CISCO-AUTH-001"]
    assert len(aaa_findings) == 1
    assert aaa_findings[0].status.value == "FAIL"