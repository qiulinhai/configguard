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

    # CISCO-AUTH-001b: detects AAA explicitly disabled (no aaa new-model)
    aaa_findings = [f for f in findings if f.rule_id == "CISCO-AUTH-001b"]
    assert len(aaa_findings) == 1
    assert aaa_findings[0].status.value == "FAIL"


def test_engine_evaluate_with_contexts():
    """Test RuleEngine can evaluate using ContextBuilder."""
    from configguard.parser import CiscoIOSParser
    from configguard.signals import SignalExtractor
    from configguard.context import ContextBuilder

    config_text = """
    hostname Router1
    !
    snmp-server community public RO
    snmp-server community private RW
    !
    end
    """

    parser = CiscoIOSParser(config_text)
    ir = parser.parse()

    # Extract signals
    extractor = SignalExtractor()
    signals = extractor.extract(ir)

    # Build contexts
    builder = ContextBuilder()
    engine = RuleEngine("configguard/rules")
    contexts = builder.build_contexts(signals)

    # Evaluate using contexts
    findings = engine.evaluate_with_contexts(contexts)

    # Count SNMP findings
    snmp_findings = [f for f in findings if f.rule_id == "CISCO-SNMP-001"]
    assert len(snmp_findings) == 1  # ONE finding, not two

    # Verify aggregated evidence
    snmp_finding = snmp_findings[0]
    assert "public" in snmp_finding.evidence
    assert "private" in snmp_finding.evidence


def test_rule_evaluate_with_context():
    """Test Rule can evaluate against a SignalContext."""
    from configguard.models import Signal
    from configguard.context import SignalContext

    rule = Rule({
        "id": "CISCO-SNMP-001",
        "name": "Disable SNMP v2c",
        "category": "snmp-security",
        "severity": "HIGH",
        "match": {"type": "regex", "pattern": "(public|private)"},
        "condition": "present",
        "finding": {"status": "FAIL"},
    })

    # Create context with multiple SNMP signals
    signals = [
        Signal(type="snmp_community", value="public", context="global",
               block_type="global", raw="snmp-server community public"),
        Signal(type="snmp_community", value="private", context="global",
               block_type="global", raw="snmp-server community private"),
    ]
    context = SignalContext(
        context_key="snmp_security",
        signals=signals,
        aggregated_evidence=["snmp-server community public", "snmp-server community private"],
        metadata={"community_count": 2},
    )

    findings = rule.evaluate_with_context(context)
    assert len(findings) == 1  # ONE finding, not two
    assert findings[0].evidence == "snmp-server community public, snmp-server community private"  # Aggregated raw