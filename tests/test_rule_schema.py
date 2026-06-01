"""Tests for rule schema extensions (v0.2.1+)."""
import yaml

from configguard.engine import Rule
from configguard.models import Reference, Severity


def test_reference_dataclass_basic():
    ref = Reference(type="cis-benchmark", id="1.1.1", url="https://example.com/cis")
    assert ref.type == "cis-benchmark"
    assert ref.id == "1.1.1"
    assert ref.url == "https://example.com/cis"


def test_reference_dataclass_to_dict():
    ref = Reference(type="cve", id="CVE-2017-6736", url="https://nvd.nist.gov/vuln/detail/CVE-2017-6736")
    d = ref.to_dict()
    assert d == {
        "type": "cve",
        "id": "CVE-2017-6736",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-6736",
    }


def test_rule_parses_references():
    rule_yaml = """
id: TEST-001
name: Test Rule
category: test
severity: HIGH

applies_to:
  category: [vty]

match:
  type: regex
  pattern: "telnet"
condition: present

finding:
  status: FAIL
  evidence: true

references:
  - type: cis-benchmark
    id: "1.1.1"
    url: "https://example.com/cis"
  - type: cve
    id: "CVE-2017-6736"
    url: "https://nvd.nist.gov/vuln/detail/CVE-2017-6736"
"""
    rule = Rule(yaml.safe_load(rule_yaml))
    assert len(rule.references) == 2
    assert rule.references[0].type == "cis-benchmark"
    assert rule.references[0].id == "1.1.1"
    assert rule.references[1].type == "cve"


def test_rule_default_references_empty():
    rule_yaml = """
id: TEST-002
name: No Refs
category: test
severity: LOW

match:
  type: regex
  pattern: "x"
condition: present

finding:
  status: FAIL
  evidence: true
"""
    rule = Rule(yaml.safe_load(rule_yaml))
    assert rule.references == []


def test_rule_warns_on_unknown_reference_type(capsys):
    rule_yaml = """
id: TEST-003
name: Unknown Type
category: test
severity: LOW

match:
  type: regex
  pattern: "x"
condition: present

finding:
  status: FAIL
  evidence: true

references:
  - type: not-a-real-type
    id: "abc"
    url: "https://example.com"
"""
    rule = Rule(yaml.safe_load(rule_yaml))
    captured = capsys.readouterr()
    assert "Unknown reference type 'not-a-real-type'" in captured.out or \
           "Unknown reference type 'not-a-real-type'" in captured.err
    # Rule should still load
    assert len(rule.references) == 1
