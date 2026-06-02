"""Wire orphan test cases 006-020 into the test suite.

Each case dir under tests/cases/ has:
  - config.txt: input configuration
  - expected.json: expected findings list (or empty for PASS)
  - metadata.yaml: optional metadata (some cases lack this)

Cases using expected_signals.json (e.g., case_004) are out of scope — they
test signal extraction, not the rule engine. Cases with no expected.json
(e.g., case_019_interface_no) are also skipped.

The engine has two evaluation paths:
  - Legacy: `engine.evaluate(ir)` — regex on raw config text
  - Context-based: `engine.evaluate_with_contexts(contexts, rules)` — signals →
    contexts → rules. This is what the CLI uses and is required for rules
    that depend on extracted signals (e.g., CISCO-MGMT-002 with pattern
    "HTTP_ENABLED" only fires when the http_server signal is present).
"""
import json
from pathlib import Path

# Ensure the signal registry has its default definitions registered before any
# test runs. The CLI does this at import time as a side effect; without it,
# ContextBuilder uses signal types as context keys instead of the proper
# category-based keys (e.g., "snmp_community" instead of "snmp"), and the
# engine's category index lookup returns nothing. See CLI cli.py:20-21.
from configguard.registry import create_signal_registry_with_defaults
create_signal_registry_with_defaults()

import pytest

from configguard.context import ContextBuilder
from configguard.engine import RuleEngine
from configguard.parser import CiscoIOSParser
from configguard.signals import SignalExtractor

CASES_DIR = Path(__file__).parent / "cases"
RULES_DIR = Path(__file__).parent.parent / "configguard" / "rules"


def _discover_cases() -> list[str]:
    """Return sorted list of case dir names that have config.txt AND expected.json."""
    out = []
    for entry in sorted(CASES_DIR.iterdir()):
        if not entry.is_dir():
            continue
        if (entry / "config.txt").exists() and (entry / "expected.json").exists():
            out.append(entry.name)
    return out


def _load_case(case_name: str) -> tuple[str, list[dict]]:
    case_dir = CASES_DIR / case_name
    config = (case_dir / "config.txt").read_text()
    expected = json.loads((case_dir / "expected.json").read_text())
    return config, expected.get("findings", [])


def _evaluate(case_name: str, config_text: str, engine: RuleEngine) -> list:
    """Run the engine using the same path the CLI uses (context-based)."""
    ir = CiscoIOSParser(config_text).parse()
    signals = SignalExtractor().extract(ir)
    contexts = ContextBuilder().build_contexts(signals)
    if not engine._category_index:
        # No context-based rules; fall back to legacy (per cli.py:79)
        return engine.evaluate(ir)
    return engine.evaluate_with_contexts(contexts, engine.rules)


@pytest.mark.parametrize("case_name", _discover_cases())
def test_case_findings_match_expected(case_name: str):
    """Engine output must match the case's expected.json findings.

    The comparison is set-based: every expected (rule_id, status) pair must
    appear in the actual findings. Extra findings are allowed (the engine
    may detect more violations than the case enumerates).
    """
    config_text, expected_findings = _load_case(case_name)
    engine = RuleEngine(str(RULES_DIR))
    findings = _evaluate(case_name, config_text, engine)

    for expected_finding in expected_findings:
        rule_id = expected_finding["rule_id"]
        expected_status = expected_finding["status"]

        matching = [f for f in findings if f.rule_id == rule_id]
        assert matching, (
            f"[{case_name}] Expected rule {rule_id} to fire, but no matching finding. "
            f"Actual findings: {[f.rule_id for f in findings]}"
        )
        assert matching[0].status.value == expected_status, (
            f"[{case_name}] {rule_id} expected {expected_status}, "
            f"got {matching[0].status.value}"
        )


def test_discovery_finds_expected_cases():
    """Sanity check: discovery should find all testable cases."""
    cases = _discover_cases()
    # 21 total dirs - case_004 (uses expected_signals.json) - case_019_interface_no (no expected.json) = 19
    assert len(cases) == 19, f"Expected 19 testable cases, found {len(cases)}: {cases}"
    # Spot-check that the known cases are present
    assert "case_001_telnet_enabled" in cases
    assert "case_020_interface_active" in cases
    # case_004 and case_019_interface_no should be excluded
    assert "case_004_signal_extraction" not in cases
    assert "case_019_interface_no" not in cases
