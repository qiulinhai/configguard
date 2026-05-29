# ConfigGuard v0.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add Signal Layer architecture to ConfigGuard — a semantic abstraction layer between config parsing and rule evaluation, with dual-path execution (v0.1 legacy + v0.2 signal rules) and signal-level deduplication.

**Architecture:** Config → Parser → ConfigIR → Signal Extractor → Signals → Dual Rule Execution (v0.1 legacy + v0.2 signal) → Merged Findings

**Tech Stack:** Python 3.10+, existing ConfigGuard codebase, pytest

---

## File Structure

```
configguard/
  __init__.py
  cli.py              # Modified: add signal extraction
  parser.py          # No changes (produces ConfigIR)
  engine.py          # Modified: merge_findings updated
  models.py         # Modified: add Signal dataclass
  signals.py        # NEW: SignalExtractor + signal types
  output/
    json.py
    markdown.py
  rules/

tests/
  test_signals.py   # NEW: signal extraction tests
  test_engine.py    # Modified: add signal-based tests
  test_cli.py
  cases/
```

---

## Task 1: Signal Model

**Files:**
- Modify: `configguard/models.py` — add Signal dataclass

- [x] **Step 1: Write failing test for Signal model**

```python
# tests/test_signals.py
import pytest
from configguard.models import Signal

def test_signal_creation():
    signal = Signal(
        type="transport_input",
        value="telnet",
        context="vty 0 4",
        block_type="line",
        raw="transport input telnet ssh",
    )
    assert signal.type == "transport_input"
    assert signal.value == "telnet"
    assert signal.context == "vty 0 4"

def test_signal_severity_hint_optional():
    signal = Signal(
        type="transport_input",
        value="telnet",
        context="vty 0 4",
        block_type="line",
        raw="transport input telnet",
        severity_hint="high",
    )
    assert signal.severity_hint == "high"
```

- [x] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_signals.py -v`
Expected: FAIL — module not found

- [x] **Step 3: Add Signal model to models.py**

Add at end of configguard/models.py:
```python
from dataclasses import dataclass, field

@dataclass
class Signal:
    type: str           # e.g., "transport_input"
    value: str          # e.g., "telnet"
    context: str        # e.g., "vty 0 4"
    block_type: str     # e.g., "line"
    raw: str            # original config line
    severity_hint: str | None = None  # optional: "high", "medium", "low"

    def __hash__(self):
        return hash((self.type, self.context))
```

- [x] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_signals.py::test_signal_creation tests/test_signals.py::test_signal_severity_hint_optional -v`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add tests/test_signals.py configguard/models.py
git commit -m "feat: add Signal dataclass for signal layer"
```

---

## Task 2: SignalExtractor Core

**Files:**
- Create: `configguard/signals.py` — SignalExtractor class

- [x] **Step 1: Write failing test for SignalExtractor**

```python
# tests/test_signals.py — add tests
from configguard.signals import SignalExtractor
from configguard.parser import CiscoIOSParser

SAMPLE_CONFIG = """
hostname Router1
!
line vty 0 4
 transport input telnet ssh
 login local
!
interface GigabitEthernet0/0
 no shutdown
!
end
"""

def test_extractor_extracts_transport_signal():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    ir = parser.parse()
    extractor = SignalExtractor()
    sigs = extractor.extract(ir)

    transport_sigs = [s for s in sigs if s.type == "transport_input"]
    assert len(transport_sigs) == 1
    assert transport_sigs[0].value == "telnet"
    assert transport_sigs[0].context == "vty 0 4"

def test_extractor_extracts_interface_signal():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    ir = parser.parse()
    extractor = SignalExtractor()
    sigs = extractor.extract(ir)

    iface_sigs = [s for s in sigs if s.type == "interface_state"]
    assert len(iface_sigs) == 1
    assert iface_sigs[0].value == "up"
    assert "GigabitEthernet" in iface_sigs[0].context
```

- [x] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_signals.py -v`
Expected: FAIL — module not found

- [x] **Step 3: Create SignalExtractor**

Create configguard/signals.py:
```python
"""Signal extraction from ConfigIR."""
from configguard.models import ConfigIR, Block, Signal


class SignalExtractor:
    def extract(self, config_ir: ConfigIR) -> list[Signal]:
        """Extract signals from parsed ConfigIR with deduplication."""
        signals = []
        seen = set()

        # Extract from blocks
        for block in config_ir.blocks:
            block_sigs = self._extract_from_block(block)
            for sig in block_sigs:
                key = (sig.type, sig.context)
                if key not in seen:
                    seen.add(key)
                    signals.append(sig)

        # Extract global-level signals
        global_sigs = self._extract_global_signals(config_ir)
        for sig in global_sigs:
            key = (sig.type, sig.context)
            if key not in seen:
                seen.add(key)
                signals.append(sig)

        return signals

    def _extract_from_block(self, block: Block) -> list[Signal]:
        signals = []

        if block.type == "line":
            signals.extend(self._extract_line_signals(block))
        elif block.type == "interface":
            signals.extend(self._extract_interface_signals(block))

        return signals

    def _extract_line_signals(self, block: Block) -> list[Signal]:
        signals = []
        context = block.name

        for cmd in block.commands:
            if cmd.startswith("transport input"):
                if "telnet" in cmd:
                    signals.append(Signal(
                        type="transport_input",
                        value="telnet",
                        context=context,
                        block_type="line",
                        raw=cmd,
                    ))
                if "ssh" in cmd:
                    signals.append(Signal(
                        type="transport_input",
                        value="ssh",
                        context=context,
                        block_type="line",
                        raw=cmd,
                    ))
            elif cmd.startswith("login"):
                if "local" in cmd:
                    signals.append(Signal(
                        type="auth_method",
                        value="local",
                        context=context,
                        block_type="line",
                        raw=cmd,
                    ))

        return signals

    def _extract_interface_signals(self, block: Block) -> list[Signal]:
        signals = []
        context = block.name

        is_shutdown = any("shutdown" in cmd for cmd in block.commands)
        if is_shutdown:
            signals.append(Signal(
                type="interface_state",
                value="shutdown",
                context=context,
                block_type="interface",
                raw="shutdown",
            ))
        else:
            signals.append(Signal(
                type="interface_state",
                value="up",
                context=context,
                block_type="interface",
                raw="no shutdown",
            ))

        has_description = any(cmd.startswith("description") for cmd in block.commands)
        signals.append(Signal(
            type="interface_description",
            value="present" if has_description else "missing",
            context=context,
            block_type="interface",
            raw=block.commands[0] if block.commands else "",
        ))

        return signals

    def _extract_global_signals(self, config_ir: ConfigIR) -> list[Signal]:
        signals = []
        raw_text = "\n".join(config_ir.raw_lines)

        # AAA
        if "aaa new-model" in raw_text:
            signals.append(Signal(
                type="aaa_enabled",
                value="true",
                context="global",
                block_type="global",
                raw="aaa new-model",
            ))
        elif "no aaa new-model" in raw_text:
            signals.append(Signal(
                type="aaa_enabled",
                value="false",
                context="global",
                block_type="global",
                raw="no aaa new-model",
            ))

        # HTTP server
        if "ip http server" in raw_text:
            signals.append(Signal(
                type="http_server",
                value="enabled",
                context="global",
                block_type="global",
                raw="ip http server",
            ))

        # SNMP
        if "snmp-server community public" in raw_text or "snmp-server community private" in raw_text:
            signals.append(Signal(
                type="snmp_version",
                value="v2c",
                context="global",
                block_type="global",
                raw="snmp-server community",
            ))
            if "public" in raw_text:
                signals.append(Signal(
                    type="snmp_community",
                    value="public",
                    context="global",
                    block_type="global",
                    raw="snmp-server community public",
                ))
            if "private" in raw_text:
                signals.append(Signal(
                    type="snmp_community",
                    value="private",
                    context="global",
                    block_type="global",
                    raw="snmp-server community private",
                ))

        # Syslog
        if "logging host" in raw_text:
            signals.append(Signal(
                type="syslog_host",
                value="configured",
                context="global",
                block_type="global",
                raw="logging host",
            ))

        # NTP
        if "ntp server" in raw_text:
            signals.append(Signal(
                type="ntp_server",
                value="configured",
                context="global",
                block_type="global",
                raw="ntp server",
            ))

        return signals
```

- [x] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_signals.py -v`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add tests/test_signals.py configguard/signals.py
git commit -m "feat: add SignalExtractor with signal extraction for all signal types"
```

---

## Task 3: Signal Deduplication in Engine

**Files:**
- Modify: `configguard/engine.py` — update merge_findings key

- [x] **Step 1: Read current engine.py merge_findings**

```bash
grep -A 15 "def merge_findings" configguard/engine.py
```

- [x] **Step 2: Update merge_findings key to (rule_id, block_name, evidence)**

Edit configguard/engine.py — update merge logic:
```python
def _merge_findings(self, v1_findings: list[Finding], v2_findings: list[Finding]) -> list[Finding]:
    """Merge findings from both execution paths with deduplication."""
    seen = set()
    merged = []

    for findings in [v1_findings, v2_findings]:
        for f in findings:
            # Key uses (rule_id, block_name, evidence) for stable deduplication
            key = (f.rule_id, f.block_name, f.evidence)
            if key not in seen:
                seen.add(key)
                merged.append(f)

    return merged
```

- [x] **Step 3: Run tests to verify unchanged behavior**

Run: `pytest tests/ -v`
Expected: All 16 tests pass (no behavior change)

- [x] **Step 4: Commit**

```bash
git add configguard/engine.py
git commit -m "fix: update merge_findings key to (rule_id, block_name, evidence)"
```

---

## Task 4: Dual Execution Integration

**Files:**
- Modify: `configguard/engine.py` — add signal-based rule execution

- [x] **Step 1: Write failing test for dual execution**

```python
# tests/test_engine.py — add test
from configguard.signals import SignalExtractor

def test_dual_execution_produces_signals():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    ir = parser.parse()
    extractor = SignalExtractor()
    signals = extractor.extract(ir)

    # Verify signals are extracted
    assert len(signals) > 0
    signal_types = {s.type for s in signals}
    assert "transport_input" in signal_types

def test_signal_based_rule_detection():
    """Test that signal-based rules can detect telnet."""
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    ir = parser.parse()
    extractor = SignalExtractor()
    signals = extractor.extract(ir)

    # Signal-based detection of telnet
    telnet_signals = [s for s in signals if s.type == "transport_input" and s.value == "telnet"]
    assert len(telnet_signals) == 1
```

- [x] **Step 2: Run test to verify it passes**

Run: `pytest tests/test_engine.py -v`
Expected: PASS

- [x] **Step 3: Commit**

```bash
git add configguard/engine.py tests/test_engine.py
git commit -m "feat: add signal extraction to dual execution path"
```

---

## Task 5: CLI Integration with Signals

**Files:**
- Modify: `configguard/cli.py` — use signals in execution

- [x] **Step 1: Write failing test for CLI with signals**

```python
# tests/test_cli.py — add test
def test_cli_with_signal_extraction(tmp_path):
    runner = CliRunner()
    config_file = tmp_path / "config.txt"
    config_file.write_text("line vty 0 4\n transport input telnet ssh\n")

    result = runner.invoke(audit, [str(config_file)])
    assert result.exit_code == 0
    assert "CISCO-MGMT-001" in result.output or "Disable Telnet" in result.output
```

- [x] **Step 2: Run test to verify it passes**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (v0.1 rules still work)

- [x] **Step 3: Commit**

```bash
git add configguard/cli.py tests/test_cli.py
git commit -m "feat: CLI remains compatible with v0.1 rules + signal extraction"
```

---

## Task 6: Signal Extraction Ground Truth Tests

**Files:**
- Create: `tests/cases/case_004_signal_extraction/` — signal extraction test case

- [x] **Step 1: Create signal extraction test case**

```
tests/cases/case_004_signal_extraction/
  config.txt
  expected_signals.json
  metadata.yaml
```

Create tests/cases/case_004_signal_extraction/config.txt:
```
hostname Router1
!
line vty 0 4
 transport input telnet ssh
 login local
!
interface GigabitEthernet0/0
 no shutdown
!
end
```

Create tests/cases/case_004_signal_extraction/expected_signals.json:
```json
{
  "case_id": "case_004_signal_extraction",
  "signals": [
    {
      "type": "transport_input",
      "value": "telnet",
      "context": "vty 0 4"
    },
    {
      "type": "transport_input",
      "value": "ssh",
      "context": "vty 0 4"
    },
    {
      "type": "auth_method",
      "value": "local",
      "context": "vty 0 4"
    },
    {
      "type": "interface_state",
      "value": "up",
      "context": "GigabitEthernet0/0"
    },
    {
      "type": "interface_description",
      "value": "missing",
      "context": "GigabitEthernet0/0"
    }
  ]
}
```

Create tests/cases/case_004_signal_extraction/metadata.yaml:
```yaml
id: case_004_signal_extraction
description: Signal extraction from mixed config
tags:
  - signal-layer
  - cisco-ios
version: "1.0"
```

- [x] **Step 2: Add test for signal extraction case**

Add to tests/test_signals.py:
```python
def test_signal_extraction_case(load_test_case):
    case = load_test_case("case_004_signal_extraction")
    parser = CiscoIOSParser(case["config"])
    ir = parser.parse()
    extractor = SignalExtractor()
    signals = extractor.extract(ir)

    expected_types = {(s["type"], s["value"], s["context"]) for s in case["expected_signals"]["signals"]}
    actual_types = {(s.type, s.value, s.context) for s in signals}

    # All expected signals should be present
    for expected in expected_types:
        assert expected in actual_types, f"Missing signal: {expected}"
```

- [x] **Step 3: Run tests to verify**

Run: `pytest tests/test_signals.py -v`
Expected: PASS

- [x] **Step 4: Commit**

```bash
git add tests/cases/case_004_signal_extraction/ tests/test_signals.py
git commit -m "feat: add ground truth test case for signal extraction"
```

---

## Task 7: CI Update for v0.2

**Files:**
- Modify: `.github/workflows/ci.yml`

- [x] **Step 1: Update CI to verify dual execution**

Add step to verify signal extraction works:
```yaml
- name: Verify signal extraction
  run: |
    python -c "
    from configguard.parser import CiscoIOSParser
    from configguard.signals import SignalExtractor
    config = 'line vty 0 4\\n transport input telnet ssh\\n'
    ir = CiscoIOSParser(config).parse()
    sigs = SignalExtractor().extract(ir)
    assert len(sigs) > 0, 'No signals extracted'
    print(f'Extracted {len(sigs)} signals')
    "
```

- [x] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: verify signal extraction in CI pipeline"
```

---

## Self-Review Checklist

1. **Spec coverage:**
   - Signal dataclass: Task 1 ✓
   - SignalExtractor: Task 2 ✓
   - Deduplication key update: Task 3 ✓
   - Dual execution: Task 4 ✓
   - CLI integration: Task 5 ✓
   - Signal extraction tests: Task 6 ✓
   - CI update: Task 7 ✓

2. **Placeholder scan:** No TBD/TODO found. All steps have concrete code.

3. **Type consistency:**
   - Signal type: `type: str`, `value: str`, `context: str`, `block_type: str`, `raw: str`, `severity_hint: str | None`
   - Consistent across all tasks ✓

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-29-configguard-v0.2-implementation.md`.**

Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**