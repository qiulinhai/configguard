# ConfigGuard v0.1 Design Specification

## 1. Overview

**Product:** Network Device Configuration Security Auditor (Cisco-first)
**Version:** v0.1
**Type:** CLI tool with reusable core engine

**Core Value Proposition:** Automatically discover the 5 most common high-risk security misconfigurations in Cisco IOS device configurations.

**Target Users:** Network engineers, security engineers, compliance auditors

---

## 2. Architecture

```
User Input (CLI)
       ↓
   Config Parser (Block-aware)
       ↓
  Raw Lines + Structured Blocks
       ↓
   Rule Engine (YAML rules)
       ↓
   Findings (JSON)
       ↓
   LLM Explanation (optional layer)
       ↓
   Output Layer (JSON / Markdown / STDOUT)
```

**Core Principles:**
- CLI is the only entry point in v0.1, but core engine is designed as a reusable library for future API/Web integration
- JSON is the source of truth; Markdown and STDOUT are derived presentation layers
- AI must never affect determinism — LLM only generates human-readable explanations, never influences PASS/FAIL decisions

---

## 3. Scope

### 3.1 Supported Platforms
- **Primary:** Cisco IOS running-config
- **Optional (v0.2):** Cisco NX-OS (subset)

### 3.2 Security Domains (v0.1)

| Domain | Description |
|--------|-------------|
| Management Plane Exposure | Telnet, HTTP, insecure VTY, remote management exposure |
| Authentication / AAA | Missing AAA, weak local login, console/VTY no auth |
| SNMP Security | SNMP v1/v2c enabled, weak community strings |
| Logging & NTP | Missing logging, no remote syslog, no NTP, time sync issues |
| Interface Hygiene | Unused interfaces not shutdown, management interface exposure |

### 3.3 Out of Scope (v0.1)
- Juniper JunOS
- AWS/GCP/Azure cloud configurations
- Firewall policy chains (Palo Alto, Fortinet, etc.)
- Routing security (OSPF/BGP analysis)
- Advanced ACL logic
- Encryption algorithm analysis

---

## 4. Parser Design

### 4.1 Parser Type
**Block-aware semi-structured parser** — not pure regex, not full AST.

### 4.2 Output Structure (Dual Representation)

```json
{
  "raw_lines": ["line vty 0 4", " transport input telnet ssh", " login local"],
  "blocks": [
    {
      "type": "line",
      "name": "vty 0 4",
      "commands": ["transport input telnet ssh", "login local"]
    }
  ],
  "metadata": {
    "total_lines": 3,
    "block_count": 1
  }
}
```

### 4.3 Block Types (v0.1)

| Block Type | Keywords | Example |
|------------|----------|---------|
| interface | `interface` | `interface GigabitEthernet0/0` |
| line | `line` | `line vty 0 4` |
| router | `router` | `router ospf 1` |
| access-list | `access-list` | `access-list 101 permit` |
| global | (top-level) | `hostname Router1` |

### 4.4 Parsing Rules

1. Identify block starters by keyword at line start
2. Track indentation to determine block nesting
3. Lines not matching block keywords attach to parent block
4. `!` separator marks block boundaries
5. Preserve both raw lines and structured blocks for rule engine flexibility

---

## 5. Rule Engine Design

### 5.1 Rule Authoring Format
**YAML** — declarative security policies, human-editable, AI-generatable.

### 5.2 Rule Schema

```yaml
id: CISCO-MGMT-001
name: Disable Telnet
category: management-plane
severity: HIGH

match:
  type: regex              # regex | exact | contains
  pattern: "transport input .*telnet"
  scope: line.vty          # optional: restrict to block type

condition: present          # present | absent

finding:
  status: FAIL             # FAIL | PASS | WARN
  evidence: true           # true = capture matched text

description: >
  Telnet transmits credentials in plaintext and should not be used.
  Attackers can intercept plaintext credentials to gain unauthorized access.

remediation: >
  Use 'transport input ssh' instead of telnet. Configure SSH version 2
  and disable telnet globally with 'no service telnetd'.
```

### 5.3 Execution Model

```
YAML (authoring) → Python evaluator (execution) → Findings JSON (runtime)
```

Rule evaluation is 100% deterministic:
```python
if re.search(rule["match"]["pattern"], config_text):
    return FAIL
```

### 5.4 Rule = Data, Not Code

Benefits:
- Rules can be added without modifying code
- Rules are testable in isolation
- LLM can generate YAML rules directly
- Community contribution is low-friction
- Future: rule versioning and exchange

---

## 6. Output Design

### 6.1 Output Formats

| Format | Priority | Description |
|--------|----------|-------------|
| JSON | P0 | Source of truth, machine-readable, API-ready |
| Markdown | P1 | Human-readable audit report |
| STDOUT | P1 | CLI summary for quick review and CI |

### 6.2 JSON Output Schema

```json
{
  "version": "0.1.0",
  "summary": {
    "total": 5,
    "pass": 3,
    "fail": 2,
    "warnings": 0
  },
  "findings": [
    {
      "rule_id": "CISCO-MGMT-001",
      "rule_name": "Disable Telnet",
      "category": "management-plane",
      "severity": "HIGH",
      "status": "FAIL",
      "evidence": "transport input telnet ssh",
      "block_type": "line",
      "block_name": "vty 0 4",
      "remediation": "Use 'transport input ssh' instead..."
    }
  ],
  "metadata": {
    "config_name": "router_config.txt",
    "device_type": "Cisco IOS",
    "parser_version": "0.1.0",
    "rules_version": "0.1.0",
    "timestamp": "2026-05-29T12:00:00Z"
  }
}
```

### 6.3 Markdown Output

```markdown
# ConfigGuard Security Audit Report

## Summary
- **Total Checks:** 5
- **Passed:** 3
- **Failed:** 2
- **Warnings:** 0

---

## FAIL Findings

### [HIGH] Disable Telnet
**Rule ID:** CISCO-MGMT-001
**Category:** Management Plane Exposure

**Evidence:**
```
line vty 0 4
 transport input telnet ssh
```

**Risk:** Telnet transmits credentials in plaintext. Attackers can intercept administrative credentials.

**Remediation:** Use 'transport input ssh' and disable telnet globally.
```

### 6.4 STDOUT Summary

```
$ configguard audit router_config.txt

[FAIL] Telnet enabled on VTY lines (CISCO-MGMT-001)
[FAIL] SNMP v2 community string 'public' detected (CISCO-SNMP-001)
[PASS] AAA authentication enabled (CISCO-AUTH-001)
[PASS] SSH v2 configured (CISCO-MGMT-002)
[PASS] Remote syslog configured (CISCO-LOG-001)

Summary: 2 failed, 3 passed
```

---

## 7. AI Layer Design

### 7.1 Position
**Explanation layer only** — AI generates human-readable descriptions, never participates in PASS/FAIL decisions.

### 7.2 When LLM is Invoked

```
Findings JSON
    ↓
LLM (optional)
    ↓
Enriched explanations + remediation suggestions
```

### 7.3 Design Principle

> **"AI must never affect determinism."**

- LLM is invoked only after rule engine produces findings
- LLM input includes rule metadata + evidence, not raw config
- LLM output is cached to avoid repeated API calls
- In v0.1, LLM explanation is disabled by default (flag: `--explain`)

---

## 8. Ground Truth System

### 8.1 Definition

> **A versioned, rule-level deterministic test corpus validated via pytest CI.**

### 8.2 Test Case Structure

```
tests/
  cases/
    case_001_telnet_enabled/
      config.txt          # Input: Cisco IOS config snippet
      expected.json      # Ground truth: expected findings
      metadata.yaml      # Case metadata and tags
    case_002_snmp_v2/
      config.txt
      expected.json
      metadata.yaml
    ...
  test_engine.py         # Test runner
  conftest.py           # Pytest fixtures
```

### 8.3 expected.json Schema

```json
{
  "case_id": "case_001_telnet_enabled",
  "description": "Telnet enabled on VTY lines should trigger FAIL",
  "findings": [
    {
      "rule_id": "CISCO-MGMT-001",
      "status": "FAIL",
      "severity": "HIGH"
    }
  ]
}
```

### 8.4 metadata.yaml Schema

```yaml
id: case_001_telnet_enabled
description: Telnet enabled on VTY lines should trigger FAIL
tags:
  - management-plane
  - cisco-ios
  - high-risk
  - telnet
version: "1.0"
author: ConfigGuard team
```

### 8.5 CI Pipeline

```yaml
# .github/workflows/ci.yml
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run pytest
        run: pytest tests/ -v
      - name: Upload report
        if: failure()
        uses: actions/upload-artifact@v4
```

---

## 9. Project Structure

```
configguard/
  __init__.py
  cli.py              # CLI entry using Typer
  parser.py          # Block-aware parser
  engine.py          # Rule engine evaluator
  models.py          # Pydantic models for data validation
  output/
    json.py          # JSON output generator
    markdown.py      # Markdown report generator
  rules/             # YAML rule definitions
    management/
      disable_telnet.yaml
      disable_http.yaml
      secure_vty.yaml
    auth/
      aaa_required.yaml
      console_auth.yaml
    snmp/
      snmp_v2_disabled.yaml
    logging/
      remote_syslog.yaml
      ntp_config.yaml
    interface/
      unused_shutdown.yaml
tests/
  cases/
    case_001_telnet_enabled/
    case_002_snmp_v2/
    case_003_missing_aaa/
  test_engine.py
  conftest.py
.github/
  workflows/
    ci.yml
docs/
  specs/
    2026-05-29-configguard-v0.1-design.md
README.md
pyproject.toml
```

---

## 10. CLI Interface

### 10.1 Commands

```bash
configguard audit <config_file> [OPTIONS]

Options:
  --output-dir      Output directory for reports (default: ./output)
  --format          Output format: json, markdown, all (default: all)
  --rules-dir       Custom rules directory (default: ./configguard/rules)
  --explain         Enable LLM explanation layer
  --verbose         Verbose output
  --version         Show version
```

### 10.2 Examples

```bash
# Basic audit
configguard audit router_config.txt

# With LLM explanations
configguard audit router_config.txt --explain

# Custom output directory
configguard audit router_config.txt --output-dir ./audit_results

# JSON only (machine-readable)
configguard audit router_config.txt --format json
```

---

## 11. Dependencies

### 11.1 Python Version
- Python 3.10+

### 11.2 Key Packages

| Package | Purpose |
|---------|---------|
| typer | CLI framework |
| pydantic | Data validation |
| pyyaml | YAML rule parsing |
| pytest | Testing framework |
| pytest-xdist | Parallel test execution |

---

## 12. Design Principles Summary

1. **Deterministic over smart** — Rule engine must produce consistent, reproducible results
2. **Rule = Data, not Code** — Rules are declarative, externalized, versioned
3. **JSON as source of truth** — All outputs derive from JSON model
4. **AI explains, never decides** — LLM is an explanation layer only
5. **Test everything** — Ground truth system with 100%+ rule coverage
6. **Start narrow, expand deliberately** — Cisco IOS only in v0.1

---

## 13. Future Roadmap

| Version | Scope |
|---------|-------|
| v0.1 | Cisco IOS + 5 domains + CLI + Ground Truth |
| v0.2 | Cisco NX-OS subset + improved parser |
| v0.3 | Multi-vendor abstraction layer |
| v1.0 | Infrastructure security compliance engine |

---

## 14. Rejected Designs

| Approach | Why Rejected |
|----------|--------------|
| Pure regex parser | Cannot preserve context; cross-line relationships lost |
| Full AST parser | Cisco IOS has no formal grammar; explosion of edge cases |
| LLM-first architecture | Non-deterministic, non-testable, cost-prohibitive |
| JSON rules | Machine-friendly but poor for human authoring |
| Go struct rules | Requires code changes to add rules; blocks community contribution |
| DSL rules | Design cost high; debugging difficult; premature complexity |
| HTML dashboard | UI complexity too early; distracts from core engine |