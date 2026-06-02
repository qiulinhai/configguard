# ConfigGuard User Guide

> A complete walkthrough for installing, running, and integrating ConfigGuard into your workflow.

This guide assumes you have a Cisco IOS configuration file you want to audit. No device access, no live probes, no network — just a `.txt` file on disk.

---

## Table of contents

1. [What is ConfigGuard?](#1-what-is-configguard)
2. [Prerequisites](#2-prerequisites)
3. [Installation](#3-installation)
4. [Verify the install](#4-verify-the-install)
5. [Concepts you need to know](#5-concepts-you-need-to-know)
6. [Your first audit](#6-your-first-audit)
7. [CLI reference (every flag)](#7-cli-reference-every-flag)
8. [Output formats in detail](#8-output-formats-in-detail)
9. [Common workflows](#9-common-workflows)
10. [CI integration recipes](#10-ci-integration-recipes)
11. [Custom rule packs](#11-custom-rule-packs)
12. [Troubleshooting](#12-troubleshooting)
13. [FAQ](#13-faq)
14. [Getting help](#14-getting-help)

---

## 1. What is ConfigGuard?

ConfigGuard is a **static analyzer for Cisco IOS configuration files**. It runs offline on the text of a config and reports CIS Benchmark violations — things like hardcoded SNMP community strings, plaintext Telnet, missing AAA, and HTTP servers left enabled.

It is built for two audiences:

- **Network engineers and security teams** who want to know if a router config complies with hardening baselines before it ships.
- **DevOps / Platform engineers** who want a CI gate that blocks a PR when a config drifts toward a known-bad state.

It is **not** an active scanner. It does not log in to a device. It does not probe ports. It does not generate or apply config. The only input is a text file; the only outputs are reports.

The full rule set, the CIS mappings, and the v0.3 risk-scoring engine are described in this guide.

---

## 2. Prerequisites

You need:

- **Python 3.10 or newer.** Check with `python3 --version`. (3.10, 3.11, 3.12, 3.13, 3.14 are all supported.)
- **`pip`** (the Python package installer). Usually comes with Python. Check with `pip --version`.
- **A Cisco IOS configuration file** in text form. `show running-config` output is ideal. The file extension doesn't matter; `.txt`, `.conf`, `.cfg` all work.
- **~20 MB of disk space** for the install and the output reports.

You do **not** need:

- Network access to a device
- A device or account credentials
- An internet connection at runtime (only at install time, to fetch the package from PyPI)
- A database, server, or any other infrastructure

Supported operating systems: Linux, macOS, Windows (anything that runs Python 3.10+). Cisco IOS 12.x – 15.x (classic IOS syntax) is the current target.

---

## 3. Installation

Pick the method that fits your setup. All four end up with a working `configguard` command on your `PATH`.

### 3.1 Install from PyPI (recommended for most users)

Once ConfigGuard is published to PyPI:

```bash
pip install configguard
```

That's it. You can now run `configguard` from anywhere.

If you want to install it for your user account only (no `sudo`, no system-wide changes):

```bash
pip install --user configguard
```

### 3.2 Install in a virtual environment (best practice for development)

Virtual environments keep ConfigGuard's dependencies isolated from your system Python. This is the recommended way to install for development or when you want to pin a specific version.

```bash
# Create a venv in the current directory
python3 -m venv .venv

# Activate it
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows (PowerShell or cmd)

# Install inside the venv
pip install configguard
```

When you're done, deactivate with `deactivate`.

### 3.3 Install from a git checkout (for contributors or specific revisions)

```bash
git clone https://github.com/qiulinhai/configguard.git
cd configguard
pip install -e .
```

The `-e` flag installs in "editable" mode: changes to the source take effect without re-installing. Use this when you intend to modify ConfigGuard or run its test suite.

If you want a non-editable install from a checkout (e.g., a pinned revision):

```bash
pip install .
```

### 3.4 Install a specific version

To pin a particular release:

```bash
pip install configguard==0.1.0
```

To upgrade an existing install:

```bash
pip install --upgrade configguard
```

### 3.5 Verify Python and pip are sane

If `pip install configguard` fails, run these to confirm the basics:

```bash
python3 --version     # should be 3.10+
pip --version         # should report a recent pip
which python3
which pip
```

If you have multiple Python versions, prefer `python3 -m pip install configguard` over plain `pip install` to make sure you install into the correct interpreter.

---

## 4. Verify the install

After installing, run:

```bash
configguard --help
```

Expected output (abbreviated):

```
Usage: configguard [OPTIONS] COMMAND [ARGS]...

  Audit a network device configuration file.

Commands:
  audit  Audit a network device configuration file.

Options:
  --install-completion  Install completion for the current shell.
  --help                Show this message and exit.
```

Then drill into the audit command:

```bash
configguard audit --help
```

You should see all the flags listed in [Section 7](#7-cli-reference-every-flag) below. If you see "command not found" or "No module named configguard", see [Section 12: Troubleshooting](#12-troubleshooting).

---

## 5. Concepts you need to know

A few terms are used throughout the CLI and reports. Skim this section once, then come back if a term is unclear.

| Term | Meaning |
| --- | --- |
| **Rule** | A single CIS-mapped check, declared in YAML. E.g., "AAA Required", "Disable HTTP Server". |
| **Finding** | The result of running a rule against your config. Each rule produces exactly one finding per config. |
| **Status** | `PASS`, `WARN`, or `FAIL`. `FAIL` means the rule's condition is violated; `PASS` means it's clean. `WARN` is used for borderline cases. |
| **Severity** | `LOW`, `MEDIUM`, or `HIGH`. How serious the violation is. Independent of `Status` — a `PASS` finding still has a `Severity`. |
| **Evidence** | The exact slice of your config that triggered the finding. Human-readable, copy-pasteable. |
| **Block** | A logical group in Cisco IOS config (`interface`, `line vty`, `router`, `aaa`, `snmp-server`, `ip http`). Findings point at a specific block. |
| **Context** | ConfigGuard's internal representation of a block, used by context-aware rules. |
| **Risk score** | A weighted aggregate (0–100) over all findings. Optional output (see [Section 7.9](#79---risk-score)). |
| **CIS Benchmark** | The [Center for Internet Security Cisco IOS Benchmark](https://www.cisecurity.org/benchmark/cisco_ios) — the source of truth for every rule's ID and remediation. |

ConfigGuard's evaluation pipeline:

```
config.txt
   │
   ▼
[ Parser ]       →  Intermediate Representation (IR)
   │
   ▼
[ Signals ]      →  Flat list of typed facts (e.g. snmp_community="public")
   │
   ▼
[ Contexts ]     →  Block-keyed grouping
   │
   ▼
[ Rule engine ]  →  Findings (PASS / WARN / FAIL × severity × evidence)
   │
   ▼
[ Outputs ]      →  STDOUT + JSON + Markdown + (optional) risk score
```

You don't need to remember the internals. They matter only when you write custom rules ([Section 11](#11-custom-rule-packs)) or when you use `--debug-contexts` ([Section 7.8](#78---debug-contexts)).

---

## 6. Your first audit

### 6.1 A sample config

Save this to `router.conf`:

```
! A typical small-office router with several CIS violations
hostname BRANCH-RTR-01
!
aaa new-model
!
ip http server
ip http authentication local
!
snmp-server community public RO
snmp-server community private RW
!
line console 0
 password cisco
 login
!
line vty 0 4
 transport input telnet
!
end
```

This config has at least three CIS violations: HTTP server enabled, SNMP v2c community strings present, VTY accepts Telnet.

### 6.2 Run the audit

```bash
configguard audit router.conf
```

Expected output:

```
JSON report: output/20260602_143022_router.report.json
Markdown report: output/20260602_143022_router.report.md

--- Audit Summary ---
[FAIL] CISCO-MGMT-001 Disable Telnet
       Severity: HIGH
       Category: management-plane
       Block: line.vty.0
       Evidence: VTY line 0: transport input contains 'telnet'
[FAIL] CISCO-MGMT-002 Disable HTTP Server
       Severity: HIGH
       Category: management-plane
       Block: http
       Evidence: HTTP server: enabled
[FAIL] CISCO-SNMP-001 Disable SNMP v2c
       Severity: HIGH
       Category: snmp-security
       Block: snmp
       Evidence: SNMP v2c enabled with 2 community strings: public, private

Total: 3 findings (3 failed, 0 warnings, 0 passed)
```

### 6.3 Read the output

- The first two lines are the paths to the JSON and Markdown reports. The timestamp prefix is a batch-safe default; pass `--output-dir` to change the location.
- `--- Audit Summary ---` is the human-readable part. One block per finding.
- For each finding, you get: status (FAIL/WARN/PASS), rule ID, rule name, severity, category, the affected block (if any), and the evidence — the exact config line that triggered it.
- The final line is the count: `X failed`, `Y warnings`, `Z passed`. This is also your CI signal: see [Section 10](#10-ci-integration-recipes).

### 6.4 Open the Markdown report

The Markdown report at `output/20260602_143022_router.report.md` is meant for humans — paste it into a PR, attach it to a ticket, send it to a colleague. It contains the same findings plus remediation text and CIS references. See [Section 8.3](#83-markdown-report) for the full layout.

### 6.5 Open the JSON report

The JSON report at `output/20260602_143022_router.report.json` is meant for tooling. Its schema is described in [Section 8.2](#82-json-report). It's stable across patch versions; new fields are added in minor versions.

### 6.6 Pass `--fail-on` for instant CI gating

```bash
configguard audit router.conf --fail-on high
```

If any finding is `FAIL` with `severity >= HIGH`, the process exits with code `1`. In this example, all three findings are HIGH, so the exit code is `1`. Use this in CI to block PRs that introduce high-severity violations. See [Section 7.10](#710---fail-on) for the full matrix.

---

## 7. CLI reference (every flag)

```
configguard audit [OPTIONS] CONFIG_FILE
```

### 7.1 Positional: `CONFIG_FILE`

The path to the Cisco IOS config text file. Required. The file is read once and not modified.

```bash
configguard audit /path/to/router.conf
configguard audit ./configs/branch-01.txt
configguard audit -              # read from stdin (advanced; see FAQ)
```

### 7.2 `--output-dir`

**Default:** `./output`

**Type:** directory path

**Auto-creates:** yes (creates the directory if it doesn't exist, including intermediate parents)

The directory where the JSON and Markdown reports are written. The filename pattern is:

```
<YYYYMMDD>_<HHMMSS>_<config-basename>.report.{json,md}
```

The timestamp prefix is non-deterministic and changes per run. This is intentional: it lets you run ConfigGuard against many devices in batch without filename collisions.

Examples:

```bash
# Default location
configguard audit router.conf
# → writes to ./output/20260602_143022_router.report.{json,md}

# Custom location
configguard audit router.conf --output-dir ./reports
# → writes to ./reports/20260602_143022_router.report.{json,md}

# Auto-creates a deep path
configguard audit router.conf --output-dir /var/log/configguard/2026/june
# → creates the full path if it doesn't exist
```

### 7.3 `--format`

**Default:** `all`

**Choices:** `json`, `markdown`, `all`

Controls which report files are written. The STDOUT summary is always printed.

| Value | JSON file | Markdown file | STDOUT summary |
| --- | --- | --- | --- |
| `all` (default) | ✓ | ✓ | ✓ |
| `json` | ✓ | ✗ | ✓ |
| `markdown` | ✗ | ✓ | ✓ |

Examples:

```bash
# Both reports (default)
configguard audit router.conf

# JSON only (faster, smaller, for tooling)
configguard audit router.conf --format json

# Markdown only (for humans; no JSON file clutter)
configguard audit router.conf --format markdown
```

> **Note:** the STDOUT summary is always printed, regardless of `--format`. This is intentional so you can see findings in the terminal even when you only want a Markdown file in CI artifacts.

### 7.4 `--rules-dir`

**Default:** `configguard/rules` (the bundled rules)

**Type:** directory path

A directory containing additional or replacement YAML rule files. Use this to:

- Add your own org-specific rules.
- Test a rule locally before contributing it upstream.
- Run a curated rule pack (e.g., a "PCI-DSS-strict" subset).

The directory layout must match the bundled rules: one YAML file per rule, with `id`, `name`, `category`, `severity`, `match`, `condition`, and `finding` fields. See [Section 11](#11-custom-rule-packs) for the schema and examples.

```bash
# Use a custom rule pack
configguard audit router.conf --rules-dir ~/my-rules/

# Combine bundled + custom (advanced — symlink or merge)
configguard audit router.conf --rules-dir ./all-rules/
```

> **Empty directory behavior:** if `--rules-dir` is empty, ConfigGuard falls back to the legacy rule engine (regex on raw config text). No crash, no warning. This is useful for smoke-testing a fresh install.

### 7.5 `--explain`

**Default:** off

**Type:** flag (no value)

Placeholder for LLM-augmented explanations. Currently a no-op for forward compatibility: the flag is accepted, the audit completes, and the report includes the standard evidence. The LLM-backed explanation is planned for a future release; the flag exists so scripts and CI configs won't break when it lands.

```bash
configguard audit router.conf --explain   # accepted, no behavior change yet
```

### 7.6 `--verbose`

**Default:** off

**Type:** flag

Reserved for future use. Currently a no-op. When enabled, future versions will print additional context to STDOUT (timing, signals extracted, rule evaluation trace). Use it today to make scripts forward-compatible.

### 7.7 `--use-context` / `--no-use-context`

**Default:** `--use-context` (enabled)

ConfigGuard has two rule-evaluation paths:

- **Context-based (default):** parser → signals → contexts → per-context rules. Required for rules that depend on extracted signals (e.g., "SNMP community is `public`").
- **Legacy:** regex on the raw config text. Faster, but cannot express signal-aware conditions.

The flag exists so you can disable context-based evaluation when:

- You're debugging a parser regression.
- You're on a config format that the context-based engine doesn't recognize yet.
- You want a baseline comparison.

```bash
# Disable context-based evaluation (use legacy engine)
configguard audit router.conf --no-use-context
```

If no rules declare `applies_to`, ConfigGuard silently falls back to legacy mode — the flag is irrelevant in that case.

### 7.8 `--debug-contexts`

**Default:** off

**Type:** flag

Prints the full extracted `SignalContext` list as JSON to STDOUT, *before* rule evaluation. Use this when:

- A rule isn't firing and you suspect a signal-extraction problem.
- You're writing a custom rule and want to see the context keys the engine produces.
- You're filing a bug and want to attach a reproducible context dump.

```bash
configguard audit router.conf --debug-contexts
```

Output (abbreviated):

```
--- DEBUG: SignalContexts ---
{
  "contexts": [
    {
      "context_key": "snmp",
      "signals": [
        { "type": "snmp_community", "value": "public", "metadata": { "acl": "RO" } },
        { "type": "snmp_community", "value": "private", "metadata": { "acl": "RW" } }
      ]
    },
    { "context_key": "http", "signals": [...] },
    { "context_key": "line.vty.0", "signals": [...] }
  ],
  "count": 3
}
--- END DEBUG ---
```

The dump is in addition to (not a replacement for) the regular audit summary.

### 7.9 `--risk-score`

**Default:** off

**Type:** flag

Enables the v0.3 weighted risk-score engine. The score is a single number from 0 to 100 with a level (NONE / LOW / MEDIUM / HIGH / CRITICAL), plus breakdowns by severity and category.

When enabled, the STDOUT summary gains a `--- Risk Assessment (v0.3) ---` section at the end:

```bash
configguard audit router.conf --risk-score
```

```
--- Risk Assessment (v0.3) ---
Risk Score: 78/100 (HIGH)
Contexts Covered: 3
Severity Breakdown: { 'HIGH': 3, 'MEDIUM': 0, 'LOW': 0 }
Category Breakdown: { 'management-plane': 2, 'snmp-security': 1 }
```

Use this when you need a single number for dashboards or trend tracking. The risk score is *not* a substitute for individual findings — it's a rollup.

### 7.10 `--fail-on`

**Default:** `none`

**Choices:** `none`, `low`, `medium`, `high`

The CI gating flag. When set to anything other than `none`, ConfigGuard exits with code `1` if any `FAIL` finding has severity at or above the threshold.

Matrix:

| `--fail-on` | Exits 1 if any FAIL finding has severity... | Example |
| --- | --- | --- |
| `none` | (never) | `configguard audit router.conf` |
| `low` | `LOW`, `MEDIUM`, or `HIGH` | Strict mode — block on any violation |
| `medium` | `MEDIUM` or `HIGH` | Reasonable default for most teams |
| `high` | `HIGH` | Loose mode — only the most serious |
| `bogus` | (invalid value) | Exits 2, no reports written |

Examples:

```bash
# Block PRs on any high-severity violation
configguard audit router.conf --fail-on high

# Block on anything at MEDIUM or higher (recommended for production)
configguard audit router.conf --fail-on medium

# Only block on the most serious issues
configguard audit router.conf --fail-on high
```

The exit code is `1` on threshold breach, `0` otherwise. The error message goes to stderr and identifies the breached findings count:

```
--fail-on high: 3 finding(s) at or above high severity. Exiting 1.
```

> **Tip:** combine with `--no-use-context` for fast linting in pre-commit, then run the full context-based engine in CI for thoroughness.

### 7.11 Quick matrix

| Flag | Default | Purpose |
| --- | --- | --- |
| `--output-dir` | `./output` | Where to write reports |
| `--format` | `all` | Which report formats to write |
| `--rules-dir` | `configguard/rules` | Custom rule pack |
| `--explain` | off | (Reserved) LLM explanations |
| `--verbose` | off | (Reserved) verbose output |
| `--use-context` | on | Context-based rule engine |
| `--debug-contexts` | off | Dump extracted contexts to STDOUT |
| `--risk-score` | off | v0.3 weighted risk score |
| `--fail-on` | `none` | Exit non-zero on severity threshold |

---

## 8. Output formats in detail

### 8.1 STDOUT summary (always printed)

```
JSON report: output/20260602_143022_router.report.json
Markdown report: output/20260602_143022_router.report.md

--- Audit Summary ---
[FAIL] CISCO-MGMT-001 Disable Telnet
       Severity: HIGH
       Category: management-plane
       Block: line.vty.0
       Evidence: VTY line 0: transport input contains 'telnet'
... (more findings) ...

Total: 3 findings (3 failed, 0 warnings, 0 passed)
```

Designed to be readable in a terminal. One block per finding. The first line of each block is the status icon `[FAIL]` / `[WARN]` / `[PASS]`, the rule ID, and the rule name.

### 8.2 JSON report

Stable, machine-readable. Use this for tooling, dashboards, and any non-trivial automation.

Top-level shape:

```json
{
  "version": "0.1.0",
  "compliance": {
    "status": "NON-COMPLIANT",
    "score": 78,
    "level": "HIGH",
    "risk_areas": ["management-plane", "snmp-security"]
  },
  "risk_assessment": {
    "score": 78,
    "level": "HIGH",
    "finding_count": 3,
    "severity_breakdown": { "HIGH": 3, "MEDIUM": 0, "LOW": 0 },
    "category_breakdown": { "management-plane": 2, "snmp-security": 1 },
    "context_coverage": 3
  },
  "summary": {
    "total": 3,
    "pass": 0,
    "fail": 3,
    "warnings": 0
  },
  "findings": [
    {
      "rule_id": "CISCO-MGMT-001",
      "rule_name": "Disable Telnet",
      "category": "management-plane",
      "severity": "HIGH",
      "status": "FAIL",
      "evidence": "VTY line 0: transport input contains 'telnet'",
      "block_type": "vty",
      "block_name": "line.vty.0",
      "remediation": "...",
      "references": [
        { "type": "cis-benchmark", "id": "2.3.1", "url": "https://..." }
      ]
    }
  ],
  "metadata": {
    "config_name": "router",
    "device_type": "Cisco IOS",
    "parser_version": "0.1.0",
    "rules_version": "0.1.0",
    "timestamp": "2026-06-02T14:30:22+00:00"
  }
}
```

Field stability:

- Top-level keys are stable across patch versions.
- `findings[*]` keys are stable; new fields may be added in minor versions but existing ones will not change.
- `compliance` and `risk_assessment` are always populated. `compliance.status` is `COMPLIANT` when no findings have `status=FAIL`, otherwise `NON-COMPLIANT`. `risk_areas` is a list of category names, ordered by weighted impact (highest first).
- `risk_assessment` is the detailed breakdown that powers the `compliance.score`; see [Section 8.4](#84-risk-score-output) for the math.

### 8.3 Markdown report

Designed to be pasted into a PR description, a Confluence page, or an email. Contains the same findings plus full descriptions, remediation steps, and CIS references.

Layout:

```markdown
# ConfigGuard Audit Report

**Config:** router
**Generated:** 2026-06-02 14:30:22
**Tool:** configguard v0.1.0

## Summary

| Status | Count |
| --- | --- |
| ❌ FAIL | 3 |
| ⚠️ WARN | 0 |
| ✅ PASS | 0 |

## Findings

### ❌ CISCO-MGMT-001 — Disable Telnet

- **Severity:** HIGH
- **Category:** management-plane
- **Block:** `line.vty.0`
- **Evidence:** VTY line 0: transport input contains 'telnet'
- **References:** CIS Benchmark 2.3.1, ...

**Description:** Telnet transmits credentials in plaintext...

**Remediation:** Replace `transport input telnet` with `transport input ssh`...

---

### (more findings) ...
```

The Markdown is generated from the same data as the JSON, so the two are always consistent.

### 8.4 Risk score output

Computed for every audit (the `--risk-score` flag is now a no-op kept for backward compatibility). The score is a weighted aggregate based on severity, finding count, and context coverage, and appears in three places:

**1. STDOUT — the `=== Compliance Assessment ===` block:**

```
=== Compliance Assessment ===

Overall Status: NON-COMPLIANT

Compliance Score: 78/100 (HIGH)

Risk Areas:
  - management-plane
  - snmp-security
```

**2. JSON — the `compliance` block** (top-level summary, see [Section 8.2](#82-json-report) for the full schema):

```json
"compliance": {
  "status": "NON-COMPLIANT",
  "score": 78,
  "level": "HIGH",
  "risk_areas": ["management-plane", "snmp-security"]
}
```

**3. JSON — the `risk_assessment` block** (detailed breakdown for dashboards and trend tracking):

```json
"risk_assessment": {
  "score": 78,
  "level": "HIGH",
  "finding_count": 3,
  "severity_breakdown": { "HIGH": 3, "MEDIUM": 0, "LOW": 0 },
  "category_breakdown": { "management-plane": 2, "snmp-security": 1 },
  "context_coverage": 3
}
```

Level thresholds (v0.3):

| Score | Level |
| --- | --- |
| 0 | NONE |
| 1–29 | LOW |
| 30–59 | MEDIUM |
| 60–89 | HIGH |
| 90–100 | CRITICAL |

---

## 9. Common workflows

### 9.1 Auditing a single router

The basic case:

```bash
configguard audit router.conf
```

Open the Markdown report and review the findings. No magic.

### 9.2 Auditing many devices in batch

ConfigGuard audits one file at a time. To audit many, loop in shell:

```bash
mkdir -p reports
for conf in configs/*.conf; do
  base=$(basename "$conf" .conf)
  configguard audit "$conf" --output-dir reports --format json
done
```

Each run writes a unique timestamped file in `reports/`. You can aggregate them with `jq`:

```bash
# Count total failures across all reports
jq -s '[.[].summary.failed] | add' reports/*.report.json

# List all unique rule IDs that fired
jq -r '.findings[].rule_id' reports/*.report.json | sort -u
```

### 9.3 Auditing a config from stdin

The `audit` command takes a file path, not a stream. If you need to audit a config that lives in a pipeline:

```bash
# Get a config from a vault, an API, or `kubectl exec`, then write to a temp file
kubectl exec cisco-router -- cat /etc/router.conf > /tmp/router.conf
configguard audit /tmp/router.conf
```

If you want true stdin support, file an issue — it's on the roadmap.

### 9.4 Pre-commit hook

Catch violations before they reach the repo:

```bash
# .git/hooks/pre-commit
#!/bin/bash
# Audit any .conf / .cfg / .txt file that was added or modified
changed=$(git diff --cached --name-only --diff-filter=AM | grep -E '\.(conf|cfg|txt)$')
if [ -n "$changed" ]; then
  tmp=$(mktemp -d)
  trap "rm -rf $tmp" EXIT
  for f in $changed; do
    configguard audit "$f" --output-dir "$tmp" --fail-on high
  done
fi
```

```bash
chmod +x .git/hooks/pre-commit
```

For a more robust pre-commit setup that also runs on the staged content (not the working tree), see the `pre-commit` framework — the community is working on an official `pre-commit-config.yaml` snippet.

### 9.5 Comparing two configs

ConfigGuard has no built-in diff mode. Workaround: audit both, then diff the JSON:

```bash
configguard audit before.conf --output-dir /tmp/before --format json
configguard audit after.conf  --output-dir /tmp/after  --format json
diff <(jq -S . /tmp/before/*.report.json) <(jq -S . /tmp/after/*.report.json)
```

For a more readable diff:

```bash
diff \
  <(jq '.findings | map({rule_id, status, evidence})' /tmp/before/*.report.json) \
  <(jq '.findings | map({rule_id, status, evidence})' /tmp/after/*.report.json)
```

---

## 10. CI integration recipes

### 10.1 GitHub Actions (basic)

```yaml
# .github/workflows/audit.yml
name: Config audit
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install configguard
      - run: configguard audit configs/ --fail-on high
        # Note: see "Auditing many devices" above for a loop pattern;
        # `audit configs/` only works if `configs/` is a single file.
```

The `--fail-on high` makes the step exit 1 on any HIGH finding, which fails the workflow. The Markdown report (in `output/`) is uploaded as a workflow artifact:

```yaml
      - run: configguard audit router.conf --fail-on high
      - uses: actions/upload-artifact@v4
        with:
          name: configguard-report
          path: output/*.report.md
```

### 10.2 GitHub Actions (matrix: many devices)

```yaml
name: Config audit (all devices)
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        config: [router-01, router-02, switch-01, firewall-01]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install configguard
      - run: configguard audit configs/${{ matrix.config }}.conf --fail-on high
      - uses: actions/upload-artifact@v4
        with:
          name: report-${{ matrix.config }}
          path: output/*.report.md
```

### 10.3 GitLab CI

```yaml
# .gitlab-ci.yml
audit:
  image: python:3.12-slim
  script:
    - pip install configguard
    - configguard audit router.conf --fail-on high
  artifacts:
    when: always
    paths:
      - output/
```

### 10.4 Jenkins

```groovy
stage('Config audit') {
  agent {
    docker { image 'python:3.12-slim' }
  }
  steps {
    sh 'pip install configguard'
    sh 'configguard audit router.conf --fail-on high'
  }
  post {
    always {
      archiveArtifacts artifacts: 'output/*.report.md', allowEmptyArchive: true
    }
  }
}
```

### 10.5 Severity-tiered gating

Some teams want different thresholds for different environments. A common pattern:

```bash
# dev branch: warn but don't block
configguard audit router.conf --fail-on none  # exits 0 always

# main branch: block on HIGH
configguard audit router.conf --fail-on high

# release branch: block on MEDIUM
configguard audit router.conf --fail-on medium
```

In GitHub Actions, branch-conditional thresholds:

```yaml
- name: Config audit
  run: |
    if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
      threshold=high
    elif [[ "${{ github.ref }}" =~ ^refs/heads/release/ ]]; then
      threshold=medium
    else
      threshold=none
    fi
    configguard audit router.conf --fail-on $threshold
```

---

## 11. Custom rule packs

If you want to enforce org-specific policies beyond the bundled CIS rules, write a YAML rule and put it in a directory, then pass `--rules-dir`.

### 11.1 Minimum rule schema

```yaml
id: ORG-001
name: No Hardcoded TACACS Key
category: authentication
severity: HIGH

match:
  type: regex
  pattern: "tacacs-server key .+"

condition: present

finding:
  status: FAIL
  evidence: true

description: >
  TACACS shared keys must come from a secrets manager, not be
  embedded in the config.

remediation: >
  Replace inline keys with a reference to the secrets vault.

references:
  - type: internal-policy
    id: "SEC-042"
```

### 11.2 Field reference

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Unique rule ID. Use your org prefix to avoid collisions (e.g., `ORG-001`). |
| `name` | yes | Short human-readable name. |
| `category` | yes | Logical grouping (e.g., `authentication`, `management-plane`). |
| `severity` | yes | `LOW`, `MEDIUM`, or `HIGH`. |
| `applies_to` | recommended | `category` and/or `block_type` filters for context-based rules. |
| `match.type` | yes | Currently `regex`. |
| `match.pattern` | yes | The regex to match. |
| `condition` | yes | `present` (rule fires if match found) or `absent` (rule fires if match NOT found). |
| `finding.status` | yes | `FAIL`, `WARN`, or `PASS`. |
| `finding.evidence` | yes | `true` to capture matched text, or a custom format string. |
| `description` | yes | Markdown block. |
| `remediation` | yes | Markdown block. |
| `references` | no | List of `{type, id, url}` records. |

### 11.3 Context-based rules

For rules that depend on extracted signals (e.g., a specific SNMP community string), add `applies_to`:

```yaml
id: ORG-002
name: Reject Default SNMP Community 'public'
category: snmp-security
severity: HIGH

applies_to:
  category:
    - snmp

match:
  type: signal
  signal_type: snmp_community
  value_pattern: "^public$"

condition: present

finding:
  status: FAIL
  evidence: true

description: >
  The default SNMP community string 'public' is well-known and must
  not be used.

remediation: >
  Choose a non-default community string with at least 32 bits of entropy.

references:
  - type: cis-benchmark
    id: "2.2.2"
```

For the full schema, see `configguard/rules/` (the bundled rules) and `tests/cases/` (ground-truth test inputs).

### 11.4 Test your custom rules

The bundled test harness is rule-agnostic. Add a test case directory to `tests/cases/`:

```bash
tests/cases/
  case_021_tacacs_inline_key/
    config.txt        # your test config
    expected.json     # expected findings
    metadata.yaml     # optional, for documentation
```

Then run `pytest tests/test_engine_all_cases.py -k case_021`. See the existing cases for the `expected.json` format.

---

## 12. Troubleshooting

### 12.1 "command not found: configguard"

The install didn't put `configguard` on your `PATH`. Check:

```bash
which configguard
pip show configguard | grep Location
```

If `pip show` finds it but `which` doesn't, add the script directory to your `PATH`. For a `--user` install, it's typically `~/.local/bin`:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"
```

If `pip show` doesn't find it at all, the install failed. Re-run with verbose output:

```bash
pip install -v configguard
```

### 12.2 "No module named configguard" when running `python3 -m configguard.cli`

You have multiple Python versions and `pip` installed into a different one. Use the same Python you installed to:

```bash
python3 -m pip install configguard
python3 -m configguard.cli audit router.conf
```

### 12.3 "Error: Failed to parse <config>: ..."

The parser doesn't recognize the syntax in your config file. Common causes:

- The file is not Cisco IOS syntax (e.g., it's Junos, NX-OS, or IOS-XE with new-style `interface` blocks).
- The file has Windows line endings (`\r\n`). Fix with `dos2unix router.conf` or `tr -d '\r' < router.conf > router.unix.conf`.
- The file is binary or has non-UTF-8 bytes.

ConfigGuard 0.1.0 covers classic Cisco IOS 12.x – 15.x. For other vendors, see the [roadmap](README.md#supported-platforms).

If you believe the parser should handle your config, please open an issue with the config (sanitized of secrets) and the error message.

### 12.4 A rule isn't firing on a config I'm sure violates it

1. **Check `--debug-contexts` first.** This prints the extracted signals. If the signal isn't there, the rule won't fire — the issue is signal extraction, not rule evaluation.
2. **Check the rule's `applies_to` block.** Context-based rules only fire for the block types listed there.
3. **Check your `--rules-dir`.** If you point it at a directory that doesn't contain the rule, it gets bypassed.
4. **Try `--no-use-context`.** If the rule fires in legacy mode but not context-based, you've found a regression in the context-based engine — please file an issue.

### 12.5 The reports have stale data from a previous run

The timestamped filename pattern (`<YYYYMMDD>_<HHMMSS>_<basename>.report.{json,md}`) means each run creates a new file. Old files are not deleted. If your `output/` directory is full of historical reports, clean it up:

```bash
rm -rf output/   # safe — it's in .gitignore
```

For long-term archival, version the reports by date:

```bash
configguard audit router.conf --output-dir reports/2026-06-02/
```

### 12.6 Performance issues on large configs

ConfigGuard is fast — sub-second on a 10,000-line config on modern hardware. If you see slowness:

- **Profile the rule pack.** Custom rules with large `regex` patterns can be slow. Test with `time configguard audit huge.conf` and isolate.
- **Run with `--no-use-context`.** Legacy engine is faster when you don't need signal-aware rules.
- **Check the parser.** Some malformed configs can cause the parser to do extra passes. Fix the config or open an issue.

### 12.7 CI: exit code is 0 but I expected 1

- The findings are `WARN` or `PASS`, not `FAIL`. `--fail-on` only triggers on `FAIL`.
- The findings are below the threshold. e.g., `--fail-on high` ignores `LOW` and `MEDIUM` findings.
- You're checking the exit code of a piped command (`configguard ... | tee log.txt` — `$?` is `tee`'s exit, not ConfigGuard's). Use `${PIPESTATUS[0]}` in bash, or run without pipes.

---

## 13. FAQ

**Q: Does ConfigGuard need device access?**
No. It's a static analyzer. It reads a config file from disk and never connects to anything.

**Q: Can I audit a running router's config directly?**
Not in 0.1.0. Pipe the config to a file first:

```bash
ssh router 'show running-config' > router.conf
configguard audit router.conf
```

**Q: Does ConfigGuard work on IOS-XE / NX-OS / Junos / EOS?**
Not in 0.1.0. Classic IOS 12.x – 15.x is the current target. Multi-vendor is on the [roadmap](README.md#supported-platforms).

**Q: Is the rule set exhaustive?**
No — it's a focused subset of the most common CIS Cisco IOS Benchmark violations (10 rules in 0.1.0). Coverage grows by contribution. See the [rules table in the README](README.md#rules).

**Q: Can I add rules?**
Yes — see [Section 11](#11-custom-rule-packs). Custom rules live in a `--rules-dir`; the bundled rules are not modified.

**Q: How do I keep ConfigGuard up to date?**
```bash
pip install --upgrade configguard
```

**Q: Is ConfigGuard safe to run on a production config file?**
Yes. It only reads the file. It does not modify the file, send it anywhere, or execute anything from it. The output reports are the only thing written.

**Q: What's the license?**
[MIT](LICENSE). You can use it in commercial and personal projects.

**Q: Can I run ConfigGuard in a Docker container?**
Yes:

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir configguard
ENTRYPOINT ["configguard"]
```

```bash
docker build -t my-configguard .
docker run --rm -v $(pwd)/configs:/configs my-configguard audit /configs/router.conf
```

**Q: How can I contribute?**
See [CONTRIBUTING.md](CONTRIBUTING.md) (TODO — link will be added when the file exists). For now: file issues, open PRs against the bundled rules, or send test cases for configs that should pass/fail.

---

## 14. Getting help

If this guide didn't answer your question:

- **Read the source.** ConfigGuard is small (~2000 LOC). The rule engine is in `configguard/engine.py`. The rules are in `configguard/rules/`.
- **Search existing issues:** [github.com/qiulinhai/configguard/issues](https://github.com/qiulinhai/configguard/issues)
- **Open a new issue.** Include: the command you ran, the config (sanitized of secrets), the full output, and the version (`configguard --version`).
- **For security issues,** email the maintainer directly rather than filing a public issue.

---

*This guide covers ConfigGuard 0.1.0. If you're on a different version, check the [release notes](docs/releases/) for changes.*
