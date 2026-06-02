# ConfigGuard

[![CI](https://github.com/qiulinhai/configguard/actions/workflows/ci.yml/badge.svg)](https://github.com/qiulinhai/configguard/actions/workflows/ci.yml)

**Network Configuration Compliance Platform.**

Continuously assess network device configurations against CIS Benchmarks, security baselines, and operational policies. ConfigGuard transforms raw network configurations into structured, audit-ready compliance data:

```
   Cisco Config
         │
         ▼

   Compliance Assessment

         │

         ├── Security Findings
         ├── Risk Score
         ├── Audit Evidence
         ├── Compliance Status
         └── Remediation Guidance
```

**Starting with Cisco IOS. Built for multi-vendor network compliance.**

ConfigGuard is a CLI tool that ingests a config file and produces a compliance report — no device access, no probe timing, no false positives from unreachable services. It runs entirely offline on a text file.

## See it run

```bash
$ configguard audit examples/sample_router.txt

JSON report: output/20260602_055630_sample_router.report.json
Markdown report: output/20260602_055630_sample_router.report.md

--- Audit Summary ---
[FAIL] CISCO-MGMT-002 Disable HTTP Server
       Severity: HIGH
       Category: management-plane
       Evidence: HTTP server: enabled
[FAIL] CISCO-SNMP-001 Disable SNMP v2c
       Severity: HIGH
       Category: snmp-security
       Evidence: SNMP v2c enabled with 1 community strings: public

Total: 2 findings (2 failed, 0 warnings, 0 passed)
```

The example config intentionally mixes violations and compliant sections so the tool's discrimination is visible.

## Risk Score

Pass `--risk-score` to get a 0–100 weighted compliance score and a level classification alongside the findings. The score rolls up severity, finding count, and category coverage into a single number you can track over time or roll up across a fleet.

```bash
$ configguard audit router.conf --risk-score
```

```
[FAIL] CISCO-MGMT-001 Disable Telnet
       Severity: HIGH
       ...
[FAIL] CISCO-MGMT-002 Disable HTTP Server
       Severity: HIGH
       ...
[FAIL] CISCO-SNMP-001 Disable SNMP v2c
       Severity: HIGH
       ...
[FAIL] CISCO-AUTH-001 AAA Required
       Severity: HIGH
       ...
[FAIL] CISCO-MGMT-003 Secure VTY Configuration
       Severity: HIGH
       ...
[FAIL] CISCO-IF-001 Unused Interfaces Must Be Shutdown
       Severity: MEDIUM
       ...

Total: 6 findings (6 failed, 0 warnings, 0 passed)

--- Risk Assessment (v0.3) ---
Risk Score: 100/100 (CRITICAL)
Contexts Covered: 5
Severity Breakdown: {'HIGH': 50, 'MEDIUM': 5}
Category Breakdown: {'management-plane': 45, 'interface-hygiene': 5, 'authentication': 13, 'snmp-security': 12}
```

Score → level mapping:

| Score | Level |
| --- | --- |
| 0 | NONE |
| 1–29 | LOW |
| 30–59 | MEDIUM |
| 60–89 | HIGH |
| 90–100 | CRITICAL |

A clean config scores **0 / 100 (NONE)**. A config with several HIGH findings scores in the **90–100 (CRITICAL)** range. Mid-range scores come from multiple MEDIUM findings or partial context coverage — useful for tracking progress as a fleet moves from "mostly broken" toward "mostly clean."

The score is also available in the JSON report (under `risk_assessment`) for dashboards and trend tracking.

## Why ConfigGuard

- **No network access.** Runs on a config file — safe for backups, git history, or any text you have on disk.
- **CIS-mapped out of the box.** Every rule links to a CIS Benchmark section, a NIST 800-53 control, and (where applicable) a CVE.
- **CI-native.** `--fail-on {low|medium|high}` returns a non-zero exit code so you can block PRs that introduce violations.
- **Deterministic.** Same input → same output. No probe timing, no banner-grabbing flakes.
- **Block-aware parser.** Understands Cisco IOS configuration blocks (`interface`, `line vty`, `router`, `aaa`, `snmp-server`, `ip http`).
- **Three output formats.** JSON for tooling, Markdown for humans, terminal for ad-hoc use.

## How it works

ConfigGuard's pipeline is what makes it a *compliance platform* rather than a regex linter. Each stage is composable and replaceable — multi-vendor support slots in at the Parser stage, not at the engine.

```
   Cisco IOS Config
          │
          ▼
      Parser             Block-aware, deterministic
          │
          ▼
      Signals            Typed facts (e.g. snmp_community="public")
          │
          ▼
      Contexts           Block-keyed groupings
          │
          ▼
      Compliance         YAML-defined controls,
      Engine             weighted risk aggregation
          │
          ├──►  Security Findings
          ├──►  Risk Score
          ├──►  Audit Evidence
          └──►  Reports (JSON + Markdown + STDOUT)
```

Each stage does one thing:

- **Parser** — turns raw config text into a structured intermediate representation. Block-aware (recognizes `interface`, `line vty`, `router`, `aaa`, `snmp-server`, `ip http`).
- **Signals** — typed facts extracted from blocks (e.g. `snmp_community="public"`, `http_server_enabled=true`). Signals are the atomic unit of compliance knowledge.
- **Contexts** — block-keyed groupings of related signals. A `snmp` context contains all the community strings; an `http` context contains server state. This is what lets multiple rules evaluate the same evidence without duplicating logic.
- **Compliance Engine** — evaluates YAML-defined controls against contexts and produces findings. The same engine that runs CIS rules today can run PCI-DSS or NIST 800-53 controls tomorrow with no engine changes — only new YAML.
- **Outputs** — Findings (PASS / FAIL / WARN), a weighted Risk Score, the exact evidence (the config line that triggered the violation), and structured reports.

The key idea: **add a new vendor by adding a parser, not by changing the engine.** That's what makes this scale beyond Cisco IOS without rewriting rules.

## Install

```bash
pip install configguard
```

Or from a checkout:

```bash
git clone https://github.com/qiulinhai/configguard.git
cd configguard
pip install -e .
```

Requires Python 3.10+.

## Quick start

```bash
# Audit a config (writes reports to ./output/)
configguard audit path/to/router.conf

# Just the JSON
configguard audit router.conf --format json

# Just the Markdown
configguard audit router.conf --format markdown

# CI gate: exit non-zero if any HIGH finding is present
configguard audit router.conf --fail-on high
```

For a complete walkthrough — every flag, every output format, CI recipes, custom rule packs, troubleshooting — see the **[User Guide](docs/user-guide.md)**.

Run `--help` for the full option list, including `--explain` (LLM-augmented remediation hints) and `--risk-score` (v0.3 weighted risk scoring).

## Rules

Ten rules across five security domains. Each rule's YAML declares its CIS Benchmark section, NIST 800-53 control, and (where applicable) CVE mapping.

| Rule ID | Name | Severity | Domain | CIS Ref |
| --- | --- | --- | --- | --- |
| [CISCO-AUTH-001](configguard/rules/auth/aaa_required.yaml) | AAA Required | HIGH | Authentication | 1.1.1 |
| [CISCO-AUTH-001b](configguard/rules/auth/aaa_missing.yaml) | AAA Disabled | HIGH | Authentication | 1.1.1 |
| [CISCO-AUTH-002](configguard/rules/auth/console_auth.yaml) | Console Authentication Required | HIGH | Authentication | 1.2.1 |
| [CISCO-MGMT-001](configguard/rules/management/disable_telnet.yaml) | Disable Telnet | HIGH | Management | 2.3.1 |
| [CISCO-MGMT-002](configguard/rules/management/disable_http.yaml) | Disable HTTP Server | HIGH | Management | 2.2.1 |
| [CISCO-MGMT-003](configguard/rules/management/secure_vty.yaml) | Secure VTY Configuration | HIGH | Management | 2.3.2 |
| [CISCO-SNMP-001](configguard/rules/snmp/snmp_v2_disabled.yaml) | Disable SNMP v2c | HIGH | SNMP | 2.2.2 |
| [CISCO-LOG-001](configguard/rules/logging/remote_syslog.yaml) | Remote Syslog Required | MEDIUM | Logging | 4.1.1 |
| [CISCO-LOG-002](configguard/rules/logging/ntp_config.yaml) | NTP Configuration Required | MEDIUM | Logging | 4.2.1 |
| [CISCO-IF-001](configguard/rules/interface/unused_shutdown.yaml) | Unused Interfaces Must Be Shutdown | MEDIUM | Interface | 3.1.1 |

## CI integration

Block PRs that introduce high-severity config drift:

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
        with: { python-version: "3.10" }
      - run: pip install configguard
      - run: configguard audit configs/ --fail-on high
```

The `--fail-on` flag accepts `none`, `low`, `medium`, `high`. The exit code is non-zero when any FAIL finding meets the threshold.

## Supported platforms

- **Cisco IOS 12.x – 15.x** (classic IOS syntax) — current coverage

Multi-vendor support (IOS-XE, SONiC, Juniper Junos, Arista EOS) is on the [roadmap](#roadmap). Adding a new vendor means a parser + rule set, not engine changes.

## Roadmap

### v0.2 — Deeper analysis
- Weighted risk scoring across all findings (v0.3 prototype already shipped; v0.2 promotes it to default)
- Compliance categories (CIS Authentication, CIS Management Plane, etc.) as first-class grouping for reports
- Richer audit reports: control narrative, evidence trail, and remediation steps in a single document

### v0.3 — Intelligent remediation
- AI-assisted remediation guidance: turn each finding into a concrete, copy-pasteable config fix
- Compliance trend tracking: store audit history, surface drift over time
- Custom control packs: orgs can ship their own YAML control sets alongside the bundled CIS rules

### v0.4 — Multi-vendor
- **Cisco IOS-XE** — second parser, same engine, same rule format
- **SONiC** — data-center switch fabric
- **Juniper Junos** — service provider and enterprise routing

### v0.5 — Fleet-scale
- Compliance dashboard: aggregate risk score across an entire network
- Fleet-wide assessment: run audits across many devices, normalized into a single report
- Diff mode: compare two configs and show what changed in compliance terms

### v1.0 — Network Compliance OS
- A platform surface: API, web UI, integrations with the rest of the security stack (SIEM, ticketing, ITSM)
- Compliance frameworks as first-class citizens: CIS, PCI-DSS, NIST 800-53, ISO 27001 — switchable per audit
- Network Compliance OS: a runnable, configurable, observable system, not a CLI

---

The roadmap is directional. Dates, scope, and order will adjust based on what users actually need. If something here would unblock you, [open an issue](https://github.com/qiulinhai/configguard/issues/new) — issues drive the order.

## Limitations

- **10 rules, not 100.** This is a focused subset of the most common CIS Cisco IOS Benchmark violations, not an exhaustive implementation. Coverage grows by contribution.
- **Regex-based matching.** Some edge cases in valid Cisco syntax may not parse cleanly. Findings are advisory — review before acting.
- **One config at a time.** `audit <file>` takes a single config. To audit many devices, loop in shell or run from CI per-config.

## Contributing

Adding a rule means writing a YAML file. See the existing rules in [`configguard/rules/`](configguard/rules) for the schema, and the ground-truth cases in [`tests/cases/`](tests/cases) for the expected-output format.

Run the test suite with:

```bash
pytest
```

## License

[MIT](LICENSE).

## References

- [CIS Cisco IOS Benchmark](https://www.cisecurity.org/benchmark/cisco_ios) — source of truth for rule IDs and remediation
- [NIST SP 800-53](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search) — control mappings
- [Cisco IOS Hardening Guides](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-a1.html) — remediation guidance
