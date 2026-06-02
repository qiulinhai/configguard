# ConfigGuard

**Static analysis for Cisco IOS configs, CIS-aligned.** Catch hardcoded SNMP community strings, plaintext Telnet, missing AAA, and other CIS Benchmark violations — before they ship.

ConfigGuard is a CLI tool that audits Cisco IOS configuration files against the [CIS Cisco IOS Benchmark](https://www.cisecurity.org/benchmark/cisco_ios). It works entirely offline on a config file: no device access, no probe timing, no false positives from unreachable services.

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

## Why ConfigGuard

- **No network access.** Runs on a config file — safe for backups, git history, or any text you have on disk.
- **CIS-mapped out of the box.** Every rule links to a CIS Benchmark section, a NIST 800-53 control, and (where applicable) a CVE.
- **CI-native.** `--fail-on {low|medium|high}` returns a non-zero exit code so you can block PRs that introduce violations.
- **Deterministic.** Same input → same output. No probe timing, no banner-grabbing flakes.
- **Block-aware parser.** Understands Cisco IOS configuration blocks (`interface`, `line vty`, `router`, `aaa`, `snmp-server`, `ip http`).
- **Three output formats.** JSON for tooling, Markdown for humans, terminal for ad-hoc use.

## Install

```bash
pip install configguard
```

Or from a checkout:

```bash
git clone https://github.com/lhqiu/configguard.git
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

- **Cisco IOS 12.x – 15.x** (classic IOS syntax)

Not yet supported: IOS-XE, IOS-XR, NX-OS, Juniper Junos, Arista EOS. ConfigGuard is intentionally Cisco-first — adding multi-vendor support would dilute rule quality before the CIS coverage is complete.

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
