# Changelog

All notable changes to ConfigGuard are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`configguard fleet audit <dir>`** — audit a directory of configs in one invocation
- **Snapshot v1 contract** — self-contained, version-stamped canonical artifact (`fleet.snapshot.json`); Phase 2's `fleet diff` will read it
- **Per-device JSON reports** for fleet audits (`devices/<name>.report.json`), same shape as the single-file `audit` JSON
- **`services/audit_service.py`** — shared "load → parse → evaluate → score → return" pipeline used by both `audit` and `fleet audit`
- **`--snapshot-name NAME`** flag (default `fleet`) for naming fleet snapshots
- **`--include GLOB`** flag (repeatable) for filtering config files (defaults: `*.conf`, `*.txt`, `*.cfg`)
- **`--quiet`** flag to suppress per-device progress on stdout
- **`configguard.audit_service.run_audit()`** public function for embedding audit in other tools

## [0.1.0] - 2026-06-02

### Added
- Initial public release
- **Network Configuration Compliance Platform** framing — audits Cisco IOS configurations against CIS Benchmarks
- **10 bundled CIS rules** covering authentication (AAA, console), management plane (telnet, HTTP, VTY), SNMP (v2c), logging (syslog, NTP), and interface hygiene
- **Block-aware Cisco IOS parser** that understands `interface`, `line vty`, `router`, `aaa`, `snmp-server`, and `ip http` configuration blocks
- **Compliance Assessment** headline in STDOUT — overall status, weighted score, level (NONE/LOW/MEDIUM/HIGH/CRITICAL), and top risk areas
- **Three output formats**: JSON (for tooling and dashboards), Markdown (for humans), STDOUT (for ad-hoc use)
- **`--fail-on {none|low|medium|high}`** for CI gating — returns non-zero exit code on threshold breach
- **`--explain`** flag (placeholder for future LLM-augmented remediation hints)
- **`--debug-contexts`** flag for inspecting the extracted `SignalContext` list as JSON
- **Custom rule packs** — point `--rules-dir` at any directory of YAML files matching the rule schema
- **JSON schema**: stable top-level fields (`compliance`, `risk_assessment`, `summary`, `findings`, `metadata`) — see [user guide §8.2](docs/user-guide.md#82-json-report)
- **JSON and Markdown reports** now lead with the same Compliance Assessment summary the user sees on STDOUT
- **GitHub Actions CI**: matrix-tested on Python 3.10, 3.11, 3.12; separate packaging job builds sdist + wheel and installs from the sdist as a smoke test
- **PyPI publish workflow** via Trusted Publishing (OIDC) — no API token stored
- **User guide** ([docs/user-guide.md](docs/user-guide.md)) — 14 sections covering installation, CLI reference, every output format, CI recipes, custom rule packs, troubleshooting, and FAQ
- **Maintainer release guide** ([docs/RELEASING.md](docs/RELEASING.md)) — PyPI trusted publisher setup and release tagging
- **README** with product positioning, "How it works" pipeline diagram, roadmap, and worked examples

[Unreleased]: https://github.com/qiulinhai/configguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/qiulinhai/configguard/releases/tag/v0.1.0
