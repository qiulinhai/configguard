# Promotion Step 1 — README + CI assets + rule provenance

**Date:** 2026-06-01
**Status:** Draft (pending user review)
**Scope:** Make the project credible to a first-time visitor in under 5 minutes. Lay the foundation for the four-step promotion plan proposed in conversation.

## Goal

When a network/security engineer or compliance reader lands on the GitHub repo, within one screen scroll they can answer: (a) what does this tool do, (b) what does the output look like, (c) is the rule set traceable to a known standard, (d) can I drop this into my CI today. The README, a frozen demo output, and a copy-paste GitHub Action + pre-commit hook must together answer all four.

## Non-goals (deferred to later steps)

- PyPI publication (step 2)
- Composite Action (`uses: Lhqiu/ConfigGuard/action@v0.2.1`) — step 1.5
- Docker image — step 2
- Full rule schema reference (`docs/contributing.md`) — follow-up
- PR inline annotations from audit JSON — step 1.5
- LLM `explain` feature promotion — out of scope

## Architecture: what changes, what doesn't

**Changes (12 files modified, 11 files created):**

| File | Change |
|---|---|
| `configguard/models.py` | Add `Reference` dataclass + `references: list[Reference]` on rule model (optional, default `[]`). |
| `configguard/registry.py` | Parse `references:` block in YAML loader. Unknown `type:` values → warning, not error. |
| `configguard/output/markdown.py` | Render references as a bullet list under each finding. |
| `configguard/output/json.py` | Include `references` array in finding JSON. |
| `configguard/cli.py` | Add `--fail-on <severity>` flag. Non-zero exit when any FAIL with severity ≥ threshold exists. Default `none` (preserves current behavior). |
| `configguard/rules/management/disable_telnet.yaml` | Add `references:` block. |
| `configguard/rules/management/disable_http.yaml` | Add `references:` block. |
| `configguard/rules/management/secure_vty.yaml` | Add `references:` block. |
| `configguard/rules/snmp/snmp_v2_disabled.yaml` | Add `references:` block. |
| `configguard/rules/auth/aaa_missing.yaml` | Add `references:` block. |
| `configguard/rules/auth/aaa_required.yaml` | Add `references:` block. |
| `configguard/rules/auth/console_auth.yaml` | Add `references:` block. |
| `README.md` | Full rewrite to layered structure (Section 3 below). |
| `tests/cases/case_020_sample_router/` | New test case. |
| `tests/test_rule_schema.py` | New tests for `references:` field (parse, model, unknown type warning, default empty). |
| `tests/test_cli.py` | Add tests for `--fail-on` (no findings, HIGH fail, MEDIUM fail, threshold respected). |
| `examples/sample_router.txt` | New sample config. |
| `examples/sample_router.stdout.txt` | Frozen STDOUT fixture. |
| `examples/sample_router.report.md` | Frozen Markdown report fixture. |
| `.github/workflows/configguard.yml` | New reusable workflow for users. |
| `.pre-commit-hooks.yaml` | New pre-commit hook definition. |
| `tools/generate_rule_table.py` | New script that emits `docs/rule-table.md` from rule YAMLs. |
| `docs/rule-table.md` | Generated rule table. |

**Unchanged:** Parser, signal extraction, context builder, engine evaluation logic, evidence builder, risk engine, ontology, adapters.

## Section 1: Rule schema extension

### New field

```yaml
references:
  - type: cis-benchmark
    id: "1.1.1"
    url: "https://www.cisecurity.org/benchmark/cisco_ios"
  - type: cisco-hardening-guide
    id: "Configuring Secure Shell"
    url: "https://www.cisco.com/..."
  - type: cve
    id: "CVE-2017-6736"
    url: "https://nvd.nist.gov/vuln/detail/CVE-2017-6736"
```

`type` is a free-form string. Recognized values: `cis-benchmark`, `cisco-hardening-guide`, `cve`, `nist-800-53`, `vendor-advisory`. Unknown values: emit a warning, still load the rule.

### Per-rule references (planned; final values from CIS Cisco IOS Benchmark v15 / Cisco IOS XE hardening docs)

| Rule ID | References |
|---|---|
| CISCO-MGMT-001 (Disable Telnet) | cis-benchmark 2.3.x; cisco-hardening-guide "Configuring Secure Shell" |
| CISCO-MGMT-002 (Disable HTTP) | cis-benchmark 2.2.x; cisco-hardening-guide "HTTP server" |
| CISCO-MGMT-003 (Secure VTY) | cis-benchmark 2.3.x; cisco-hardening-guide "VTY line security" |
| CISCO-SNMP-001 (Disable SNMP v2c) | cis-benchmark 2.2.x; cve CVE-1999-0517 (community string class); cisco-hardening-guide "SNMPv3 migration" |
| CISCO-AUTH-001b (Console auth required) | cis-benchmark 1.x; cisco-hardening-guide "Console line security" |
| CISCO-AUTH-001 (AAA required) | cis-benchmark 1.x; nist-800-53 AC-2 |
| (the third auth/ rule — verify ID at implementation) | (same AAA family) |

Final IDs to be cross-checked against the actual CIS benchmark text at implementation time. The implementation step is allowed to update these mappings but must not drop references. Each of the 7 rules must have at least one CIS reference.

### Backward compatibility

`references:` is optional. The 7 existing rules pass the field as `[]` by default until populated. All existing test cases keep passing without modification.

## Section 2: Demo sample config

**File:** `examples/sample_router.txt`

A realistic ~40-line Cisco IOS config that triggers findings across management, AAA, and SNMP, and includes some passing checks to demonstrate discrimination.

**Required triggered findings (verified by `tests/cases/case_020_sample_router/expected.json`):**

- CISCO-MGMT-001 — Telnet on a VTY line
- CISCO-MGMT-002 — `ip http server`
- CISCO-SNMP-001 — `snmp-server community public RO`
- One aaa/* rule (console auth or AAA new-model, depending on which rules are wired in step 1)

**Required passing checks (verifies "FAIL" isn't the only output):**

- CISCO-MGMT-003 — `transport input ssh` on VTY
- (Optional) a non-violating `interface` block

**Output capture (frozen fixtures):**

- `examples/sample_router.stdout.txt` — `configguard audit` STDOUT
- `examples/sample_router.report.md` — Markdown report

**No automated drift detection in step 1** — a follow-up test will diff generated output against these fixtures. Out of scope here.

## Section 3: README structure

**Length budget:** ~250 lines.

**Section order (top to bottom):**

1. **Title + one-line value prop** — "ConfigGuard — deterministic security auditor for Cisco network device configurations."
2. **Badges** — only existing ones (CI status, license). No fake badges.
3. **What it does** — 3-4 plain-language bullets. No marketing fluff. No exclamation marks.
4. **Quick start** — install + `configguard audit <file>`. Note: `pip install git+...` until PyPI ships.
5. **What you get** — embedded STDOUT from `examples/sample_router.stdout.txt` in a fenced block.
6. **Rule coverage** — include `docs/rule-table.md`. Columns: Rule ID | Name | Severity | Category | CIS reference. Table is regenerated by `tools/generate_rule_table.py`.
7. **Severity model** — one paragraph: HIGH / MEDIUM / LOW semantics; FAIL / WARN / PASS status semantics.
8. **Output formats** — Markdown excerpt, JSON shape, STDOUT — each with a one-line "when to use this."
9. **Run in CI** — two subsections:
   - **GitHub Actions** — drop-in `.github/workflows/configguard.yml` snippet
   - **pre-commit** — hook config snippet
10. **Adding rules** — 1-paragraph pointer to `docs/contributing.md` (will be written in a follow-up; pointer is fine for now).
11. **Architecture** — 1-paragraph pointer to `docs/architecture/`.
12. **License** — existing.

## Section 4: CI assets

### `.github/workflows/configguard.yml`

A workflow intended to be copied by downstream users. Audits changed config files on PR; uploads report as artifact. Comments on `--fail-on`:

- Default `--fail-on` is `none` (preserves v0.2.1 CLI behavior; returns 0 on findings)
- Users add `--fail-on high` (or medium / low) to gate merges
- README documents both modes

### `.pre-commit-hooks.yaml`

Standard pre-commit hook schema. `entry: configguard audit`. `types: [file]`. `files: \.(conf|cfg|txt)$`. `language: python`.

Users add the hook by adding the repo to their own `.pre-commit-config.yaml`. README shows a copy-paste block.

### `--fail-on` flag

CLI option:
- `--fail-on {none,low,medium,high}` (default `none`)
- When set to anything other than `none`: after generating reports, scan findings. If any FAIL with `severity ≥ threshold` exists, `typer.Exit(1)`. Output to STDERR with a one-line message ("X findings at or above <severity> severity").
- Tests cover all 4 modes (none/LOW/MEDIUM/HIGH) and a passing-config case.

## Out of scope (recorded for the next spec)

- PyPI publication
- Composite Action / third-party action marketplace
- Docker image
- PR inline annotations from JSON
- Full rule schema reference doc
- LLM `explain` promotion

## Test plan

- `tests/test_rule_schema.py`
  - Parse a rule with `references:` — model has references populated correctly
  - Parse a rule without `references:` — model has `references == []`
  - Parse a rule with unknown `type:` — rule loads, warning emitted
  - Round-trip: model → JSON output → references array present
- `tests/test_cli.py`
  - `--fail-on none` on a config with HIGH findings: exit 0
  - `--fail-on high` on a config with HIGH findings: exit 1
  - `--fail-on medium` on a config with only HIGH findings: exit 0
  - `--fail-on high` on a clean config: exit 0
- `tests/cases/case_020_sample_router/`
  - `config.txt` — copy of `examples/sample_router.txt`
  - `expected.json` — expected findings list
  - `metadata.yaml` — case metadata
- Existing 19 test cases — no changes; all still pass (backward compat)

## Open risks

1. **CIS section numbers may not be exact.** Final mappings will be cross-checked at implementation time. The spec allows updates as long as at least one CIS reference is present per rule.
2. **Frozen fixtures may drift from generation.** Documented in non-goals; not auto-detected in step 1.
3. **GitHub Action `pip install git+...` may be slow** (clone + install on every CI run). Acceptable for step 1; PyPI in step 2 fixes this.
4. **Pre-commit `language: python` requires users to have Python installed.** Standard in the pre-commit ecosystem; acceptable.

## Sequencing (the agreed Approach A)

1. Schema + loader + report rendering for `references:`
2. Populate all 7 rules
3. `--fail-on` flag + tests
4. `examples/sample_router.txt` + frozen fixtures
5. `tools/generate_rule_table.py` + `docs/rule-table.md`
6. README rewrite
7. `.github/workflows/configguard.yml` + `.pre-commit-hooks.yaml`
8. New test case `case_020_sample_router`
9. Run full test suite, verify all green
10. Commit
