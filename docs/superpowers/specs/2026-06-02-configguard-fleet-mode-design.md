# ConfigGuard Fleet Mode (v0.5) — Design

> **Status:** Design Approved
> **Date:** 2026-06-02
> **Type:** Feature Design + Snapshot v1 Contract
> **Target Release:** v0.5.0

---

## 1. Background and Motivation

ConfigGuard v0.1.0 audits **a single config file at a time**. The v0.1 README explicitly calls out two user-facing limitations that block adoption in real operational environments:

- **"One config at a time."** `audit <file>` takes a single config. To audit many devices, the user must loop in shell.
- **"Risk Score" is per-device.** No way to see fleet posture; no way to find the worst offenders.

Feedback from network engineers on Reddit and adjacent communities (June 2026) consistently flagged the same workflow gap: operators manage *fleets* (5–50 devices typical, 100+ at scale), not individual files. They want:

1. **Fleet posture** — is the network compliant overall? Which devices are worst?
2. **Change analysis** — what changed in compliance terms when a config was edited?

ConfigGuard v0.5 introduces the **Fleet Layer** to address (1). The Snapshot schema is designed so (2) lands cleanly in v0.6 as `configguard fleet diff`, sharing the same data model.

---

## 2. Goals and Non-Goals

### 2.1 Goals (v0.5)

- `configguard fleet audit <dir>` audits a directory of configs in one invocation.
- Output a **single canonical artifact** (the `Snapshot`) that:
  - Contains all per-device findings, config hashes, and a derived fleet summary.
  - Is self-contained — no companion file required to interpret it.
  - Is stable enough to support a Phase 2 `fleet diff` command without schema change.
- Provide a per-device JSON report per device for human drilldown.
- Reuse the existing v0.1 audit pipeline unchanged.
- Add a thin service layer so the new fleet command and the future `diff` command share a single entry point.
- Set the stage for v0.6+ (`fleet diff`, `fleet report`, `fleet export`, multi-vendor adapters).

### 2.2 Non-Goals (v0.5)

- **`configguard fleet diff`** — Phase 2 (v0.6).
- **Fleet-level risk score** — deferred. The algorithm needs validation against real fleets before becoming a contract. Phase 1 reports fleet status (COMPLIANT / NON-COMPLIANT) and counts only.
- **Multi-vendor fleet audit** — Phase 4. v0.5 fleet mode is Cisco-IOS-only.
- **Recursion into subdirectories** — explicitly out. One-level scan only.
- **Per-device Markdown reports** — stdout + per-device JSON only.
- **CSV/Excel export** — future `fleet export`.
- **Concurrency / parallel device audit** — explicitly deferred. Serial execution is fast enough for the 5–50 device target fleet.

---

## 3. Architectural Decisions

### 3.1 Three-layer structure (Device ↔ Service ↔ Engine)

Introduce a **service layer** between CLI and engine. This is the load-bearing structural change for the Fleet Layer.

```
cli.py              (Device Layer:  configguard audit <file>)
fleet.py            (Fleet Layer:   configguard fleet audit <dir>)
     │
     ▼
services/
  audit_service.py  (Service Layer: shared by both)
     │
     ▼
engine.py, risk/, ...   (Engine Layer: existing)
```

**Why a service layer now:**

- Phase 2 will add `configguard diff <before> <after>` and `configguard fleet diff <old> <new>`. All three (audit, fleet audit, diff) need the same "load → parse → evaluate → score → return" pipeline. Without a service layer, that pipeline gets duplicated, then refactored a second time.
- `audit_service.run(config_path, options) -> AuditResult` is the single entry point. It is a pure function — no file writes, no stdout — that returns a fully populated `AuditResult` (config_hash, findings, risk result, error if any). Callers decide what to write and where.

### 3.2 Snapshot as the canonical artifact

The **`Snapshot` is the single source of truth for the Fleet Layer.** All Phase 2+ features (`fleet diff`, `fleet report`, `fleet export`, external dashboards) read Snapshots. Per-device `<name>.report.json` files are run-time caches for human drilldown; the Snapshot does not depend on them. (A future "regenerate per-device reports from Snapshot" command is possible but not in v0.5 scope.)

**Implication:** Snapshots are **self-contained**. The per-device `findings` are embedded in `devices[i].findings` rather than referenced by path. A Snapshot can be moved with `scp` and still be interpretable.

### 3.3 Summary is a derived view

`Snapshot.summary` is **derived from `Snapshot.devices`** and stored in the file for convenience (so `fleet report` doesn't have to recompute counts on every read). Documented in the spec: "summary is a computed view; regenerate it by walking devices if you suspect drift."

This keeps `devices` as the actual source of truth and avoids the trap of having two parallel structures that can fall out of sync.

### 3.4 No `score` field in v1 Snapshot

`DeviceSnapshot` exposes the **categorical level** (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) but **not the numeric `score` (0–100)**.

Reasoning: Snapshot is a long-term contract; the RiskEngine scoring algorithm is implementation detail. The categorical level is what drives user action ("this device is HIGH → investigate") and is more robust to threshold-table tweaks. Numeric scores can change semantically without any schema change, which would feel like incompatibility to downstream consumers.

The per-device `report.json` (a run-time artifact, not a long-term contract) continues to include `score` and `level` in its `risk_assessment` block. Phase 1 keeps the v0.1 per-device JSON contract unchanged.

If a future version needs to record scores, the migration path is to nest them under a versioned `risk_engine: {version, score}` object — see §9.

### 3.5 Serial execution

Explicitly chosen over a process-pool design:

- 50 devices × 0.3s/device = 15 seconds. Acceptable for the MVP fleet size.
- ProcessPoolExecutor adds pickle, shared-state, and concurrency-test complexity for no user-visible win at this scale.
- MVP principle: "prove someone uses it before optimizing performance."

This decision is reversible. A `--parallel` flag can be added in v0.5.x or v0.6 without schema change.

---

## 4. CLI Surface

```bash
configguard fleet audit CONFIG_DIR [OPTIONS]

Arguments:
  CONFIG_DIR                   Directory containing device configs (required)

Options (inherited semantics from `configguard audit`):
  --output-dir PATH            Where to write snapshot + per-device reports
                               [default: ./output]
  --rules-dir PATH             Rules directory
                               [default: configguard/rules]
  --use-context / --no-use-context
                               Engine mode [default: --use-context]
  --fail-on {none|low|medium|high}
                               Exit non-zero if any FAIL finding (across the
                               whole fleet) has severity >= threshold
                               [default: none]

Options (new for fleet):
  --snapshot-name NAME         Custom snapshot basename
                               [default: fleet]
  --include GLOB               Glob to match config files. Repeatable.
                               [default: --include '*.conf' --include '*.txt' --include '*.cfg']
                               Example: --include '*.conf' --include '*.txt'
  --quiet                      Suppress per-device progress lines on stdout
                               (Snapshot path and Fleet Assessment block still
                               print). For CI logs.
```

**Future commands (NOT in v0.5):** `configguard fleet diff`, `configguard fleet report`, `configguard fleet export`, `configguard diff` (Device Layer). All share the Snapshot data model.

---

## 5. File Discovery Rules

- **One-level scan** of `CONFIG_DIR`. No recursion. Subdirectories are silently ignored. This keeps output paths and the Snapshot schema simple; deep fleet layouts can be addressed by a future `--recursive` flag (Phase 2+).
- Match the union of `--include` globs (defaults: `*.conf`, `*.txt`, `*.cfg`).
- Skip dotfiles, symlinks, and unreadable files. Silent skip; counted in `summary.errored` if a `DeviceSnapshot` is still produced.
- **Deterministic order**: alphabetical by relative path. The order in `devices[]` matches the on-disk order.
- **Zero-match is a hard error**: `Error: no config files found in CONFIG_DIR (matched: *.conf,*.txt,*.cfg). Exiting 1.` A silently empty fleet audit is dangerous in CI; better to fail loud.

---

## 6. Output Structure

```
<output-dir>/
├── fleet.snapshot.json              # canonical artifact
└── devices/
    ├── core1.report.json             # per-device
    ├── core2.report.json
    ├── edge1.report.json
    ├── edge2.report.json
    └── fw1.report.json
```

- **`fleet.snapshot.json`** — always written. Default name; if `--snapshot-name` is passed, use `<name>.snapshot.json` instead (e.g. `--snapshot-name 20260602_prod` → `20260602_prod.snapshot.json`).
- **`devices/<name>.report.json`** — one per audited device. No timestamp prefix on these files (only on the snapshot if `--snapshot-name` is timestamped). Names collide only if the same filename appears twice in `CONFIG_DIR`; the filesystem prevents that for a one-level scan.
- The `devices/` subdirectory is **always** created, even if the fleet has zero devices (the error path is handled before this).

### 6.1 Stdout (default, non-quiet)

```
Auditing 5 devices...
[1/5] core1    COMPLIANT
[2/5] core2    COMPLIANT
[3/5] edge1    COMPLIANT
[4/5] edge2    NON-COMPLIANT  (CRITICAL)
[5/5] fw1      NON-COMPLIANT  (HIGH)

=== Fleet Compliance Assessment ===

Snapshot: output/fleet.snapshot.json

Fleet Status: NON-COMPLIANT
Devices: 5 audited (3 compliant, 2 non-compliant)
Findings: 8 total (4 failed, 0 warnings, 4 passed)
High-risk devices: 2

Worst offenders:
  edge2   CRITICAL  3 high-risk findings  (top: disable_http_server)
  fw1     HIGH      1 high-risk finding   (top: disable_telnet)

Per-device reports (5):
  output/devices/core1.report.json
  output/devices/core2.report.json
  output/devices/edge1.report.json
  output/devices/edge2.report.json
  output/devices/fw1.report.json
```

- **Worst offenders display rules:**
  - Sort by `level` (CRITICAL > HIGH > MEDIUM > LOW), then by `findings` count desc.
  - **One line per device**: level + findings count + top-rule name only. No rule list — keeps stdout bounded as the rule library grows.
  - Cap at 5 devices shown. Remaining devices are summarized as "and N more — see snapshot for full list."
- **No Fleet Score in Phase 1.** Replaced by the categorical Fleet Status (NON-COMPLIANT / COMPLIANT) and counts. Documented in the user guide as a deliberate v1 conservatism.

### 6.2 Stdout (--quiet)

Skips the `Auditing N devices...` and per-device progress lines. Snapshot path and Fleet Assessment block still print. CI-friendly.

### 6.3 Exit code

`--fail-on` applies to the **fleet rollup**, not per-device. If any FAIL finding (in any device) meets the threshold:

```
--fail-on high: 4 finding(s) at or above high severity. Exiting 1.
```

Otherwise exit 0. `--fail-on bogus` is still a hard error (exit 2), same as `audit` today.

---

## 7. Snapshot v1 Schema (the contract)

```json
{
  "snapshot_version": 1,
  "generator": {
    "configguard_version": "0.5.0",
    "python_version": "3.12.4"
  },
  "generated_at": "2026-06-02T14:30:22Z",
  "source": {
    "config_dir": "./configs",
    "rules_dir": "./configguard/rules"
  },
  "summary": {
    "device_count": 5,
    "compliant": 3,
    "non_compliant": 2,
    "errored": 0,
    "findings_total": 8,
    "findings_failed": 4,
    "findings_passed": 4,
    "high_risk_device_count": 2
  },
  "devices": [
    {
      "device_name": "edge2",
      "config_path": "configs/edge2.conf",
      "config_hash": "7d865e959b2466918c9863afca942d0fb89d2c9f9b0a1e2c5d3b8e4a7f1c0d2e",
      "status": "NON-COMPLIANT",
      "level": "CRITICAL",
      "severity_breakdown": { "HIGH": 2, "MEDIUM": 1, "LOW": 0 },
      "findings": [
        {
          "rule_id": "CISCO-MGMT-002",
          "rule_name": "Disable HTTP Server",
          "category": "management-plane",
          "severity": "HIGH",
          "status": "FAIL",
          "evidence": "HTTP server: enabled",
          "block_type": "http",
          "block_name": "http",
          "remediation": "...",
          "references": [...]
        }
      ],
      "error": null
    }
  ]
}
```

### 7.1 Field-by-field spec

| Field | Type | Required | Notes |
|---|---|---|---|
| `snapshot_version` | int | yes | Always `1` for this contract. Bumped on breaking changes only. |
| `generator.configguard_version` | string | yes | The version of ConfigGuard that produced the Snapshot. |
| `generator.python_version` | string | yes | For debugging "weird behavior on Python 3.10" reports. |
| `generated_at` | string (ISO 8601 UTC) | yes | When the Snapshot was written. |
| `source.config_dir` | string | yes | As the user passed it (relative or absolute). Metadata only. |
| `source.rules_dir` | string | yes | As the user passed it. Metadata only. |
| `summary.*` | derived from `devices` | yes | See §7.3. May be regenerated by walking `devices`. |
| `devices[].device_name` | string | yes | **Identity** of the device. Match key for cross-snapshot diff. |
| `devices[].config_path` | string | yes | **Metadata**: where the file lives. Do NOT use as a match key. |
| `devices[].config_hash` | string (hex) | yes | SHA-256 digest of the configuration file bytes, encoded as **lowercase hexadecimal** (64 chars, no `sha256:` prefix). Phase 2 diff uses this for a fast skip-equal-configs pre-check. The algorithm is documented in the spec, not in the data. |
| `devices[].status` | enum | yes | One of `COMPLIANT`, `NON-COMPLIANT`, `ERROR`. Three values, never null. |
| `devices[].level` | enum | yes | One of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. The RiskEngine's categorical conclusion. **No `score` field in v1.** |
| `devices[].severity_breakdown` | object | yes | `{"HIGH": n, "MEDIUM": n, "LOW": n}`. Always present, counts can be zero. |
| `devices[].findings` | array | yes | Same Finding shape as v0.1 per-device `report.json`. Empty array if `status = ERROR`. |
| `devices[].error` | string \| null | yes | `null` for COMPLIANT/NON-COMPLIANT. Non-null string for ERROR. |

### 7.2 `status` is a three-valued state machine

The three values are semantically distinct and intentionally not collapsed:

- `COMPLIANT` — audit ran, no FAIL findings.
- `NON-COMPLIANT` — audit ran, ≥1 FAIL findings.
- `ERROR` — audit could not run (parse error, read error, etc.). `findings` is `[]`. `error` is a non-null message.

Collapsing ERROR into NON-COMPLIANT would hide parse failures in compliance counts. The user must be able to answer "17 non-compliant: are they all real violations, or did 2 fail to parse?".

### 7.3 `summary` is a derived view

Stored fields:
- `device_count` — `len(devices)`
- `compliant`, `non_compliant`, `errored` — counts of each `status` value
- `findings_total`, `findings_failed`, `findings_passed` — sum across all devices
- `high_risk_device_count` — devices with `level ∈ {HIGH, CRITICAL}`

`summary` is documented as **derived**: a consumer can verify it by walking `devices`. If a downstream tool ever sees drift, it can regenerate. This is the contract that lets us safely add fields to `summary` in a future Snapshot version.

### 7.4 `device_name` is identity; `config_path` is metadata

This is the single most important field naming decision in the contract. It must be enforced in the spec doc, code comments on `DeviceSnapshot`, and reviewed in every PR that touches Snapshot code:

- `device_name` (the filename stem) is the **identity** of a device across snapshots. Use it as the match key for diff.
- `config_path` is the **location** the device was found at. It is metadata, not identity.

The reason: a user may move the configs between directories between snapshots. `snapshot A` taken from `configs/edge2.conf` and `snapshot B` taken from `production/edge2.conf` should diff as the same device. Matching on `config_path` would silently miss this.

### 7.5 `findings` is the v0.1 Finding shape, byte-for-byte

The per-device `findings` array in `DeviceSnapshot` is **identical** to the `findings` array in the existing v0.1 per-device `report.json`. This means:

- A user opening `devices/edge2.report.json` and `fleet.snapshot.json → devices[i].findings[0]` sees the same keys and values.
- Phase 2's `fleet diff` just compares two arrays of Finding; no shape translation needed.
- Any new field added to Finding in a future v0.x must be added in both places at the same time (enforced by tests).

### 7.6 Versioning policy

- `snapshot_version: 1` is the contract for v0.5.0.
- **Additive changes** (new optional field, new enum value to an existing enum) do **not** bump the version. Consumers ignore unknown fields.
- **Breaking changes** (rename, remove, type change) bump the version and ship a migration tool: `configguard fleet migrate-snapshot old.json`. (Phase 2+.)
- **Validation** lives in `configguard fleet verify-snapshot <file>` (Phase 2+). Phase 1 ships with tests that load and round-trip a v1 Snapshot via `Snapshot.from_dict()`.

### 7.7 What is NOT in v1

These are deliberately deferred. Each is easy to add later; keeping v1 small keeps the contract tight.

- **Per-finding timestamps** — needs cross-snapshot state. Phase 2.
- **Per-device metadata** (site, role, owner) — user's CI can inject this.
- **Rule pack version pinning** — added when multiple rule pack versions coexist.
- **Compliance framework tagging** (CIS, NIST) — Phase 3.
- **Config line-level diff** — different product, not in scope.
- **Fleet-level score** — deferred until algorithm is validated against real fleets.

---

## 8. Error Handling

| Situation | Behavior |
|---|---|
| `CONFIG_DIR` does not exist | Exit 1, error on stderr. |
| `CONFIG_DIR` is a file, not a dir | Exit 1, error on stderr. |
| `CONFIG_DIR` has zero matching files | Exit 1, error on stderr. |
| A config file fails to read | `DeviceSnapshot.status = "ERROR"`, `error` set, `findings = []`. Fleet continues. |
| A config file fails to parse | Same as above. |
| A `--fail-on` threshold is met (any device) | Exit 1 after all devices audited. Report is still written. |
| `--fail-on bogus` | Exit 2, error on stderr. Same as `audit` today. |
| Output directory not writable | Exit 1, error on stderr. |
| Two devices in `CONFIG_DIR` resolve to the same `device_name` | Impossible for a one-level scan (filesystem prevents it). |

The key principle: **partial success is preferred over atomic failure.** If 4 of 5 devices audit cleanly and 1 fails to parse, the user gets a Snapshot with 4 valid `DeviceSnapshot` entries and 1 ERROR entry. They can fix the bad config and re-run; the good ones don't need re-auditing because the Snapshot is already on disk.

---

## 9. Future Migration Path for `score` (informational)

If a future ConfigGuard version (e.g. v0.7) decides the RiskEngine algorithm is stable and wants to expose numeric scores in Snapshots, the migration is:

```json
{
  "status": "NON-COMPLIANT",
  "level": "CRITICAL",
  "severity_breakdown": { "HIGH": 2, "MEDIUM": 1, "LOW": 0 },
  "risk_engine": {
    "version": "2",
    "score": 91
  }
}
```

The nested `risk_engine` namespace keeps it versioned, so the `score` value can change between `risk_engine.version` values without a Snapshot schema bump. This is informational only; v0.5 does not include it.

---

## 10. Testing Strategy

### 10.1 Unit tests

- `services/audit_service.py`:
  - `run()` returns `AuditResult` with all fields populated.
  - `config_hash` matches a known SHA-256 of test input bytes.
  - Parse error → `error` populated, `findings = []`, `status` reflects error.
  - File-not-found → `error` populated.
- `snapshot.py`:
  - `Snapshot.from_dict()` round-trips a v1 Snapshot.
  - `summary` is correctly derived from `devices`.
  - `status` validation rejects unknown values.
  - Unknown fields are silently ignored (forward compat).
- `fleet.py`:
  - File discovery respects `--include` globs.
  - File discovery respects deterministic ordering.
  - Zero-match → `typer.Exit(1)`.
  - `<output-dir>/devices/` is created.

### 10.2 Integration tests

- `configguard fleet audit <tmpdir> --output-dir <tmpdir/out>` end-to-end on 3-device sample dir.
- Snapshot file exists, valid JSON, schema-valid.
- Per-device `report.json` files exist, one per device.
- `fleet_status` field reflects the worst case in the fleet.
- `--fail-on high` with a HIGH finding in any device → exit 1.
- `--fail-on none` always exits 0.
- `--quiet` suppresses per-device progress.
- `--snapshot-name 20260602_test` produces `20260602_test.snapshot.json`.

### 10.3 Snapshot schema tests

- A hand-written v1 Snapshot loads via `Snapshot.from_dict()` without error.
- A Snapshot missing required top-level fields is rejected with a clear message.
- A Snapshot with `snapshot_version: 2` is rejected (Phase 2+ has its own handler).
- A v1 Snapshot with extra unknown fields loads fine (forward compat).
- `summary` drift detection: if `summary` is manually edited to disagree with `devices`, the test asserts the `devices` walk can regenerate `summary` correctly.

### 10.4 End-to-end smoke

- The `examples/` directory gets a `fleet_sample/` with 3 example configs (clean, dirty, parse-error) used as the canonical demo.
- `configguard fleet audit examples/fleet_sample/` produces the README's "See it run" fleet example output.

---

## 11. Documentation Updates

- `README.md` — new "Fleet mode" section after "Your first audit" with the `configguard fleet audit` example and a small fleet audit output sample.
- `docs/user-guide.md` — new chapter 15 "Fleet audits" (after "Auditing from CI"), covers CLI reference, Snapshot schema overview, and the per-device vs fleet view.
- `docs/RELEASING.md` — no change (this is a feature, not a release-process change).
- `CHANGELOG.md` — new `[0.5.0]` section at top under `[Unreleased]`.

---

## 12. Open Questions / Out of Scope

These are explicitly **not** designed in this spec:

1. **Concurrency** — see §3.5. Reversible later.
2. **Phase 2 `configguard fleet diff`** — designed against the Snapshot contract but the diff algorithm and output are not in scope here. A follow-up design doc will cover it.
3. **Phase 2 `configguard fleet report` and `configguard fleet export`** — also follow-up design docs.
4. **Multi-vendor fleet audit (Linux, Junos)** — Phase 4. The Snapshot schema is designed to accommodate non-Cisco device types (DeviceSnapshot has no Cisco-specific fields), but no Phase 1 work implements them.
5. **Snapshot retention / archival** — no built-in rotation. The user names their snapshots via `--snapshot-name`. Phase 3+ may add a `--archive` flag.

---

## 13. Acceptance Criteria for v0.5.0

v0.5.0 ships when:

1. `configguard fleet audit <dir>` works end-to-end on the `examples/fleet_sample/` set.
2. `fleet.snapshot.json` is a valid v1 Snapshot (verified by `Snapshot.from_dict()`).
3. All 358 existing v0.1 tests still pass; new fleet tests bring the total above 380.
4. The user guide's "Fleet audits" chapter is published.
5. CHANGELOG entry is written.
6. README's "See it run" example includes a fleet audit output.
