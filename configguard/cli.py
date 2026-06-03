"""ConfigGuard CLI entry point."""
import json
import sys
import typer
from pathlib import Path
from datetime import datetime
from configguard.registry import create_signal_registry_with_defaults
from configguard.models import Severity
from configguard.output.json import generate_json_report
from configguard.output.markdown import generate_markdown_report

app = typer.Typer()

# Initialize registry at module load time
create_signal_registry_with_defaults()

_FAIL_ON_SEVERITY_ORDER = {
    "none": None,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}

_SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


@app.command()
def audit(
    config_file: Path,
    output_dir: Path = typer.Option(Path("./output"), help="Output directory"),
    format: str = typer.Option("all", help="Output format: json, markdown, all"),
    rules_dir: Path = typer.Option(Path("configguard/rules"), help="Rules directory"),
    explain: bool = typer.Option(False, help="Enable LLM explanations"),
    verbose: bool = typer.Option(False, help="Verbose output"),
    use_context: bool = typer.Option(True, help="Use context-based evaluation (per-context, aggregated evidence)"),
    debug_contexts: bool = typer.Option(False, help="Output SignalContext JSON for debugging (before evaluation)"),
    risk_score: bool = typer.Option(False, help="(Deprecated) Risk score is now always computed. Flag kept for backward compatibility."),
    fail_on: str = typer.Option("none", "--fail-on", help="Exit non-zero if any FAIL finding has severity >= threshold. One of: none, low, medium, high."),
):
    """Audit a network device configuration file."""
    if not config_file.exists():
        typer.echo(f"Error: File not found: {config_file}", err=True)
        raise typer.Exit(1)

    from configguard.services.audit_service import run_audit

    result = run_audit(
        config_path=config_file,
        config_name=config_file.name,
        rules_dir=rules_dir,
        use_context=use_context,
    )

    if result.is_error:
        typer.echo(f"Error: {result.error}", err=True)
        raise typer.Exit(1)

    findings = result.findings
    risk_result = result.risk_result

    # --debug-contexts: re-extract contexts just for printing (the service
    # doesn't expose them; for v0.5 this debug flag only works in `audit`,
    # not in `fleet audit`. That's acceptable; documented in v0.5 docs.)
    if use_context and debug_contexts:
        from configguard.parser import CiscoIOSParser
        from configguard.signals import SignalExtractor
        from configguard.context import ContextBuilder
        ir = CiscoIOSParser(config_file.read_text()).parse()
        extractor = SignalExtractor()
        signals = extractor.extract(ir)
        builder = ContextBuilder()
        contexts = builder.build_contexts(signals)
        contexts_json = {
            "contexts": [ctx.to_dict() for ctx in contexts],
            "count": len(contexts),
        }
        typer.echo("\n--- DEBUG: SignalContexts ---")
        typer.echo(json.dumps(contexts_json, indent=2, default=str))
        typer.echo("--- END DEBUG ---\n")

    output_dir.mkdir(parents=True, exist_ok=True)
    config_name = config_file.stem  # filename without extension

    # Use timestamp for batch-safe, reproducible output naming
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_prefix = f"{timestamp}_{config_name}"

    if format in ("json", "all"):
        json_report = generate_json_report(
            findings=findings,
            config_name=config_name,
            rules_version="0.1.0",
            risk_result=risk_result,
        )
        json_path = output_dir / f"{report_prefix}.report.json"
        json_path.write_text(json_report)
        typer.echo(f"JSON report: {json_path}")

    if format in ("markdown", "all"):
        md_report = generate_markdown_report(
            findings=findings,
            config_name=config_name,
            risk_result=risk_result,
        )
        md_path = output_dir / f"{report_prefix}.report.md"
        md_path.write_text(md_report)
        typer.echo(f"Markdown report: {md_path}")

    total = len(findings)
    fail = sum(1 for f in findings if f.status.value == "FAIL")
    warn = sum(1 for f in findings if f.status.value == "WARN")
    pass_count = sum(1 for f in findings if f.status.value == "PASS")

    # === Compliance Assessment (v0.2: always shown, was opt-in via --risk-score) ===
    # Headline summary so first-time users see "compliance platform" framing
    # (per the README) rather than a bare list of failures.
    rs = risk_result.risk_score
    overall_status = "NON-COMPLIANT" if fail > 0 else "COMPLIANT"
    typer.echo("\n=== Compliance Assessment ===\n")
    typer.echo(f"Overall Status: {overall_status}\n")
    typer.echo(f"Compliance Score: {rs.score}/100 ({rs.level.value})")
    if rs.category_breakdown:
        # Top categories by weighted impact, capped at 5 to keep the block readable
        sorted_cats = sorted(rs.category_breakdown.items(), key=lambda x: -x[1])
        typer.echo("\nRisk Areas:")
        for cat, _weight in sorted_cats[:5]:
            typer.echo(f"  - {cat}")
    typer.echo()

    # STDOUT summary - derived from findings list, not re-counted
    typer.echo("--- Audit Summary ---")
    for f in findings:
        status_icon = "FAIL" if f.status.value == "FAIL" else "PASS"
        typer.echo(f"[{status_icon}] {f.rule_id} {f.rule_name}")
        typer.echo(f"       Severity: {f.severity.value}")
        typer.echo(f"       Category: {f.category}")
        if f.block_name:
            typer.echo(f"       Block: {f.block_name}")
        # Use human-readable evidence summary if available, else fall back to raw evidence
        if f.evidence_summary:
            typer.echo(f"       Evidence: {f.evidence_summary['summary']}")
        else:
            typer.echo(f"       Evidence: {f.evidence}")

    typer.echo(f"\nTotal: {total} findings ({fail} failed, {warn} warnings, {pass_count} passed)")

    # --fail-on gate
    if fail_on not in _FAIL_ON_SEVERITY_ORDER:
        typer.echo(f"Error: --fail-on must be one of: {list(_FAIL_ON_SEVERITY_ORDER.keys())}", err=True)
        raise typer.Exit(2)
    threshold = _FAIL_ON_SEVERITY_ORDER[fail_on]
    if threshold is not None:
        threshold_rank = _SEVERITY_RANK[threshold]
        breach = [f for f in findings if f.status.value == "FAIL" and _SEVERITY_RANK.get(f.severity, 0) >= threshold_rank]
        if breach:
            typer.echo(
                f"\n--fail-on {fail_on}: {len(breach)} finding(s) at or above {fail_on} severity. Exiting 1.",
                err=True,
            )
            raise typer.Exit(1)


# ---- Fleet subcommand (v0.5) ----

# Subcommand: configguard fleet audit
fleet_app = typer.Typer(help="Fleet-level operations across many configs (v0.5).")
app.add_typer(fleet_app, name="fleet")


@fleet_app.command("audit")
def fleet_audit_cmd(
    config_dir: Path = typer.Argument(..., help="Directory containing device config files."),
    output_dir: Path = typer.Option(Path("./output"), help="Output directory for snapshot + per-device reports."),
    snapshot_name: str = typer.Option("fleet", help="Snapshot file basename (no extension)."),
    rules_dir: Path = typer.Option(Path("configguard/rules"), help="Rules directory."),
    fail_on: str = typer.Option("none", "--fail-on", help="Exit non-zero if any FAIL finding (across the whole fleet) has severity >= threshold. One of: none, low, medium, high."),
    use_context: bool = typer.Option(True, "--use-context/--no-use-context", help="Use context-based evaluation."),
    include: list[str] = typer.Option(
        ["*.conf", "*.txt", "*.cfg"],
        "--include",
        help="Glob for config files (repeatable).",
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress per-device progress on stdout."),
):
    """Audit every config in a directory. Produces fleet.snapshot.json + per-device reports."""
    from configguard import __version__
    from configguard.fleet import build_snapshot, write_fleet_outputs

    # Validate fail_on
    if fail_on not in _FAIL_ON_SEVERITY_ORDER:
        typer.echo(f"Error: --fail-on must be one of: {list(_FAIL_ON_SEVERITY_ORDER.keys())}", err=True)
        raise typer.Exit(2)
    threshold = _FAIL_ON_SEVERITY_ORDER[fail_on]

    config_dir = Path(config_dir)
    if not config_dir.is_dir():
        typer.echo(f"Error: not a directory: {config_dir}", err=True)
        raise typer.Exit(1)

    # Discover + build
    try:
        snapshot = build_snapshot(
            config_dir=config_dir,
            rules_dir=rules_dir,
            configguard_version=__version__,
            use_context=use_context,
        )
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)

    # Write artifacts
    snap_path, per_device_paths = write_fleet_outputs(
        snapshot=snapshot,
        output_dir=output_dir,
        snapshot_name=snapshot_name,
    )

    # Progress lines (suppressed by --quiet)
    if not quiet:
        total = len(snapshot.devices)
        typer.echo(f"Auditing {total} devices...")
        for i, ds in enumerate(snapshot.devices, start=1):
            level_str = f"  ({ds.level})" if ds.status in ("COMPLIANT", "NON-COMPLIANT") else ""
            typer.echo(f"[{i}/{total}] {ds.device_name:<12} {ds.status}{level_str}")

    # Fleet Assessment block (always printed)
    typer.echo("\n=== Fleet Compliance Assessment ===\n")
    fleet_status = "NON-COMPLIANT" if snapshot.summary.non_compliant > 0 or snapshot.summary.errored > 0 else "COMPLIANT"
    typer.echo(f"Snapshot: {snap_path}\n")
    typer.echo(f"Fleet Status: {fleet_status}")
    typer.echo(f"Devices: {snapshot.summary.device_count} audited "
               f"({snapshot.summary.compliant} compliant, "
               f"{snapshot.summary.non_compliant} non-compliant, "
               f"{snapshot.summary.errored} errored)")
    typer.echo(f"Findings: {snapshot.summary.findings_total} total "
               f"({snapshot.summary.findings_failed} failed, "
               f"{snapshot.summary.findings_passed} passed)")
    typer.echo(f"High-risk devices: {snapshot.summary.high_risk_device_count}")

    # Worst offenders (top 5)
    non_errored = [d for d in snapshot.devices if d.status != "ERROR"]
    level_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    ranked = sorted(
        non_errored,
        key=lambda d: (level_rank.get(d.level, 99), -len(d.findings)),
    )
    top_rules_by_device = {
        d.device_name: next((f.rule_id for f in d.findings if f.status.value == "FAIL"), None)
        for d in non_errored
    }
    if ranked:
        typer.echo("\nWorst offenders:")
        for d in ranked[:5]:
            fail_count = sum(1 for f in d.findings if f.status.value == "FAIL")
            top_rule = top_rules_by_device[d.device_name] or "(no FAIL)"
            typer.echo(f"  {d.device_name:<12} {d.level:<10} {fail_count} high-risk finding(s)  (top: {top_rule})")
        if len(ranked) > 5:
            typer.echo(f"  ... and {len(ranked) - 5} more — see snapshot for full list.")

    # Per-device report paths
    typer.echo(f"\nPer-device reports ({len(per_device_paths)}):")
    for p in per_device_paths:
        typer.echo(f"  {p}")

    # --fail-on gate (fleet-wide)
    if threshold is not None:
        threshold_rank = _SEVERITY_RANK[threshold]
        breach = [
            f for d in snapshot.devices for f in d.findings
            if f.status.value == "FAIL" and _SEVERITY_RANK.get(f.severity, 0) >= threshold_rank
        ]
        if breach:
            typer.echo(
                f"\n--fail-on {fail_on}: {len(breach)} finding(s) at or above {fail_on} severity. Exiting 1.",
                err=True,
            )
            raise typer.Exit(1)


def main():
    args = sys.argv[1:]
    # If the first arg isn't a known subcommand, assume the user typed a bare
    # config file path and route to `audit`. This preserves the historical
    # `configguard <file>` form alongside the explicit `configguard audit <file>`.
    if args and args[0] not in {"audit", "fleet", "--help", "-h", "--version"}:
        args = ["audit", *args]
    app(args)


if __name__ == "__main__":
    main()