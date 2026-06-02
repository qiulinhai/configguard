"""ConfigGuard CLI entry point."""
import json
import sys
import typer
from pathlib import Path
from datetime import datetime
from configguard.parser import CiscoIOSParser
from configguard.signals import SignalExtractor
from configguard.context import ContextBuilder
from configguard.engine import RuleEngine
from configguard.evidence import EvidenceBuilder
from configguard.risk import RiskEngine
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

    config_text = config_file.read_text()
    parser = CiscoIOSParser(config_text)
    try:
        ir = parser.parse()
    except Exception as exc:
        typer.echo(
            f"Error: Failed to parse {config_file}: {exc}",
            err=True,
        )
        raise typer.Exit(1)

    engine = RuleEngine(str(rules_dir))

    # Context-based evaluation: signals -> contexts -> per-context evaluation
    if use_context:
        extractor = SignalExtractor()
        signals = extractor.extract(ir)

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals)

        if debug_contexts:
            contexts_json = {
                "contexts": [ctx.to_dict() for ctx in contexts],
                "count": len(contexts),
            }
            typer.echo("\n--- DEBUG: SignalContexts ---")
            typer.echo(json.dumps(contexts_json, indent=2, default=str))
            typer.echo("--- END DEBUG ---\n")

        # Fall back to legacy evaluation if rules don't have applies_to declarations
        if not engine._category_index:
            # No context-based rules loaded, use legacy evaluation
            findings = engine.evaluate(ir)
        else:
            findings = engine.evaluate_with_contexts(contexts, engine.rules)

        # Build context-to-finding mapping and attach evidence summaries
        evidence_builder = EvidenceBuilder()
        context_by_key = {ctx.context_key: ctx for ctx in contexts}
        for f in findings:
            if f.block_name and f.block_name in context_by_key:
                context = context_by_key[f.block_name]
                evidence_builder.attach_evidence_summary(f, context)
    else:
        # Legacy per-signal evaluation
        findings = engine.evaluate(ir)

    # Risk scoring (v0.3) - now always-on (was opt-in via --risk-score, promoted to
    # default in v0.2 to align CLI output with the 'compliance platform' framing).
    # The --risk-score flag is kept for backward compatibility but is a no-op.
    risk_result = RiskEngine().evaluate(findings)

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


def main():
    args = sys.argv[1:]
    if args and args[0] == "audit":
        args = args[1:]
    app(args)


if __name__ == "__main__":
    main()