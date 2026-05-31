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
from configguard.output.json import generate_json_report
from configguard.output.markdown import generate_markdown_report

app = typer.Typer()


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
    risk_score: bool = typer.Option(False, help="Include risk score calculation (v0.3)"),
):
    """Audit a network device configuration file."""
    if not config_file.exists():
        typer.echo(f"Error: File not found: {config_file}", err=True)
        raise typer.Exit(1)

    config_text = config_file.read_text()
    parser = CiscoIOSParser(config_text)
    ir = parser.parse()

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

    # Risk scoring (v0.3) - post-processing layer
    risk_result = None
    if risk_score:
        risk_engine = RiskEngine()
        risk_result = risk_engine.evaluate(findings)

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
        )
        json_path = output_dir / f"{report_prefix}.report.json"
        json_path.write_text(json_report)
        typer.echo(f"JSON report: {json_path}")

    if format in ("markdown", "all"):
        md_report = generate_markdown_report(findings=findings, config_name=config_name)
        md_path = output_dir / f"{report_prefix}.report.md"
        md_path.write_text(md_report)
        typer.echo(f"Markdown report: {md_path}")

    # STDOUT summary - derived from findings list, not re-counted
    typer.echo("\n--- Audit Summary ---")
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

    total = len(findings)
    fail = sum(1 for f in findings if f.status.value == "FAIL")
    warn = sum(1 for f in findings if f.status.value == "WARN")
    pass_count = sum(1 for f in findings if f.status.value == "PASS")
    typer.echo(f"\nTotal: {total} findings ({fail} failed, {warn} warnings, {pass_count} passed)")

    # Risk score output (v0.3)
    if risk_score and risk_result:
        rs = risk_result.risk_score
        typer.echo("\n--- Risk Assessment (v0.3) ---")
        typer.echo(f"Risk Score: {rs.score}/100 ({rs.level.value})")
        typer.echo(f"Contexts Covered: {rs.context_coverage}")
        if rs.severity_breakdown:
            typer.echo(f"Severity Breakdown: {rs.severity_breakdown}")
        if rs.category_breakdown:
            typer.echo(f"Category Breakdown: {rs.category_breakdown}")


def main():
    args = sys.argv[1:]
    if args and args[0] == "audit":
        args = args[1:]
    app(args)


if __name__ == "__main__":
    main()