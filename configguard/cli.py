"""ConfigGuard CLI entry point."""
import typer
from pathlib import Path
from configguard.parser import CiscoIOSParser
from configguard.engine import RuleEngine
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
):
    """Audit a network device configuration file."""
    if not config_file.exists():
        typer.echo(f"Error: File not found: {config_file}", err=True)
        raise typer.Exit(1)

    config_text = config_file.read_text()
    parser = CiscoIOSParser(config_text)
    ir = parser.parse()

    engine = RuleEngine(str(rules_dir))
    findings = engine.evaluate(ir)

    output_dir.mkdir(parents=True, exist_ok=True)
    config_name = config_file.stem  # filename without extension

    if format in ("json", "all"):
        json_report = generate_json_report(
            findings=findings,
            config_name=config_name,
            rules_version="0.1.0",
        )
        json_path = output_dir / f"{config_name}.report.json"
        json_path.write_text(json_report)
        typer.echo(f"JSON report: {json_path}")

    if format in ("markdown", "all"):
        md_report = generate_markdown_report(findings=findings, config_name=config_name)
        md_path = output_dir / f"{config_name}.report.md"
        md_path.write_text(md_report)
        typer.echo(f"Markdown report: {md_path}")

    # STDOUT summary - derived from findings list, not re-counted
    typer.echo("\n--- Audit Summary ---")
    for f in findings:
        status_icon = "FAIL" if f.status.value == "FAIL" else "PASS"
        typer.echo(f"[{status_icon}] {f.rule_id} {f.rule_name}")
        if f.block_name:
            typer.echo(f"       Block: {f.block_name}")
        typer.echo(f"       Evidence: {f.evidence}")

    total = len(findings)
    fail = sum(1 for f in findings if f.status.value == "FAIL")
    warn = sum(1 for f in findings if f.status.value == "WARN")
    pass_count = sum(1 for f in findings if f.status.value == "PASS")
    typer.echo(f"\nTotal: {total} findings ({fail} failed, {warn} warnings, {pass_count} passed)")


def main():
    app()


if __name__ == "__main__":
    main()