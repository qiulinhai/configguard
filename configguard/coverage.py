"""Coverage Matrix Generator.

Generates a markdown coverage matrix showing:
- All signal categories from registry
- Rules that cover each category
- Uncovered categories (gaps)
"""
import typer
from configguard.engine import RuleEngine
from configguard.registry import SignalRegistry, create_signal_registry_with_defaults

app = typer.Typer()


@app.command()
def coverage(
    rules_dir: str = typer.Option("configguard/rules", help="Rules directory"),
    output: str = typer.Option("coverage_matrix.md", help="Output file"),
):
    """Generate coverage matrix showing category → rule coverage."""
    # Initialize registry
    create_signal_registry_with_defaults()
    registry = SignalRegistry.get_instance()
    engine = RuleEngine(rules_dir)

    # Get all categories from registry
    all_categories = set(registry.get_all_categories())

    # Get all categories that have rules
    covered_categories = set(engine.get_categories())

    # Build matrix rows
    rows = []
    for category in sorted(all_categories):
        rules = engine.get_rules_for_category(category)
        rule_ids = [r.id for r in rules]
        coverage_status = "✓" if rule_ids else "✗"
        rule_list = ", ".join(rule_ids) if rule_ids else "(none)"

        rows.append(f"| {category} | {coverage_status} | {rule_list} |")

    # Build table
    header = "| Category | Covered | Rules |"
    separator = "|----------|---------|-------|"

    content = "\n".join([
        "# ConfigGuard Coverage Matrix",
        "",
        f"Generated: coverage matrix",
        "",
        header,
        separator,
        *rows,
        "",
        "## Uncovered Categories",
        "",
    ])

    # Add uncovered section
    uncovered = sorted(all_categories - covered_categories)
    if uncovered:
        for cat in uncovered:
            content += f"- {cat}\n"
    else:
        content += "All categories are covered!\n"

    # Write output
    with open(output, "w") as f:
        f.write(content)

    typer.echo(f"Coverage matrix written to {output}")
    typer.echo(f"Total categories: {len(all_categories)}")
    typer.echo(f"Covered: {len(covered_categories)}")
    typer.echo(f"Uncovered: {len(uncovered)}")


if __name__ == "__main__":
    app()