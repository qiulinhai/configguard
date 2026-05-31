#!/usr/bin/env python3
"""Generate Rule Coverage Matrix from test cases."""
import json
import os
from pathlib import Path
from collections import defaultdict


def scan_cases():
    """Scan all test cases and build coverage matrix."""
    cases_dir = Path("tests/cases")
    matrix = defaultdict(lambda: defaultdict(list))

    for case_dir in sorted(cases_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        if case_dir.name.startswith("."):
            continue

        config_file = case_dir / "config.txt"
        expected_file = case_dir / "expected.json"
        metadata_file = case_dir / "metadata.yaml"

        if not config_file.exists():
            continue

        # Read expected findings
        expected_findings = []
        if expected_file.exists():
            data = json.loads(expected_file.read_text())
            expected_findings = data.get("findings", [])

        # Detect pattern type
        pattern = "N/A"
        if expected_file.exists():
            data = json.loads(expected_file.read_text())
            pattern = data.get("pattern", "N/A")

        # Determine test patterns
        patterns = detect_patterns(config_file.read_text(), expected_findings)
        if pattern in ["PASS", "FAIL", "EDGE", "MULTI", "REAL"]:
            patterns.add(pattern)

        # Map to rules
        rule_ids = set()
        for f in expected_findings:
            rule_ids.add(f.get("rule_id"))

        if not rule_ids:
            # No findings - might be a PASS case, check pattern
            if pattern == "PASS":
                # Need to infer rule from metadata
                if metadata_file.exists():
                    import yaml
                    meta = yaml.safe_load(metadata_file.read_text())
                    if meta and "rule_id" in meta:
                        rule_ids.add(meta["rule_id"])

        for rule_id in rule_ids:
            for p in patterns:
                matrix[rule_id][p].append(case_dir.name)

    return matrix


def detect_patterns(config_text: str, findings: list) -> set:
    """Detect which test patterns this case covers."""
    patterns = set()

    if not findings:
        patterns.add("PASS")
    else:
        patterns.add("FAIL")

    # Multi-instance detection
    lines = config_text.split("\n")
    multi_lines = [l for l in lines if l.strip() and not l.strip().startswith("!")]
    if len(multi_lines) > 10:
        patterns.add("MULTI")

    # Edge case detection keywords
    edge_keywords = ["ssh", "secure", "crypto", "archive", "login local"]
    if any(kw in config_text.lower() for kw in edge_keywords):
        patterns.add("EDGE")

    # Real config detection (hostname, long config)
    if "hostname" in config_text and len(config_text) > 500:
        patterns.add("REAL")

    return patterns


def get_all_rules():
    """Get all rules from rules directory."""
    from configguard.engine import RuleEngine
    engine = RuleEngine("configguard/rules")
    return {r.id for r in engine.rules}


def print_matrix(matrix: dict):
    """Print coverage matrix."""
    patterns = ["PASS", "FAIL", "EDGE", "MULTI", "REAL"]
    all_rules = sorted(get_all_rules())

    # Header
    header = f"{'Rule ID':<20}" + "".join(f"{p:>8}" for p in patterns)
    separator = "-" * len(header)

    print()
    print("=" * len(header))
    print("ConfigGuard Rule Coverage Matrix")
    print("=" * len(header))
    print()
    print(header)
    print(separator)

    totals = defaultdict(int)

    for rule_id in all_rules:
        row = f"{rule_id:<20}"
        for pattern in patterns:
            cases = matrix[rule_id].get(pattern, [])
            count = len(cases)
            totals[pattern] += count
            if count > 0:
                row += f"{count:>8}"
            else:
                row += f"{'':>8}"
        print(row)

    print(separator)
    print(f"{'TOTAL':<20}" + "".join(f"{totals[p]:>8}" for p in patterns))
    print()

    # Summary stats
    total_cases = sum(len(matrix[r].get(p, [])) for r in matrix for p in patterns)
    covered_rules = len([r for r in all_rules if matrix[r]])
    total_rules = len(all_rules)

    print(f"Rules with coverage: {covered_rules}/{total_rules}")
    print(f"Total Test Cases: {total_cases}")
    print()

    # Coverage status per rule
    print("Coverage Status:")
    print("-" * 50)
    for rule_id in sorted(all_rules):
        case_count = sum(len(matrix[rule_id].get(p, [])) for p in patterns)
        covered_patterns = len([p for p in patterns if matrix[rule_id].get(p)])
        total_patterns = len(patterns)
        status = "✅" if covered_patterns == total_patterns else ("⚠️" if covered_patterns >= 2 else "❌")
        print(f"  {status} {rule_id}: {covered_patterns}/{total_patterns} patterns ({case_count} cases)")


def main():
    print("ConfigGuard Rule Coverage Matrix Generator")
    print("=" * 50)

    matrix = scan_cases()
    print_matrix(matrix)

    # Save matrix to JSON for CI integration
    patterns = ["PASS", "FAIL", "EDGE", "MULTI", "REAL"]
    output = {
        "timestamp": "2026-05-30",
        "matrix": {rule: {p: list(cases) for p, cases in patterns_.items()} for rule, patterns_ in matrix.items()},
    }

    matrix_file = Path("output/coverage_matrix.json")
    matrix_file.parent.mkdir(exist_ok=True)
    matrix_file.write_text(json.dumps(output, indent=2))
    print(f"\nMatrix saved to {matrix_file}")


if __name__ == "__main__":
    main()