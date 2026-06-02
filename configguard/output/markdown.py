"""Markdown report generator for ConfigGuard."""
from configguard.models import Finding


def generate_markdown_report(findings: list[Finding], config_name: str) -> str:
    summary = {
        "total": len(findings),
        "pass": sum(1 for f in findings if f.status.value == "PASS"),
        "fail": sum(1 for f in findings if f.status.value == "FAIL"),
        "warnings": sum(1 for f in findings if f.status.value == "WARN"),
    }

    lines = [
        "# ConfigGuard Security Audit Report",
        "",
        "## Summary",
        f"- **Total Checks:** {summary['total']}",
        f"- **Passed:** {summary['pass']}",
        f"- **Failed:** {summary['fail']}",
        f"- **Warnings:** {summary['warnings']}",
        "",
        "---",
        "",
    ]

    fail_findings = [f for f in findings if f.status.value == "FAIL"]
    pass_findings = [f for f in findings if f.status.value == "PASS"]

    if fail_findings:
        lines.append("## Failed Findings\n")
        for f in fail_findings:
            lines.append(f"### [{f.severity.value}] {f.rule_name}")
            lines.append(f"**Rule ID:** {f.rule_id}")
            lines.append(f"**Category:** {f.category}")
            lines.append("")
            lines.append("**Evidence:**")
            lines.append(f"```\n{f.evidence}\n```")
            lines.append("")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
            if f.references:
                lines.append("**References:**")
                for ref in f.references:
                    ref_type = ref.get("type", "reference")
                    ref_id = ref.get("id", "")
                    ref_url = ref.get("url", "")
                    if ref_type.upper() in ("CVE", "NIST-800-53"):
                        label = f"{ref_type.upper()} {ref_id}" if ref_id else ref_type
                    else:
                        label = f"{ref_type.replace('-', ' ').title()} {ref_id}".strip()
                    if ref_url:
                        lines.append(f"- [{label}]({ref_url})")
                    else:
                        lines.append(f"- {label}")
                lines.append("")

    if pass_findings:
        lines.append("## Passed Findings\n")
        for f in pass_findings:
            lines.append(f"- [{f.severity.value}] {f.rule_name} ({f.rule_id})")

    return "\n".join(lines)