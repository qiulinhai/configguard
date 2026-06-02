"""JSON output generator for ConfigGuard."""
import json
from datetime import datetime, timezone
from configguard.models import Finding
from configguard.risk.engine import RiskEngineResult


def generate_json_report(
    findings: list[Finding],
    config_name: str,
    rules_version: str,
    risk_result: RiskEngineResult | None = None,
) -> str:
    summary = {
        "total": len(findings),
        "pass": sum(1 for f in findings if f.status.value == "PASS"),
        "fail": sum(1 for f in findings if f.status.value == "FAIL"),
        "warnings": sum(1 for f in findings if f.status.value == "WARN"),
    }

    report: dict = {
        "version": "0.1.0",
        "summary": summary,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "category": f.category,
                "severity": f.severity.value,
                "status": f.status.value,
                "evidence": f.evidence,
                "block_type": f.block_type,
                "block_name": f.block_name,
                "remediation": f.remediation,
                "references": f.references,
            }
            for f in findings
        ],
        "metadata": {
            "config_name": config_name,
            "device_type": "Cisco IOS",
            "parser_version": "0.1.0",
            "rules_version": rules_version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }

    if risk_result is not None:
        rs = risk_result.risk_score
        fail = summary["fail"]
        overall_status = "NON-COMPLIANT" if fail > 0 else "COMPLIANT"

        sorted_cats = sorted(rs.category_breakdown.items(), key=lambda x: -x[1])
        risk_areas = [cat for cat, _ in sorted_cats]

        report["compliance"] = {
            "status": overall_status,
            "score": rs.score,
            "level": rs.level.value,
            "risk_areas": risk_areas,
        }
        report["risk_assessment"] = {
            "score": rs.score,
            "level": rs.level.value,
            "finding_count": rs.finding_count,
            "severity_breakdown": rs.severity_breakdown,
            "category_breakdown": rs.category_breakdown,
            "context_coverage": rs.context_coverage,
        }

    return json.dumps(report, indent=2)
