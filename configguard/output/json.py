"""JSON output generator for ConfigGuard."""
import json
from datetime import datetime, timezone
from configguard.models import Finding


def generate_json_report(findings: list[Finding], config_name: str, rules_version: str) -> str:
    summary = {
        "total": len(findings),
        "pass": sum(1 for f in findings if f.status.value == "PASS"),
        "fail": sum(1 for f in findings if f.status.value == "FAIL"),
        "warnings": sum(1 for f in findings if f.status.value == "WARN"),
    }

    report = {
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

    return json.dumps(report, indent=2)