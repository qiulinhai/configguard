"""Deterministic rule engine evaluator."""
import re
import yaml
from pathlib import Path
from configguard.models import ConfigIR, Finding, FindingStatus, Severity
from configguard.context import SignalContext


class Rule:
    def __init__(self, rule_data: dict):
        self.id = rule_data["id"]
        self.name = rule_data["name"]
        self.category = rule_data["category"]
        self.severity = Severity(rule_data["severity"])
        self.match_type = rule_data["match"]["type"]
        self.pattern = rule_data["match"]["pattern"]
        self.scope = rule_data["match"].get("scope")
        self.condition = rule_data["condition"]
        self.finding_status = FindingStatus(rule_data["finding"]["status"])
        self.description = rule_data.get("description", "")
        self.remediation = rule_data.get("remediation", "")

    def evaluate(self, ir: ConfigIR) -> list[Finding]:
        findings = []
        text_to_search = self._get_search_text(ir)

        if self.condition == "present":
            matches = list(re.finditer(self.pattern, text_to_search))
            if matches:
                for match in matches:
                    findings.append(Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        status=self.finding_status,
                        evidence=match.group(),
                        block_type=self._get_block_type_for_match(match, ir),
                        block_name=self._get_block_name_for_match(match, ir),
                        remediation=self.remediation,
                    ))
        elif self.condition == "absent":
            matches = list(re.finditer(self.pattern, text_to_search))
            if not matches:
                # Pattern not found = item is absent as required, report finding.status directly
                findings.append(Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    status=self.finding_status,
                    evidence="",
                    block_type=None,
                    block_name=None,
                    remediation=self.remediation,
                ))
        # If matches found for absent condition, item exists (good), don't add finding

        return findings

    def _get_search_text(self, ir: ConfigIR) -> str:
        if self.scope:
            scope_type = self.scope.split(".")[0]
            for block in ir.blocks:
                if block.type == scope_type:
                    return "\n".join(block.commands)
        return "\n".join(ir.raw_lines)

    def _get_block_type_for_match(self, match, ir: ConfigIR) -> str | None:
        if not self.scope:
            return None
        scope_type = self.scope.split(".")[0]
        for block in ir.blocks:
            if block.type == scope_type:
                block_text = "\n".join(block.commands)
                if match.group() in block_text:
                    return block.type
        return None

    def _get_block_name_for_match(self, match, ir: ConfigIR) -> str | None:
        if not self.scope:
            return None
        scope_type = self.scope.split(".")[0]
        for block in ir.blocks:
            if block.type == scope_type:
                block_text = "\n".join(block.commands)
                if match.group() in block_text:
                    return block.name
        return None

    def evaluate_with_context(self, context: SignalContext) -> list[Finding]:
        """Evaluate this rule against a signal context.

        Unlike evaluate() which searches ConfigIR directly, this method
        evaluates the aggregated signals in a context.
        """
        findings = []

        # For "present" condition: check if aggregated evidence matches pattern
        if self.condition == "present":
            evidence_text = ", ".join(context.aggregated_evidence)
            if re.search(self.pattern, evidence_text):
                findings.append(Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    status=self.finding_status,
                    evidence=evidence_text,  # Aggregated evidence
                    block_type="global",
                    block_name=context.context_key,
                    remediation=self.remediation,
                ))
        elif self.condition == "absent":
            evidence_text = ", ".join(context.aggregated_evidence)
            if not re.search(self.pattern, evidence_text):
                findings.append(Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    status=self.finding_status,
                    evidence="",
                    block_type="global",
                    block_name=context.context_key,
                    remediation=self.remediation,
                ))

        return findings


class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules = []
        self.rules_dir = Path(rules_dir)
        self._load_rules()

    def _load_rules(self):
        if not self.rules_dir.exists():
            return
        for yaml_file in self.rules_dir.rglob("*.yaml"):
            with open(yaml_file) as f:
                rule_data = yaml.safe_load(f)
                self.rules.append(Rule(rule_data))

    def evaluate(self, ir: ConfigIR) -> list[Finding]:
        all_findings = []
        seen_findings = set()  # Deduplication by (rule_id, block_name, evidence)
        for rule in self.rules:
            findings = rule.evaluate(ir)
            for finding in findings:
                # Deduplicate: skip if same rule_id + block_name + evidence combination already seen
                dedup_key = (finding.rule_id, finding.block_name, finding.evidence)
                if dedup_key not in seen_findings:
                    seen_findings.add(dedup_key)
                    all_findings.append(finding)
        return all_findings