"""Deterministic rule engine evaluator."""
import re
import yaml
from pathlib import Path
from configguard.models import ConfigIR, Finding, FindingStatus, Severity


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
        for rule in self.rules:
            findings = rule.evaluate(ir)
            all_findings.extend(findings)
        return all_findings