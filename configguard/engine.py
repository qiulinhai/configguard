"""Deterministic rule engine evaluator.

v0.2.1: Implements dual-axis rule matching with O(1) category lookup.

This module provides the Rule Engine component:
- Stage 1: O(1) hash lookup by context_type (replaces if-else chain)
- Stage 2: Optional domain filtering (reserved for v0.3)
- Compile-time inverted index construction
"""
import re
import yaml
from pathlib import Path
from typing import Optional

from configguard.models import ConfigIR, Finding, FindingStatus, Severity
from configguard.context import SignalContext


class Rule:
    """A single security rule.

    v0.2.1 adds applies_to structure for declarative matching.
    """

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

        # v0.2.1: Declarative applies_to for category matching
        # Supports: category list, security_domain list
        self.applies_to = rule_data.get("applies_to", {})
        self._categories = self.applies_to.get("category", [])
        self._domains = self.applies_to.get("security_domain", [])

    def matches_category(self, category: str) -> bool:
        """Stage 1: Check if rule applies to this category."""
        return category in self._categories

    def matches_domain(self, domain: str) -> bool:
        """Stage 2: Check if rule applies to this security domain (v0.3+)."""
        return domain in self._domains

    def evaluate(self, ir: ConfigIR) -> list[Finding]:
        """Legacy per-signal evaluation."""
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

        return findings

    def _get_search_text(self, ir: ConfigIR) -> str:
        if self.scope:
            scope_type = self.scope.split(".")[0]
            for block in ir.blocks:
                if block.type == scope_type:
                    return "\n".join(block.commands)
        return "\n".join(ir.raw_lines)

    def _get_block_type_for_match(self, match, ir: ConfigIR) -> Optional[str]:
        if not self.scope:
            return None
        scope_type = self.scope.split(".")[0]
        for block in ir.blocks:
            if block.type == scope_type:
                block_text = "\n".join(block.commands)
                if match.group() in block_text:
                    return block.type
        return None

    def _get_block_name_for_match(self, match, ir: ConfigIR) -> Optional[str]:
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

        Uses aggregated evidence from context for pattern matching.
        """
        findings = []

        # Aggregate raw command text for pattern matching
        evidence_text = ", ".join(s.raw for s in context.signals)

        if self.condition == "present":
            if re.search(self.pattern, evidence_text):
                findings.append(Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    status=self.finding_status,
                    evidence=evidence_text,
                    block_type="global",
                    block_name=context.context_type,  # v0.2.1: use context_type
                    remediation=self.remediation,
                ))
        elif self.condition == "absent":
            if not re.search(self.pattern, evidence_text):
                findings.append(Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    status=self.finding_status,
                    evidence="",
                    block_type="global",
                    block_name=context.context_type,  # v0.2.1: use context_type
                    remediation=self.remediation,
                ))

        return findings


class RuleEngine:
    """Rule engine with dual-axis matching.

    v0.2.1 changes:
    - Compile-time category inverted index (O(1) lookup)
    - Replaces _find_rules_for_context() if-else chain
    - Supports declarative applies_to in rules
    """

    def __init__(self, rules_dir: str):
        self.rules: list[Rule] = []
        self.rules_dir = Path(rules_dir)

        # v0.2.1: Stage 1 index - category → rules
        # Built at compile-time, enables O(1) lookup
        self._category_index: dict[str, list[Rule]] = {}

        self._load_rules()

    def _load_rules(self) -> None:
        """Load rules and build compile-time inverted index."""
        if not self.rules_dir.exists():
            return

        for yaml_file in self.rules_dir.rglob("*.yaml"):
            with open(yaml_file) as f:
                rule_data = yaml.safe_load(f)
                rule = Rule(rule_data)
                self.rules.append(rule)

        # Build Stage 1 inverted index
        self._rebuild_category_index()

    def _rebuild_category_index(self) -> None:
        """Build category → rules inverted index.

        This is the key O(1) lookup structure.
        """
        self._category_index.clear()

        for rule in self.rules:
            for category in rule._categories:
                if category not in self._category_index:
                    self._category_index[category] = []
                self._category_index[category].append(rule)

    def evaluate(self, ir: ConfigIR) -> list[Finding]:
        """Legacy per-signal evaluation."""
        all_findings = []
        seen_findings = set()

        for rule in self.rules:
            findings = rule.evaluate(ir)
            for finding in findings:
                dedup_key = (finding.rule_id, finding.block_name, finding.evidence)
                if dedup_key not in seen_findings:
                    seen_findings.add(dedup_key)
                    all_findings.append(finding)

        return all_findings

    def evaluate_with_contexts(
        self,
        contexts: list[SignalContext],
        rules: Optional[list[Rule]] = None
    ) -> list[Finding]:
        """Evaluate rules against contexts using dual-axis matching.

        Stage 1: O(1) hash lookup via _category_index
        Stage 2: Optional domain filtering (v0.3+)

        Note: Caller should check if _category_index is empty and fall back
        to legacy evaluate() if rules don't have applies_to declarations.

        Args:
            contexts: List of SignalContext from ContextBuilder
            rules: Optional rule list (defaults to all loaded rules)
        """
        if rules is None:
            rules = self.rules

        all_findings = []
        seen_findings = set()

        for context in contexts:
            # Stage 1: O(1) lookup - get rules for this context_type
            candidate_rules = self._category_index.get(context.context_type, [])

            # Stage 2: Domain filtering (v0.3+ would filter here)
            for rule in candidate_rules:
                if rule not in rules:
                    continue

                findings = rule.evaluate_with_context(context)
                for finding in findings:
                    dedup_key = (finding.rule_id, finding.block_name, finding.evidence)
                    if dedup_key not in seen_findings:
                        seen_findings.add(dedup_key)
                        all_findings.append(finding)

        return all_findings

    def get_categories(self) -> list[str]:
        """Get all categories with registered rules."""
        return list(self._category_index.keys())

    def get_rules_for_category(self, category: str) -> list[Rule]:
        """Get rules that apply to a specific category."""
        return self._category_index.get(category, [])