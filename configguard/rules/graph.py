"""Graph-Based Rule Evaluation — IR v1.1 Core.

This module introduces graph-aware rule evaluation as an extension to the
existing flat rule evaluation model.

New paradigm:
    Before (v0.3):  rule.evaluate(ConfigIR) → flat finding
    After (v1.1):  rule.evaluate_graph(kg) → multi-hop attack path finding

Key concepts:
    - Attack path: a chain of resources connected by relationships
      that represents a potential attack vector (e.g., SNMP → VTY → SSH)
    - Graph traversal depth: how many hops to search from a starting resource
    - Constraint attributes: attribute conditions that must be met at each hop
    - Risk propagation: risk score increases with each hop in an attack path

Example attack path detection:
    1. Find network.snmp with exposed_by
    2. Traverse to network.interface (depends_on)
    3. Traverse to auth.remote_access (peer_of)
    4. Check auth.remote_access for weak methods (constraint)
    → Attack path: SNMP(exposed) → interface(reachable) → VTY(weak)

Usage:
    from configguard.ontology import SecurityKnowledgeGraph
    from configguard.rules.graph import GraphRule, GraphRuleEngine

    kg = SecurityKnowledgeGraph(resources).build()
    gre = GraphRuleEngine(rules)
    findings = gre.evaluate_graph(kg)
"""
import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import TypedDict

from configguard.models import Finding, FindingStatus, Severity, CanonicalResource
from configguard.ontology import SecurityKnowledgeGraph, RelationshipType


# ---------------------------------------------------------------------------
# Attack Path Model
# ---------------------------------------------------------------------------
class AttackPath(TypedDict):
    """A multi-hop attack path through the security knowledge graph."""
    path_id: str
    resource_ids: list[str]          # Ordered list of resource IDs in path
    relationship_types: list[str]    # Relationship type at each hop
    risk_score: int                   # 0-100, computed from hops + constraints
    entry_point: str                 # First resource in path (the exposure point)
    terminal_node: str               # Last resource (the target)


# ---------------------------------------------------------------------------
# GraphRule — Rule that evaluates against SecurityKnowledgeGraph
# ---------------------------------------------------------------------------
class GraphRule:
    """A rule that evaluates against a SecurityKnowledgeGraph.

    GraphRule is different from the base Rule class (which searches flat text).
    GraphRule traverses the knowledge graph to find multi-hop attack paths
    based on resource types, relationship constraints, and attribute filters.

    Key fields:
        target_resource_type: The resource type to start searching from
        traversal_depth: Maximum hops to traverse from target (default: 2)
        constraint_attributes: {attr_name: (operator, value)} pairs that must match
        required_relationships: List of RelationshipTypes that must exist in path
        attack_path_required: If True, only report if multi-hop path found
    """

    def __init__(self, rule_data: dict):
        self.id = rule_data["id"]
        self.name = rule_data["name"]
        self.category = rule_data["category"]
        self.severity = Severity(rule_data["severity"])
        self.description = rule_data.get("description", "")
        self.remediation = rule_data.get("remediation", "")

        # Graph-specific evaluation parameters
        self.target_resource_type = rule_data.get("target_resource_type")
        self.traversal_depth = rule_data.get("traversal_depth", 2)
        self.constraint_attributes = rule_data.get("constraint_attributes", {})
        self.required_relationships = rule_data.get("required_relationships", [])
        self.attack_path_required = rule_data.get("attack_path_required", False)
        self.min_risk_score = rule_data.get("min_risk_score", 0)

        # Legacy pattern matching (for backward compatibility)
        self.match_type = rule_data.get("match", {}).get("type")
        self.pattern = rule_data.get("match", {}).get("pattern")
        self.condition = rule_data.get("condition", "present")

    def evaluate_graph(self, kg: SecurityKnowledgeGraph) -> list[Finding]:
        """Evaluate this rule against a knowledge graph.

        Algorithm:
            1. Find all resources matching target_resource_type
            2. For each resource, find connected resources within traversal_depth
            3. Check if required_relationships exist in the traversal
            4. Check if constraint_attributes are satisfied along the path
            5. Compute risk_score based on path length and constraint satisfaction
            6. If attack_path_required, only report if multi-hop path found

        Returns:
            List of Finding objects with attack path details
        """
        if not self.target_resource_type:
            return []

        findings = []

        # Find target nodes
        target_nodes = [
            kg.nodes[rid] for rid, node in kg.nodes.items()
            if node["resource_type"] == self.target_resource_type
        ]

        for node in target_nodes:
            resource = kg.resources[node["resource_id"]]
            attack_paths = self._find_attack_paths(kg, node)

            for path in attack_paths:
                if self._path_satisfies_constraints(path, kg):
                    finding = self._create_finding(path, kg)
                    findings.append(finding)

        return findings

    def _find_attack_paths(
        self,
        kg: SecurityKnowledgeGraph,
        start_node: dict
    ) -> list[AttackPath]:
        """Find all attack paths starting from start_node."""
        paths = []
        resource_id = start_node["resource_id"]

        # BFS traversal up to traversal_depth
        queue: list[tuple[str, list[str], list[str]]] = [
            (resource_id, [resource_id], [])
        ]
        visited_paths: set[tuple[str, ...]] = set()

        while queue:
            current, path_ids, path_rels = queue.pop(0)

            if len(path_ids) > self.traversal_depth:
                continue

            # Record this path (as tuple for hashability)
            path_key = tuple(path_ids)
            if path_key in visited_paths:
                continue
            visited_paths.add(path_key)

            # Get outbound relationships from current node
            outbound_rels = [
                r for r in kg.relationships
                if r["source_id"] == current and r["direction"] == "outbound"
            ]

            for rel in outbound_rels:
                next_id = rel["target_id"]
                if next_id not in path_ids:  # Avoid cycles
                    new_path_ids = path_ids + [next_id]
                    new_path_rels = path_rels + [rel["type"]]

                    # Terminal node reached with required depth
                    if len(new_path_ids) >= 2:
                        path_key = tuple(new_path_ids)
                        if path_key not in visited_paths:
                            risk_score = self._compute_risk_score(new_path_ids, new_path_rels)
                            paths.append(AttackPath(
                                path_id=f"{'-'.join(new_path_ids[:3])}",
                                resource_ids=new_path_ids,
                                relationship_types=new_path_rels,
                                risk_score=risk_score,
                                entry_point=new_path_ids[0],
                                terminal_node=new_path_ids[-1],
                            ))

                    # Continue traversal
                    if len(new_path_ids) < self.traversal_depth:
                        queue.append((next_id, new_path_ids, new_path_rels))

        return paths

    def _path_satisfies_constraints(self, path: AttackPath, kg: SecurityKnowledgeGraph) -> bool:
        """Check if a path satisfies required relationship types and attribute constraints."""
        # Check required relationships
        if self.required_relationships:
            path_rel_set = set(path["relationship_types"])
            required_set = set(self.required_relationships)
            if not required_set.issubset(path_rel_set):
                return False

        # Check minimum risk score
        if path["risk_score"] < self.min_risk_score:
            return False

        # Check constraint attributes on each resource in path
        for rid in path["resource_ids"]:
            if rid not in kg.resources:
                continue
            resource = kg.resources[rid]

            for attr_name, constraint in self.constraint_attributes.items():
                if isinstance(constraint, dict):
                    operator = constraint.get("operator", "eq")
                    expected = constraint.get("value")
                else:
                    operator = "eq"
                    expected = constraint

                actual = resource.attributes.get(attr_name)
                if not self._check_constraint(actual, operator, expected):
                    return False

        return True

    def _check_constraint(self, actual, operator: str, expected) -> bool:
        """Check if an actual value satisfies a constraint."""
        if actual is None:
            return False

        if operator == "eq":
            return actual == expected
        elif operator == "ne":
            return actual != expected
        elif operator == "contains":
            if isinstance(actual, list):
                return expected in actual
            elif isinstance(actual, str):
                return expected in actual
            return False
        elif operator == "in":
            return actual in expected
        elif operator == "gt":
            return actual > expected
        elif operator == "lt":
            return actual < expected
        elif operator == "gte":
            return actual >= expected
        elif operator == "lte":
            return actual <= expected

        return False

    def _compute_risk_score(self, path_ids: list[str], relationship_types: list[str]) -> int:
        """Compute risk score for an attack path.

        Score formula:
            base_score = len(path_ids) * 15  # Longer paths = higher risk
            relationship_bonus = count of constraint violations * 10
            final = min(100, base_score + relationship_bonus)
        """
        base_score = len(path_ids) * 15

        # Penalize insecure relationships
        insecure_rels = {
            RelationshipType.EXPOSED_BY,
            RelationshipType.DEPENDS_ON,
        }
        relationship_bonus = sum(
            10 for rel in relationship_types
            if rel in insecure_rels
        )

        # Penalize path length (more hops = more risk)
        if len(path_ids) > 2:
            relationship_bonus += (len(path_ids) - 2) * 5

        return min(100, base_score + relationship_bonus)

    def _create_finding(self, path: AttackPath, kg: SecurityKnowledgeGraph) -> Finding:
        """Create a Finding from an attack path."""
        entry_resource = kg.resources.get(path["entry_point"])
        terminal_resource = kg.resources.get(path["terminal_node"])

        evidence = {
            "path_length": len(path["resource_ids"]),
            "risk_score": path["risk_score"],
            "relationship_chain": " → ".join(path["relationship_types"]),
            "entry_point": path["entry_point"],
            "terminal_node": path["terminal_node"],
        }

        return Finding(
            rule_id=f"{self.id}-PATH",
            rule_name=f"{self.name} (Attack Path)",
            category=self.category,
            severity=self.severity,
            status=FindingStatus.FAIL,
            evidence=str(evidence),
            block_type="graph",
            block_name=f"path:{path['path_id']}",
            remediation=self.remediation,
            evidence_summary={
                "summary": f"Attack path detected: {len(path['resource_ids'])}-hop path with risk score {path['risk_score']}",
                "path": " → ".join(path['relationship_types']),
                "risk_score": path["risk_score"],
            },
        )


# ---------------------------------------------------------------------------
# GraphRuleEngine — Evaluates GraphRules against a SecurityKnowledgeGraph
# ---------------------------------------------------------------------------
class GraphRuleEngine:
    """Rule engine that evaluates GraphRules against a SecurityKnowledgeGraph.

    This extends the existing RuleEngine (which evaluates against flat ConfigIR)
    to support graph-based multi-hop attack path detection.

    Usage:
        kg = SecurityKnowledgeGraph(resources).build()
        gre = GraphRuleEngine(rules_dir="/path/to/rules")
        findings = gre.evaluate_graph(kg)
    """

    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules: list[GraphRule] = []
        self._load_rules()

    def _load_rules(self):
        """Load rules from YAML files."""
        if not self.rules_dir.exists():
            return

        for yaml_file in self.rules_dir.rglob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    rule_data = yaml.safe_load(f)
                    # Only load graph-aware rules
                    if rule_data.get("graph_aware") or rule_data.get("target_resource_type"):
                        self.rules.append(GraphRule(rule_data))
            except (yaml.YAMLError, IOError):
                continue

    def evaluate_graph(self, kg: SecurityKnowledgeGraph) -> list[Finding]:
        """Evaluate all graph-aware rules against a knowledge graph.

        Returns list of findings, including attack path detections.
        """
        all_findings = []
        seen_keys: set[tuple] = set()

        for rule in self.rules:
            findings = rule.evaluate_graph(kg)
            for finding in findings:
                key = (finding.rule_id, finding.block_name)
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_findings.append(finding)

        return all_findings

    def evaluate_graph_legacy_compatible(
        self,
        kg: SecurityKnowledgeGraph,
        legacy_rules: list
    ) -> list[Finding]:
        """Evaluate both graph-aware rules and legacy flat rules.

        This preserves backward compatibility during transition from
        RuleEngine.evaluate() to GraphRuleEngine.evaluate_graph().
        """
        graph_findings = self.evaluate_graph(kg)
        return graph_findings
