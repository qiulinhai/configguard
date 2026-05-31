"""Composite Risk Scoring Engine v0.4.

v0.4 builds on v0.3 RiskEngine by integrating:
- Attack path information from SecurityKnowledgeGraph
- Relationship-based risk propagation
- Privilege gain weighting
- Cross-domain attack chain detection
- Business impact factors (CIS/NIST mapping)

The engine is deterministic: same inputs → same score.

Risk Formula:
    composite_risk = normalize(
        base_severity
        + attack_path_depth_factor
        + exposure_multiplier
        + privilege_gain_weight
        + cross_domain_bonus
        + business_impact_factor
    )
"""
from configguard.models import Finding, Severity
from configguard.ontology import SecurityKnowledgeGraph, RelationshipType
from configguard.risk.v04.model import (
    CompositeRiskResult,
    RiskLevel,
    RiskFactor,
    AttackPathRisk,
    SEVERITY_WEIGHTS,
    PATH_DEPTH_WEIGHTS,
    EXPOSURE_MULTIPLIERS,
    PRIVILEGE_GAIN_WEIGHTS,
    CROSS_DOMAIN_BONUS,
    BUSINESS_IMPACT_WEIGHTS,
    MAX_TOTAL,
)


class CompositeRiskEngine:
    """Compute composite risk score from findings and knowledge graph.

    This is a post-processing layer that:
    - Reads findings from RuleEngine / GraphRuleEngine
    - Optionally reads SecurityKnowledgeGraph for attack paths
    - Computes composite risk score with explainable factors
    - Returns risk level classification

    Usage:
        findings = rule_engine.evaluate(config)
        kg = SecurityKnowledgeGraph(resources).build()
        risk_engine = CompositeRiskEngine()
        result = risk_engine.evaluate(findings, kg=kg)
        print(result.composite_score)  # 0-100
    """

    def evaluate(
        self,
        findings: list[Finding],
        kg: SecurityKnowledgeGraph | None = None,
        business_context: dict | None = None,
    ) -> CompositeRiskResult:
        """Evaluate composite risk score.

        Args:
            findings: List of findings from RuleEngine
            kg: Optional SecurityKnowledgeGraph for attack path analysis
            business_context: Optional business impact factors

        Returns:
            CompositeRiskResult with score breakdown and classification
        """
        if not findings:
            return self._empty_result()

        # Factor 1: Base severity (from rule severity)
        base_severity_score = self._compute_base_severity(findings)

        # Factor 2: Attack path depth (from knowledge graph)
        path_score, top_paths = self._compute_attack_path_score(findings, kg)

        # Factor 3: Exposure multiplier (from finding tags and graph)
        exposure_score = self._compute_exposure_score(findings, kg)

        # Factor 4: Privilege gain weight
        privilege_score = self._compute_privilege_score(findings, kg)

        # Factor 5: Cross-domain bonus
        cross_domain_score = self._compute_cross_domain_score(findings, kg)

        # Factor 6: Business impact
        business_score = self._compute_business_impact(findings, business_context)

        # Compute weighted contributions
        risk_factors = [
            RiskFactor(
                name="base_severity",
                value=base_severity_score,
                weight=1.0,
                contribution=base_severity_score,
                description="Intrinsic severity from rule severity classification",
            ),
            RiskFactor(
                name="attack_path_depth",
                value=path_score,
                weight=1.0,
                contribution=path_score,
                description="Risk from multi-hop attack paths in knowledge graph",
            ),
            RiskFactor(
                name="exposure_multiplier",
                value=exposure_score,
                weight=1.0,
                contribution=exposure_score,
                description="Exposure level based on network reachability",
            ),
            RiskFactor(
                name="privilege_gain",
                value=privilege_score,
                weight=1.0,
                contribution=privilege_score,
                description="Potential privilege gain from exploit",
            ),
            RiskFactor(
                name="cross_domain_bonus",
                value=cross_domain_score,
                weight=1.0,
                contribution=cross_domain_score,
                description="Bonus for multi-domain attack chains",
            ),
            RiskFactor(
                name="business_impact",
                value=business_score,
                weight=1.0,
                contribution=business_score,
                description="Business impact based on compliance requirements",
            ),
        ]

        # Sum all contributions for raw score
        raw_score = sum(f["contribution"] for f in risk_factors)

        # Normalize to 0-100
        composite_score = self._normalize_score(raw_score)

        # Classify risk level
        risk_level = self._classify_risk_level(composite_score)

        # Find top risk finding
        top_finding_id = self._find_top_risk_finding(findings, base_severity_score)

        return CompositeRiskResult(
            composite_score=composite_score,
            risk_level=RiskLevel(risk_level),
            risk_factors=risk_factors,
            attack_paths=top_paths,
            top_risk_finding_id=top_finding_id,
            exposure_score=self._normalize_score(exposure_score * 3.33),  # Scale to 100
            privilege_score=self._normalize_score(privilege_score * 2.5),  # Scale to 100
            business_impact_score=self._normalize_score(business_score * 3.33),  # Scale to 100
            metadata={
                "finding_count": len(findings),
                "has_graph": kg is not None,
                "formula": "composite_risk = base_severity + path_depth + exposure + privilege + cross_domain + business",
            },
        )

    def _compute_base_severity(self, findings: list[Finding]) -> float:
        """Compute base severity score from finding severities."""
        total = 0.0
        for f in findings:
            weight = SEVERITY_WEIGHTS.get(f.severity.value, 0)
            total += weight
        return min(total / max(1, len(findings)), MAX_TOTAL * 0.4)

    def _compute_attack_path_score(
        self,
        findings: list[Finding],
        kg: SecurityKnowledgeGraph | None
    ) -> tuple[float, list[AttackPathRisk]]:
        """Compute risk from attack paths in knowledge graph.

        Returns (score, top_paths).
        """
        if kg is None:
            return 0.0, []

        top_paths = []
        total_path_risk = 0.0

        # Find paths through high-risk resources
        for finding in findings:
            if finding.block_type == "graph":
                # This finding came from graph-based rule
                path_id = finding.block_name
                if path_id and path_id.startswith("path:"):
                    # Extract resource IDs from path
                    path_key = path_id.replace("path:", "")
                    resource_ids = path_key.split("-")

                    if len(resource_ids) >= 2:
                        depth = len(resource_ids) - 1
                        depth_weight = PATH_DEPTH_WEIGHTS.get(
                            min(depth, max(PATH_DEPTH_WEIGHTS.keys())),
                            PATH_DEPTH_WEIGHTS[max(PATH_DEPTH_WEIGHTS.keys())]
                        )

                        path_risk = depth_weight + (depth * 5)
                        total_path_risk += path_risk

                        top_paths.append(AttackPathRisk(
                            path_id=path_id,
                            path_length=depth,
                            entry_point=resource_ids[0],
                            terminal_node=resource_ids[-1],
                            risk_score=min(100, path_risk * 2),
                            relationship_chain=[],
                            privilege_gain=5,
                            cross_domain=False,
                            business_impact=None,
                        ))

        # Also analyze graph structure for high-risk paths
        if kg.stats["total_relationships"] > 0:
            outbound = [r for r in kg.relationships if r["direction"] == "outbound"]
            high_risk_rels = {RelationshipType.EXPOSED_BY, RelationshipType.DEPENDS_ON}

            for rel in outbound:
                if rel["type"] in high_risk_rels:
                    path_score = PATH_DEPTH_WEIGHTS.get(2, 10)
                    total_path_risk += path_score

        # Limit path score contribution
        return min(total_path_risk, MAX_TOTAL * 0.25), top_paths[:5]

    def _compute_exposure_score(
        self,
        findings: list[Finding],
        kg: SecurityKnowledgeGraph | None
    ) -> float:
        """Compute exposure multiplier based on resource reachability."""
        exposure = 1.0  # Default multiplier

        for f in findings:
            # Check tags for exposure hints
            tags = getattr(f, 'tags', []) if hasattr(f, 'tags') else []
            if tags:
                if "internet-exposed" in tags or "mgmt-plane" in tags:
                    exposure = max(exposure, EXPOSURE_MULTIPLIERS["mgmt-plane"])

        # If graph available, check for exposed resources
        if kg:
            for rid, node in kg.nodes.items():
                resource = kg.resources.get(rid)
                if resource:
                    tags = resource.tags
                    if "internet-exposed" in tags:
                        exposure = EXPOSURE_MULTIPLIERS["internet-exposed"]
                        break
                    elif "mgmt-plane" in tags:
                        exposure = max(exposure, EXPOSURE_MULTIPLIERS["mgmt-plane"])

        # Return weighted exposure score
        base_score = 10.0
        return base_score * exposure

    def _compute_privilege_score(
        self,
        findings: list[Finding],
        kg: SecurityKnowledgeGraph | None
    ) -> float:
        """Compute privilege gain weight from findings and graph."""
        privilege_score = 0.0

        for f in findings:
            category = f.category.lower()

            # Category-based privilege assessment
            if "auth" in category or "rbac" in category:
                if any(kw in category for kw in ["admin", "write", "root"]):
                    privilege_score = max(privilege_score, PRIVILEGE_GAIN_WEIGHTS["admin"])
                elif "read" in category or "access" in category:
                    privilege_score = max(privilege_score, PRIVILEGE_GAIN_WEIGHTS["read"])
            elif "config" in category or "write" in category:
                privilege_score = max(privilege_score, PRIVILEGE_GAIN_WEIGHTS["write"])

        # Check graph for RBAC/privilege relationships
        if kg:
            for rid, node in kg.nodes.items():
                resource = kg.resources.get(rid)
                if resource and resource.resource_type.startswith("auth.rbac."):
                    wildcard = resource.attributes.get("wildcard")
                    if wildcard is True:
                        privilege_score = max(privilege_score, PRIVILEGE_GAIN_WEIGHTS["admin"])

        return min(privilege_score, MAX_TOTAL * 0.20)

    def _compute_cross_domain_score(
        self,
        findings: list[Finding],
        kg: SecurityKnowledgeGraph | None
    ) -> float:
        """Compute cross-domain attack chain bonus."""
        if kg is None:
            return 0.0

        domains_seen: set[str] = set()

        # Collect domains from findings
        for f in findings:
            category = f.category.lower()
            if "auth" in category:
                domains_seen.add("auth")
            elif "network" in category or "snmp" in category or "interface" in category:
                domains_seen.add("network")
            elif "os" in category or "sysctl" in category or "pam" in category:
                domains_seen.add("os")
            elif "logging" in category or "monitoring" in category:
                domains_seen.add("observability")
            elif "cloud" in category or "k8s" in category:
                domains_seen.add("cloud-native")

        # Collect domains from graph
        if kg:
            for rid in kg.resources:
                resource = kg.resources[rid]
                rt = resource.resource_type
                domain = rt.split(".")[0]
                domains_seen.add(domain)

        # Bonus per additional domain after first
        domain_count = len(domains_seen)
        if domain_count > 1:
            return CROSS_DOMAIN_BONUS * (domain_count - 1)

        return 0.0

    def _compute_business_impact(
        self,
        findings: list[Finding],
        business_context: dict | None
    ) -> float:
        """Compute business impact based on compliance mapping."""
        if business_context is None:
            business_context = {}

        impact_score = 0.0

        # Default compliance categories that matter
        compliance_categories = {
            "confidentiality": ["snmp", "auth", "encryption"],
            "integrity": ["config", "write", "acl"],
            "availability": ["logging", "ntp", "syslog"],
        }

        for f in findings:
            category = f.category.lower()
            severity = f.severity.value

            # High severity issues in compliance categories get business impact
            if severity in ("HIGH", "CRITICAL"):
                for impact_type, keywords in compliance_categories.items():
                    if any(kw in category for kw in keywords):
                        weight = BUSINESS_IMPACT_WEIGHTS.get(impact_type, 0)
                        if severity == "CRITICAL":
                            weight *= 1.5
                        impact_score += weight

        # Apply business context overrides
        if business_context:
            if business_context.get("is_regulated"):
                impact_score *= 1.3
            if business_context.get("is_critical_infrastructure"):
                impact_score *= 1.5

        return min(impact_score, MAX_TOTAL * 0.15)

    def _normalize_score(self, raw_score: float) -> int:
        """Normalize raw score to 0-100 range."""
        if raw_score <= 0:
            return 0
        normalized = (raw_score / MAX_TOTAL) * 100
        return min(100, max(0, int(normalized)))

    def _classify_risk_level(self, score: int) -> str:
        """Classify risk score into risk level."""
        if score >= 85:
            return "CRITICAL"
        elif score >= 65:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "INFO"

    def _find_top_risk_finding(self, findings: list[Finding], base_score: float) -> str | None:
        """Find the finding with highest base severity."""
        if not findings:
            return None

        top = max(findings, key=lambda f: (
            SEVERITY_WEIGHTS.get(f.severity.value, 0),
            1 if f.status.value == "FAIL" else 0
        ))
        return f"{top.rule_id}:{top.block_name}" if top.block_name else top.rule_id

    def _empty_result(self) -> CompositeRiskResult:
        """Return empty result when no findings."""
        return CompositeRiskResult(
            composite_score=0,
            risk_level=RiskLevel.INFO,
            risk_factors=[],
            attack_paths=[],
            top_risk_finding_id=None,
            exposure_score=0,
            privilege_score=0,
            business_impact_score=0,
            metadata={"finding_count": 0},
        )
