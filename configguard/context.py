"""Context Builder for semantic signal grouping."""
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any
from configguard.models import Signal


SIGNAL_CONTEXT_CLUSTERS = {
    # SNMP: all SNMP signals cluster by security context
    "snmp_version": "snmp_security",
    "snmp_community": "snmp_security",

    # VTY: per-VTY instance (context already contains "vty" prefix after normalization)
    "transport_input": "{context}",
    "auth_method": "{context}",

    # Interface: per-interface
    "interface_state": "interface_{context}",
    "interface_description": "interface_{context}",

    # Global: single context
    "aaa_enabled": "global_auth",
    "http_server": "global_services",
    "syslog_host": "global_logging",
    "ntp_server": "global_time",
}


@dataclass
class SignalContext:
    """A semantic grouping of signals relevant to a single rule evaluation.

    This is the core semantic unit of ConfigGuard's reasoning layer.
    All rule evaluations operate on contexts, not individual signals.

    Schema (frozen v0.2.1):
        id: str - Unique identifier (auto-generated UUID)
        context_key: str - Semantic type (e.g., "snmp_security", "vty_0_4")
        signals: list[Signal] - Original signals (preserves audit trail)
        aggregated_evidence: list[str] - Evidence values for pattern matching
        metadata: dict - Extensible metadata
    """
    context_key: str
    signals: list[Signal] = field(default_factory=list)
    aggregated_evidence: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict[str, Any]:
        """Serialize context to dictionary for JSON output."""
        return {
            "id": self.id,
            "context_key": self.context_key,
            "signals": [
                {
                    "type": s.type,
                    "value": s.value,
                    "context": s.context,
                    "block_type": s.block_type,
                    "raw": s.raw,
                }
                for s in self.signals
            ],
            "evidence": self.aggregated_evidence,
            "metadata": self.metadata,
        }


class ContextBuilder:
    """Builds signal contexts for rule evaluation.

    Groups signals by rule-relevant semantic dimensions so that
    rules evaluate against contexts (not individual signals).
    """

    def build_contexts(self, signals: list[Signal], rules: list) -> list[SignalContext]:
        """Group signals into contexts for rule evaluation.

        Each context is scoped to a specific rule_id and contains
        all signals relevant to that rule's evaluation.
        """
        if not signals:
            return []

        # Step 1: Cluster signals by context key
        clusters = self._cluster_signals(signals)

        # Step 2: Build contexts for each rule's relevant clusters
        contexts = []
        for rule in rules:
            relevant_clusters = self._get_relevant_clusters_for_rule(rule, clusters)
            for cluster_key, cluster_signals in relevant_clusters.items():
                context = self._build_context(rule.id, cluster_key, cluster_signals)
                contexts.append(context)

        return contexts

    def _cluster_signals(self, signals: list[Signal]) -> dict[str, list[Signal]]:
        """Cluster signals by context key."""
        clusters: dict[str, list[Signal]] = {}

        for signal in signals:
            cluster_key = self._get_cluster_key(signal)
            if cluster_key not in clusters:
                clusters[cluster_key] = []
            clusters[cluster_key].append(signal)

        return clusters

    def _get_cluster_key(self, signal: Signal) -> str:
        """Get the cluster key for a signal."""
        template = SIGNAL_CONTEXT_CLUSTERS.get(signal.type, signal.type)
        return self._expand_context_key(template, signal)

    def _expand_context_key(self, template: str, signal: Signal) -> str:
        """Expand context key template with signal context."""
        if "{context}" in template:
            normalized = signal.context.replace(" ", "_").replace("/", "_")
            return template.format(context=normalized)
        return template

    def _get_relevant_clusters_for_rule(self, rule, clusters: dict[str, list[Signal]]) -> dict[str, list[Signal]]:
        """Get clusters relevant for a rule based on rule's signal dependencies."""
        relevant = {}
        rule_id_lower = rule.id.lower()

        # Determine which signal types this rule cares about
        if "snmp" in rule_id_lower:
            # SNMP rules need snmp_security cluster
            if "snmp_security" in clusters:
                relevant["snmp_security"] = clusters["snmp_security"]
        elif "vty" in rule_id_lower or "mgmt" in rule_id_lower:
            # VTY/mgmt rules need vty clusters
            for key, sigs in clusters.items():
                if key.startswith("vty_"):
                    relevant[key] = sigs
        elif "interface" in rule_id_lower:
            # Interface rules need interface clusters
            for key, sigs in clusters.items():
                if key.startswith("interface_"):
                    relevant[key] = sigs
        elif "auth" in rule_id_lower or "aaa" in rule_id_lower:
            # Auth rules need global_auth cluster
            if "global_auth" in clusters:
                relevant["global_auth"] = clusters["global_auth"]
        elif "http" in rule_id_lower or "web" in rule_id_lower:
            # HTTP rules need global_services cluster
            if "global_services" in clusters:
                relevant["global_services"] = clusters["global_services"]
        elif "syslog" in rule_id_lower or "logging" in rule_id_lower:
            if "global_logging" in clusters:
                relevant["global_logging"] = clusters["global_logging"]
        elif "ntp" in rule_id_lower or "time" in rule_id_lower:
            if "global_time" in clusters:
                relevant["global_time"] = clusters["global_time"]
        else:
            # For rules that don't match specific categories, don't include any clusters
            # This prevents false positive context assignment
            pass

        return relevant

    def _build_context(self, rule_id: str, cluster_key: str, signals: list[Signal]) -> SignalContext:
        """Build a single context from clustered signals."""
        # Aggregate evidence values
        evidence_values = [s.value for s in signals]

        # Build metadata
        metadata = {
            "signal_count": len(signals),
            "signal_types": list({s.type for s in signals}),
            "rule_id": rule_id,  # Track which rule this context is for
        }

        # Add specific metadata based on context type
        if cluster_key == "snmp_security":
            metadata["community_count"] = len([s for s in signals if s.type == "snmp_community"])
            versions = [s.value for s in signals if s.type == "snmp_version"]
            if versions:
                metadata["version"] = versions[0]
        elif cluster_key.startswith("vty_"):
            transports = [s.value for s in signals if s.type == "transport_input"]
            if transports:
                metadata["transport"] = transports
        elif cluster_key.startswith("interface_"):
            states = [s.value for s in signals if s.type == "interface_state"]
            if states:
                metadata["state"] = states[0]
            descriptions = [s.value for s in signals if s.type == "interface_description"]
            if descriptions:
                metadata["description"] = descriptions[0]

        return SignalContext(
            context_key=cluster_key,
            signals=signals,
            aggregated_evidence=evidence_values,
            metadata=metadata,
        )
