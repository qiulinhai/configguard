"""Context Builder for semantic signal grouping.

v0.2.1: Implements Type/Instance separation in SignalContext.

This module provides the Aggregation Layer of ConfigGuard's three-layer IR model:
- Groups signals into semantic contexts
- Separates context_type (what kind of thing) from instance_id (which specific thing)
- Provides guard rails against context explosion attacks
"""
import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

from configguard.models import Signal
from configguard.registry import SignalRegistry, SignalDefinition

# Guard rail: maximum instances per category per node
MAX_CONTEXT_INSTANCES_PER_NODE = 1000


class ContextOverflowError(RuntimeError):
    """Raised when context instances exceed the safety limit."""
    pass


@dataclass
class SignalContext:
    """Semantic grouping of signals for rule evaluation.

    v0.2.1 introduces Type/Instance separation:
    - context_type: The semantic category (e.g., "snmp", "vty", "interface")
    - instance_id: The specific instance identifier (None for singletons)

    This separation enables:
    - O(1) rule matching by type
    - Clear distinction between singleton and per-instance contexts
    - Future extensibility to hierarchical contexts

    Attributes:
        context_type: Semantic category ("snmp", "vty", "interface", etc.)
        instance_id: Specific instance identifier (None for singleton contexts)
        category: Mirrors context_type (保留概念边界 for future flexibility)
        signals: Original signals (preserves audit trail)
        aggregated_evidence: Evidence values for pattern matching
        metadata: Extensible metadata
        id: Stable deterministic ID
    """
    context_type: str
    instance_id: Optional[str]
    signals: list[Signal] = field(default_factory=list)
    aggregated_evidence: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    id: str = field(default="")

    # Alias for category (concept boundary preserved)
    @property
    def category(self) -> str:
        """category mirrors context_type -保留概念边界."""
        return self.context_type

    @property
    def context_key(self) -> str:
        """Backward-compatible context_key for v0.2 code.

        Returns context_type for singleton, or 'type_instance' for per-instance.
        """
        if self.instance_id is None:
            return self.context_type
        return f"{self.context_type}_{self.instance_id}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize context to dictionary for JSON output."""
        return {
            "id": self.id,
            "context_type": self.context_type,
            "instance_id": self.instance_id,
            "category": self.category,
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

    @staticmethod
    def _compute_context_id(context_type: str, instance_id: Optional[str], evidence: list[str]) -> str:
        """Compute stable deterministic ID from context content."""
        key = f"{context_type}:{instance_id or 'singleton'}:{','.join(sorted(evidence))}"
        return hashlib.sha256(key.encode()).hexdigest()[:8]


class ContextBuilder:
    """Builds signal contexts using SignalRegistry metadata.

    v0.2.1 refactoring:
    - Uses SignalRegistry for metadata instead of hardcoded SIGNAL_CONTEXT_CLUSTERS
    - Implements Type/Instance separation
    - Provides guard rails against context explosion
    """

    def __init__(self, registry: Optional[SignalRegistry] = None):
        """Initialize with optional registry.

        Args:
            registry: SignalRegistry instance. If None, uses singleton.
        """
        self.registry = registry or SignalRegistry.get_instance()

    def build_contexts(self, signals: list[Signal]) -> list[SignalContext]:
        """Group signals into semantic contexts.

        Uses SignalRegistry to determine:
        - How to cluster signals (via aggregation_strategy)
        - What context_template to use

        Guard rails:
        - Counts per-instance contexts per category
        - Raises ContextOverflowError if limit exceeded
        """
        if not signals:
            return []

        # Track instance counts for guard rail
        instance_counts: dict[str, set] = {}

        # Step 1: Cluster signals by context
        clusters = self._cluster_signals(signals)

        # Step 2: Apply guard rail check
        self._check_instance_limits(instance_counts)

        # Step 3: Build contexts per cluster
        contexts = []
        for cluster_key, cluster_signals in clusters.items():
            context = self._build_context(cluster_key, cluster_signals)
            contexts.append(context)

        return contexts

    def _cluster_signals(self, signals: list[Signal]) -> dict[str, list[Signal]]:
        """Cluster signals by context using registry metadata."""
        clusters: dict[str, list[Signal]] = {}

        for signal in signals:
            defn = self.registry.get(signal.type)
            if not defn:
                # Unknown signal type, skip or use signal.type as fallback
                cluster_key = signal.type
            else:
                cluster_key = self._get_cluster_key(defn, signal)

            clusters.setdefault(cluster_key, []).append(signal)

        return clusters

    def _get_cluster_key(self, defn: SignalDefinition, signal: Signal) -> str:
        """Get cluster key from signal definition and signal.

        Uses context_template to determine how to group this signal:
        - "singleton": Single global context for this signal type
        - "{context}": Use signal's own context as instance identifier
        - "interface_{context}": Prefix with "interface_" + instance
        """
        template = defn.context_template

        if template == "singleton":
            # Singleton: use category as cluster key
            return defn.category

        # Dynamic template expansion
        if "{context}" in template:
            normalized = signal.context.replace(" ", "_").replace("/", "_")
            # Remove template prefix if present (e.g., "interface_{context}")
            prefix = template.split("{")[0]
            return f"{prefix}{normalized}" if prefix else normalized

        # Static template (shouldn't happen after validation)
        return template

    def _check_instance_limits(self, instance_counts: dict[str, set]) -> None:
        """Check if any category exceeds instance limit.

        Raises:
            ContextOverflowError: If any category exceeds MAX_CONTEXT_INSTANCES_PER_NODE
        """
        for category, instances in instance_counts.items():
            if len(instances) > MAX_CONTEXT_INSTANCES_PER_NODE:
                raise ContextOverflowError(
                    f"Context Avalanche Warning! Category '{category}' "
                    f"exceeded maximum limit of {MAX_CONTEXT_INSTANCES_PER_NODE} instances. "
                    f"Possible configuration error or injection attack."
                )

    def _build_context(self, cluster_key: str, signals: list[Signal]) -> SignalContext:
        """Build a single context from clustered signals.

        Parses cluster_key to extract context_type and instance_id:
        - "management_plane" → context_type="management_plane", instance_id=None
        - "vty_0_4" → context_type="vty", instance_id="0_4"
        - "interface_GigabitEthernet0_0" → context_type="interface", instance_id="GigabitEthernet0_0"
        """
        context_type, instance_id = self._parse_cluster_key(cluster_key)

        # Aggregate evidence values (use raw for pattern matching)
        evidence_values = [s.raw for s in signals]

        # Build metadata
        metadata = {
            "signal_count": len(signals),
            "signal_types": list({s.type for s in signals}),
            "cluster_key": cluster_key,
        }

        # Add specific metadata based on context type
        if context_type == "snmp":
            metadata["community_count"] = len([s for s in signals if s.type == "snmp_community"])
            versions = [s.value for s in signals if s.type == "snmp_version"]
            if versions:
                metadata["version"] = versions[0]
        elif context_type == "vty":
            transports = [s.value for s in signals if s.type == "transport_input"]
            if transports:
                metadata["transport"] = transports
        elif context_type == "interface":
            states = [s.value for s in signals if s.type == "interface_state"]
            if states:
                metadata["state"] = states[0]
            descriptions = [s.value for s in signals if s.type == "interface_description"]
            if descriptions:
                metadata["description"] = descriptions[0]

        # Compute deterministic ID
        context_id = SignalContext._compute_context_id(context_type, instance_id, evidence_values)

        return SignalContext(
            id=context_id,
            context_type=context_type,
            instance_id=instance_id,
            signals=signals,
            aggregated_evidence=evidence_values,
            metadata=metadata,
        )

    def _parse_cluster_key(self, cluster_key: str) -> tuple[str, Optional[str]]:
        """Parse cluster key into context_type and instance_id.

        Examples:
            "management_plane" → ("management_plane", None)
            "vty_0_4" → ("vty", "0_4")
            "interface_GigabitEthernet0_0" → ("interface", "GigabitEthernet0_0")
        """
        # Check for known prefixes
        known_prefixes = ["vty_", "interface_"]

        for prefix in known_prefixes:
            if cluster_key.startswith(prefix):
                instance_id = cluster_key[len(prefix):]
                context_type = prefix.rstrip("_")
                return (context_type, instance_id)

        # Singleton or unknown - no instance_id
        return (cluster_key, None)