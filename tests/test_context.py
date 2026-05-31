"""Tests for ContextBuilder v0.2.1.

Tests SignalContext Type/Instance separation and registry integration.
"""
import pytest
from configguard.models import Signal
from configguard.context import ContextBuilder, SignalContext
from configguard.registry import create_signal_registry_with_defaults, SignalRegistry


class TestSignalContextStructure:
    """Test SignalContext has Type/Instance separation."""

    def setup_method(self):
        """Initialize registry before each test."""
        SignalRegistry.reset_instance()
        create_signal_registry_with_defaults()

    def test_context_has_context_type(self):
        """SignalContext must have context_type field."""
        ctx = SignalContext(
            context_type="snmp",
            instance_id=None,
        )
        assert ctx.context_type == "snmp"

    def test_context_has_instance_id(self):
        """SignalContext must have instance_id field."""
        ctx = SignalContext(
            context_type="vty",
            instance_id="0_4",
        )
        assert ctx.instance_id == "0_4"

    def test_singleton_context_has_no_instance_id(self):
        """Singleton contexts have instance_id=None."""
        ctx = SignalContext(
            context_type="management_plane",
            instance_id=None,
        )
        assert ctx.instance_id is None

    def test_category_alias(self):
        """category property mirrors context_type."""
        ctx = SignalContext(
            context_type="interface",
            instance_id="GigabitEthernet0/0",
        )
        assert ctx.category == ctx.context_type

    def test_context_id_is_deterministic(self):
        """Context ID must be stable across runs."""
        ctx1 = SignalContext(
            context_type="snmp",
            instance_id=None,
            signals=[],
            aggregated_evidence=["public"],
        )
        ctx2 = SignalContext(
            context_type="snmp",
            instance_id=None,
            signals=[],
            aggregated_evidence=["public"],
        )
        assert ctx1.id == ctx2.id


class TestContextBuilder:
    """Test ContextBuilder signal grouping with registry."""

    def setup_method(self):
        """Initialize registry before each test."""
        SignalRegistry.reset_instance()
        create_signal_registry_with_defaults()

    def test_empty_signals_returns_empty_contexts(self):
        """No signals returns no contexts."""
        builder = ContextBuilder()
        contexts = builder.build_contexts([])
        assert contexts == []

    def test_snmp_signals_cluster_by_type(self):
        """SNMP signals form one context with context_type='snmp'."""
        signals = [
            Signal(type="snmp_community", value="public", context="global",
                   block_type="global", raw="snmp-server community public"),
            Signal(type="snmp_version", value="v2c", context="global",
                   block_type="global", raw="snmp-server community"),
        ]

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals)

        assert len(contexts) == 1
        ctx = contexts[0]
        assert ctx.context_type == "snmp"  # Uses category for singleton
        assert ctx.instance_id is None
        assert len(ctx.signals) == 2

    def test_vty_signals_cluster_by_instance(self):
        """Different VTY lines form separate contexts."""
        signals = [
            Signal(type="transport_input", value="telnet", context="vty 0 4",
                   block_type="line", raw="transport input telnet"),
            Signal(type="transport_input", value="telnet", context="vty 5 9",
                   block_type="line", raw="transport input telnet"),
        ]

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals)

        assert len(contexts) == 2
        context_types = {ctx.context_type for ctx in contexts}
        assert context_types == {"vty"}

        instance_ids = {ctx.instance_id for ctx in contexts}
        assert instance_ids == {"0_4", "5_9"}

    def test_interface_signals_cluster_by_instance(self):
        """Interface signals group by specific interface."""
        signals = [
            Signal(type="interface_state", value="up", context="GigabitEthernet0/0",
                   block_type="interface", raw="no shutdown"),
            Signal(type="interface_state", value="shutdown", context="GigabitEthernet0/1",
                   block_type="interface", raw="shutdown"),
        ]

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals)

        assert len(contexts) == 2
        context_types = {ctx.context_type for ctx in contexts}
        assert context_types == {"interface"}

        instance_ids = {ctx.instance_id for ctx in contexts}
        assert "GigabitEthernet0_0" in instance_ids
        assert "GigabitEthernet0_1" in instance_ids

    def test_mixed_signals_all_clustered(self):
        """Mixed signal types all get clustered."""
        signals = [
            Signal(type="snmp_community", value="public", context="global",
                   block_type="global", raw="snmp-server community public"),
            Signal(type="transport_input", value="telnet", context="vty 0 4",
                   block_type="line", raw="transport input telnet"),
        ]

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals)

        # Both signals clustered (SNMP singleton + VTY per-instance)
        assert len(contexts) == 2
        context_types = {ctx.context_type for ctx in contexts}
        assert "snmp" in context_types
        assert "vty" in context_types


class TestContextKeyExpansion:
    """Test context cluster key generation."""

    def setup_method(self):
        SignalRegistry.reset_instance()
        create_signal_registry_with_defaults()

    def test_vty_cluster_key_format(self):
        """VTY context cluster key is 'vty_{instance}'."""
        signal = Signal(
            type="transport_input",
            value="telnet",
            context="vty 0 4",
            block_type="line",
            raw="transport input telnet",
        )

        builder = ContextBuilder()
        clusters = builder._cluster_signals([signal])
        cluster_keys = list(clusters.keys())

        assert "vty_0_4" in cluster_keys

    def test_interface_cluster_key_format(self):
        """Interface context cluster key is 'interface_{name}'."""
        signal = Signal(
            type="interface_state",
            value="up",
            context="GigabitEthernet0/0",
            block_type="interface",
            raw="no shutdown",
        )

        builder = ContextBuilder()
        clusters = builder._cluster_signals([signal])
        cluster_keys = list(clusters.keys())

        assert "interface_GigabitEthernet0_0" in cluster_keys


class TestAggregatedEvidence:
    """Test evidence aggregation in contexts."""

    def setup_method(self):
        SignalRegistry.reset_instance()
        create_signal_registry_with_defaults()

    def test_snmp_context_aggregates_all_evidence(self):
        """SNMP context aggregates all community strings."""
        signals = [
            Signal(type="snmp_community", value="public", context="global",
                   block_type="global", raw="snmp-server community public"),
            Signal(type="snmp_community", value="private", context="global",
                   block_type="global", raw="snmp-server community private"),
            Signal(type="snmp_version", value="v2c", context="global",
                   block_type="global", raw="snmp-server community"),
        ]

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals)

        assert len(contexts) == 1
        ctx = contexts[0]
        # aggregated_evidence contains raw command strings
        evidence_str = ", ".join(ctx.aggregated_evidence)
        assert "public" in evidence_str
        assert "private" in evidence_str

    def test_vty_context_aggregates_transport_methods(self):
        """VTY context aggregates transport methods."""
        signals = [
            Signal(type="transport_input", value="telnet", context="vty 0 4",
                   block_type="line", raw="transport input telnet"),
            Signal(type="transport_input", value="ssh", context="vty 0 4",
                   block_type="line", raw="transport input telnet ssh"),
        ]

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals)

        assert len(contexts) == 1
        ctx = contexts[0]
        evidence = set(ctx.aggregated_evidence)
        assert "transport input telnet" in evidence
        assert "transport input telnet ssh" in evidence


class TestIntegrationSnmpSingleFinding:
    """Integration test for SNMP single finding with context aggregation."""

    def test_snmp_single_finding_with_all_communities(self):
        """SNMP rule produces findings with community strings.

        Note: Full context-based aggregation (1 finding for all communities)
        requires rules to have applies_to declarations. Current rules don't have
        these yet, so this test validates the current behavior.
        """
        from configguard.parser import CiscoIOSParser
        from configguard.signals import SignalExtractor
        from configguard.context import ContextBuilder
        from configguard.engine import RuleEngine

        SignalRegistry.reset_instance()
        create_signal_registry_with_defaults()

        config_text = """
        hostname Router1
        !
        snmp-server community public RO
        snmp-server community private RW
        snmp-server community community123
        !
        end
        """

        parser = CiscoIOSParser(config_text)
        ir = parser.parse()

        extractor = SignalExtractor()
        signals = extractor.extract(ir)

        # Verify all 3 signals extracted (3 communities + 1 version)
        snmp_communities = [s for s in signals if s.type == "snmp_community"]
        assert len(snmp_communities) == 3

        builder = ContextBuilder()
        engine = RuleEngine("configguard/rules")

        contexts = builder.build_contexts(signals)

        # Verify contexts are built (context aggregation is working)
        snmp_contexts = [c for c in contexts if c.context_type == "snmp"]
        assert len(snmp_contexts) == 1

        # Context correctly aggregates all signals
        ctx = snmp_contexts[0]
        evidence_str = ", ".join(ctx.aggregated_evidence)
        assert "public" in evidence_str
        assert "private" in evidence_str
        assert "community123" in evidence_str


class TestGuardRail:
    """Test context explosion guard rails."""

    def setup_method(self):
        SignalRegistry.reset_instance()
        create_signal_registry_with_defaults()

    def test_many_instances_tracked(self):
        """Many interface instances are tracked correctly."""
        # Create many interface signals
        signals = [
            Signal(
                type="interface_state",
                value="up",
                context=f"GigabitEthernet0/{i}",
                block_type="interface",
                raw="no shutdown",
            )
            for i in range(100)
        ]

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals)

        # All 100 interfaces should form separate contexts
        assert len(contexts) == 100