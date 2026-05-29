"""Tests for ContextBuilder."""
import pytest
from configguard.models import Signal
from configguard.context import ContextBuilder, SignalContext, SIGNAL_CONTEXT_CLUSTERS


class TestSignalContextClusters:
    """Test signal to context key mapping."""

    def test_snmp_signals_cluster_to_snmp_security(self):
        assert SIGNAL_CONTEXT_CLUSTERS["snmp_version"] == "snmp_security"
        assert SIGNAL_CONTEXT_CLUSTERS["snmp_community"] == "snmp_security"

    def test_vty_signals_cluster_to_vty_context(self):
        assert SIGNAL_CONTEXT_CLUSTERS["transport_input"] == "{context}"
        assert SIGNAL_CONTEXT_CLUSTERS["auth_method"] == "{context}"

    def test_interface_signals_cluster_to_interface_context(self):
        assert SIGNAL_CONTEXT_CLUSTERS["interface_state"] == "interface_{context}"
        assert SIGNAL_CONTEXT_CLUSTERS["interface_description"] == "interface_{context}"

    def test_global_signals_cluster_to_global_contexts(self):
        assert SIGNAL_CONTEXT_CLUSTERS["aaa_enabled"] == "global_auth"
        assert SIGNAL_CONTEXT_CLUSTERS["http_server"] == "global_services"
        assert SIGNAL_CONTEXT_CLUSTERS["syslog_host"] == "global_logging"
        assert SIGNAL_CONTEXT_CLUSTERS["ntp_server"] == "global_time"


class TestContextBuilder:
    """Test ContextBuilder signal grouping."""

    def test_empty_signals_returns_empty_contexts(self):
        builder = ContextBuilder()
        contexts = builder.build_contexts([], [])
        assert contexts == []

    def test_single_snmp_community_groups_correctly(self):
        """Single SNMP community should form one context."""
        signals = [
            Signal(type="snmp_community", value="public", context="global",
                   block_type="global", raw="snmp-server community public"),
        ]

        # Mock rule object with id containing "snmp"
        class MockRule:
            id = "CISCO-SNMP-001"

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals, [MockRule()])

        assert len(contexts) == 1
        ctx = contexts[0]
        assert ctx.rule_id == "CISCO-SNMP-001"
        assert ctx.context_key == "snmp_security"
        assert len(ctx.signals) == 1
        assert "public" in ctx.aggregated_evidence

    def test_multiple_snmp_communities_group_into_single_context(self):
        """Multiple SNMP communities should aggregate into one context."""
        signals = [
            Signal(type="snmp_community", value="public", context="global",
                   block_type="global", raw="snmp-server community public"),
            Signal(type="snmp_community", value="private", context="global",
                   block_type="global", raw="snmp-server community private"),
            Signal(type="snmp_version", value="v2c", context="global",
                   block_type="global", raw="snmp-server community"),
        ]

        class MockRule:
            id = "CISCO-SNMP-001"

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals, [MockRule()])

        # Should be ONE context, not three
        assert len(contexts) == 1
        ctx = contexts[0]
        assert ctx.context_key == "snmp_security"
        assert len(ctx.signals) == 3
        assert set(ctx.aggregated_evidence) == {"public", "private", "v2c"}
        assert ctx.metadata["community_count"] == 2

    def test_multiple_vty_lines_separate_contexts(self):
        """Different VTY lines should form separate contexts."""
        signals = [
            Signal(type="transport_input", value="telnet", context="vty 0 4",
                   block_type="line", raw="transport input telnet"),
            Signal(type="transport_input", value="telnet", context="vty 5 9",
                   block_type="line", raw="transport input telnet"),
        ]

        class MockRule:
            id = "CISCO-MGMT-001"

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals, [MockRule()])

        assert len(contexts) == 2
        context_keys = {ctx.context_key for ctx in contexts}
        assert "vty_0_4" in context_keys
        assert "vty_5_9" in context_keys

    def test_interface_signals_group_by_interface(self):
        """Interface signals should group per interface."""
        signals = [
            Signal(type="interface_state", value="up", context="GigabitEthernet0/0",
                   block_type="interface", raw="no shutdown"),
            Signal(type="interface_state", value="shutdown", context="GigabitEthernet0/1",
                   block_type="interface", raw="shutdown"),
        ]

        class MockRule:
            id = "CISCO-INTERFACE-001"

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals, [MockRule()])

        assert len(contexts) == 2
        context_keys = {ctx.context_key for ctx in contexts}
        assert "interface_GigabitEthernet0_0" in context_keys
        assert "interface_GigabitEthernet0_1" in context_keys

    def test_mixed_signals_filter_by_rule(self):
        """Context builder should filter clusters based on rule type."""
        signals = [
            Signal(type="snmp_community", value="public", context="global",
                   block_type="global", raw="snmp-server community public"),
            Signal(type="transport_input", value="telnet", context="vty 0 4",
                   block_type="line", raw="transport input telnet"),
        ]

        # SNMP rule should only get SNMP context
        class SnmpRule:
            id = "CISCO-SNMP-001"

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals, [SnmpRule()])

        assert len(contexts) == 1
        assert contexts[0].context_key == "snmp_security"


class TestContextKeyExpansion:
    """Test context key template expansion."""

    def test_vty_context_expansion(self):
        """vty_{context} should expand with normalized context."""
        signal = Signal(
            type="transport_input",
            value="telnet",
            context="vty 0 4",
            block_type="line",
            raw="transport input telnet",
        )

        builder = ContextBuilder()
        key = builder._get_cluster_key(signal)
        assert key == "vty_0_4"

    def test_interface_context_expansion(self):
        """interface_{context} should expand with normalized context."""
        signal = Signal(
            type="interface_state",
            value="up",
            context="GigabitEthernet0/0",
            block_type="interface",
            raw="no shutdown",
        )

        builder = ContextBuilder()
        key = builder._get_cluster_key(signal)
        assert key == "interface_GigabitEthernet0_0"

    def test_global_context_no_expansion(self):
        """Global contexts without template don't expand."""
        signal = Signal(
            type="aaa_enabled",
            value="true",
            context="global",
            block_type="global",
            raw="aaa new-model",
        )

        builder = ContextBuilder()
        key = builder._get_cluster_key(signal)
        assert key == "global_auth"


class TestAggregatedEvidence:
    """Test evidence aggregation in contexts."""

    def test_snmp_context_aggregates_all_evidence(self):
        """SNMP context should aggregate public, private, version."""
        signals = [
            Signal(type="snmp_community", value="public", context="global",
                   block_type="global", raw="snmp-server community public"),
            Signal(type="snmp_community", value="private", context="global",
                   block_type="global", raw="snmp-server community private"),
            Signal(type="snmp_version", value="v2c", context="global",
                   block_type="global", raw="snmp-server community"),
        ]

        class MockRule:
            id = "CISCO-SNMP-001"

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals, [MockRule()])

        assert len(contexts) == 1
        ctx = contexts[0]
        assert set(ctx.aggregated_evidence) == {"public", "private", "v2c"}
        assert ctx.metadata["community_count"] == 2
        assert ctx.metadata["version"] == "v2c"

    def test_vty_context_aggregates_transport_methods(self):
        """VTY context should aggregate all transport methods."""
        signals = [
            Signal(type="transport_input", value="telnet", context="vty 0 4",
                   block_type="line", raw="transport input telnet"),
            Signal(type="transport_input", value="ssh", context="vty 0 4",
                   block_type="line", raw="transport input telnet ssh"),
            Signal(type="auth_method", value="local", context="vty 0 4",
                   block_type="line", raw="login local"),
        ]

        class MockRule:
            id = "CISCO-MGMT-001"

        builder = ContextBuilder()
        contexts = builder.build_contexts(signals, [MockRule()])

        assert len(contexts) == 1
        ctx = contexts[0]
        assert set(ctx.aggregated_evidence) == {"telnet", "ssh", "local"}
        assert "telnet" in ctx.metadata.get("transport", [])
        assert "ssh" in ctx.metadata.get("transport", [])


class TestIntegrationSnmpSingleFinding:
    """Integration test for SNMP single finding with context aggregation."""

    def test_snmp_single_finding_with_all_communities(self):
        """SNMP rule produces ONE finding with all community strings."""
        from configguard.parser import CiscoIOSParser
        from configguard.signals import SignalExtractor
        from configguard.context import ContextBuilder
        from configguard.engine import RuleEngine

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

        # Build contexts for SNMP rules
        snmp_rules = [r for r in engine.rules if "snmp" in r.id.lower()]
        contexts = builder.build_contexts(signals, snmp_rules)

        # Evaluate with contexts
        findings = engine.evaluate_with_contexts(contexts)

        # ONE finding for CISCO-SNMP-001
        snmp_findings = [f for f in findings if f.rule_id == "CISCO-SNMP-001"]
        assert len(snmp_findings) == 1

        # Evidence contains all three communities
        evidence = snmp_findings[0].evidence
        assert "public" in evidence
        assert "private" in evidence
        assert "community123" in evidence
