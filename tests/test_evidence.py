"""Unit tests for configguard.evidence — EvidenceBuilder formatting layer."""
import pytest

from configguard.context import SignalContext
from configguard.evidence import EvidenceBuilder
from configguard.models import Finding, FindingStatus, Severity, Signal


def make_signal(signal_type: str, value: str, context: str = "ctx1", block_type: str = "block", raw: str | None = None) -> Signal:
    return Signal(
        type=signal_type,
        value=value,
        context=context,
        block_type=block_type,
        raw=raw or f"{signal_type}={value}",
    )


def make_context(
    context_type: str = "snmp",
    instance_id: str | None = None,
    signals: list[Signal] | None = None,
    metadata: dict | None = None,
) -> SignalContext:
    return SignalContext(
        context_type=context_type,
        instance_id=instance_id,
        signals=signals or [],
        metadata=metadata or {},
    )


def make_finding(severity: Severity = Severity.HIGH, status: FindingStatus = FindingStatus.FAIL) -> Finding:
    return Finding(
        rule_id="TEST-001",
        rule_name="Test",
        category="test",
        severity=severity,
        status=status,
        evidence="raw evidence",
    )


class TestBuildSnmpEvidence:
    def test_single_community(self):
        ctx = make_context("snmp", signals=[
            make_signal("snmp_community", "public", "snmp"),
            make_signal("snmp_version", "v2c", "snmp"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert result["summary"] == "SNMP v2c enabled with 1 community strings: public"
        assert result["details"] == ["public"]
        assert result["raw_count"] == 2

    def test_multiple_communities(self):
        ctx = make_context("snmp", signals=[
            make_signal("snmp_community", "public", "snmp"),
            make_signal("snmp_community", "private", "snmp"),
            make_signal("snmp_version", "v2c", "snmp"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert "public" in result["summary"]
        assert "private" in result["summary"]
        assert result["details"] == ["public", "private"]

    def test_no_version_defaults_to_v2c(self):
        ctx = make_context("snmp", signals=[
            make_signal("snmp_community", "public", "snmp"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert "SNMP v2c" in result["summary"]

    def test_no_communities_still_renders(self):
        ctx = make_context("snmp", signals=[
            make_signal("snmp_version", "v3", "snmp"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert "SNMP v3" in result["summary"]
        assert "0 community strings" in result["summary"]


class TestBuildVtyEvidence:
    def test_with_transport_and_auth(self):
        ctx = make_context("vty", instance_id="0_4", signals=[
            make_signal("transport_input", "telnet", "vty 0 4"),
            make_signal("transport_input", "ssh", "vty 0 4"),
            make_signal("auth_method", "local", "vty 0 4"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert "VTY line" in result["summary"]
        assert "vty_0_4" in result["summary"]
        assert "transports:" in result["summary"]
        assert "auth:" in result["summary"]

    def test_transport_only(self):
        ctx = make_context("vty", instance_id="0_4", signals=[
            make_signal("transport_input", "telnet", "vty 0 4"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert "telnet" in result["summary"]
        assert "auth:" not in result["summary"]


class TestBuildInterfaceEvidence:
    def test_with_state_and_description(self):
        # context_key uses underscores, not slashes (instance_id is sanitized)
        ctx = make_context(
            "interface",
            instance_id="GigabitEthernet0_0",
            signals=[make_signal("interface_state", "up", "GigabitEthernet0/0")],
            metadata={"state": "up", "description": "Uplink to core"},
        )
        result = EvidenceBuilder().build(ctx)
        assert "GigabitEthernet0_0" in result["summary"]
        assert "up" in result["summary"]
        assert "Uplink to core" in result["summary"]
        assert result["details"] == ["up", "Uplink to core"]

    def test_state_only_no_description(self):
        # Dispatcher triggered by `interface_state` signal type, not metadata
        ctx = make_context(
            "interface",
            instance_id="GigabitEthernet0_0",
            signals=[make_signal("interface_state", "administratively down", "GigabitEthernet0/0")],
            metadata={"state": "administratively down", "description": "missing"},
        )
        result = EvidenceBuilder().build(ctx)
        assert "administratively down" in result["summary"]
        assert "description:" not in result["summary"]
        assert result["details"] == ["administratively down"]


class TestBuildHttpEvidence:
    def test_http_enabled(self):
        ctx = make_context("http", signals=[
            make_signal("http_server", "enabled", "http"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert result["summary"] == "HTTP server: enabled"
        assert result["details"] == ["enabled"]


class TestBuildAaaEvidence:
    def test_aaa_enabled(self):
        ctx = make_context("aaa", signals=[
            make_signal("aaa_enabled", "true", "aaa"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert result["summary"] == "AAA: true"
        assert result["details"] == ["true"]


class TestBuildSyslogEvidence:
    def test_static_message(self):
        ctx = make_context("logging", signals=[
            make_signal("syslog_host", "192.0.2.10", "logging"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert result["summary"] == "Remote syslog configured"
        assert result["details"] == ["logging host configured"]


class TestBuildNtpEvidence:
    def test_static_message(self):
        ctx = make_context("ntp", signals=[
            make_signal("ntp_server", "10.0.0.1", "ntp"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert result["summary"] == "NTP server configured"
        assert result["details"] == ["ntp server configured"]


class TestBuildGenericEvidence:
    def test_unknown_signal_types(self):
        ctx = make_context("weird", signals=[
            make_signal("some_new_type", "value1", "weird"),
            make_signal("another_type", "value2", "weird"),
        ])
        result = EvidenceBuilder().build(ctx)
        assert "weird" in result["summary"]
        assert "2 signals" in result["summary"]
        assert set(result["details"]) == {"some_new_type", "another_type"}


class TestAttachEvidenceSummary:
    def test_attaches_summary_to_finding(self):
        ctx = make_context("snmp", signals=[
            make_signal("snmp_community", "public", "snmp"),
            make_signal("snmp_version", "v2c", "snmp"),
        ])
        finding = make_finding()
        result = EvidenceBuilder().attach_evidence_summary(finding, ctx)
        assert result is finding  # modifies in place AND returns
        assert finding.evidence_summary is not None
        assert "SNMP v2c" in finding.evidence_summary["summary"]

    def test_generic_fallback_when_no_matching_dispatcher(self):
        # Context with only unknown signal types → generic branch
        ctx = make_context("unknown", signals=[
            make_signal("mystery_signal", "x", "unknown"),
        ])
        finding = make_finding()
        EvidenceBuilder().attach_evidence_summary(finding, ctx)
        assert "unknown" in finding.evidence_summary["summary"]
