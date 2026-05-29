"""Tests for ConfigGuard signal layer."""
import pytest
from configguard.models import Signal

def test_signal_creation():
    signal = Signal(
        type="transport_input",
        value="telnet",
        context="vty 0 4",
        block_type="line",
        raw="transport input telnet ssh",
    )
    assert signal.type == "transport_input"
    assert signal.value == "telnet"
    assert signal.context == "vty 0 4"

def test_signal_severity_hint_optional():
    signal = Signal(
        type="transport_input",
        value="telnet",
        context="vty 0 4",
        block_type="line",
        raw="transport input telnet",
        severity_hint="high",
    )
    assert signal.severity_hint == "high"

def test_signal_hash():
    """Signals with same type and context should have same hash for deduplication."""
    sig1 = Signal(type="transport_input", value="telnet", context="vty 0 4", block_type="line", raw="cmd1")
    sig2 = Signal(type="transport_input", value="telnet", context="vty 0 4", block_type="line", raw="cmd2")
    assert hash(sig1) == hash(sig2)

from configguard.signals import SignalExtractor
from configguard.parser import CiscoIOSParser

SAMPLE_CONFIG = """
hostname Router1
!
line vty 0 4
 transport input telnet ssh
 login local
!
interface GigabitEthernet0/0
 no shutdown
!
end
"""

def test_extractor_extracts_transport_signal():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    ir = parser.parse()
    extractor = SignalExtractor()
    sigs = extractor.extract(ir)

    transport_sigs = [s for s in sigs if s.type == "transport_input"]
    assert len(transport_sigs) >= 1
    telnet_sigs = [s for s in transport_sigs if s.value == "telnet"]
    assert len(telnet_sigs) == 1
    assert telnet_sigs[0].context == "vty 0 4"

def test_extractor_extracts_interface_signal():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    ir = parser.parse()
    extractor = SignalExtractor()
    sigs = extractor.extract(ir)

    iface_sigs = [s for s in sigs if s.type == "interface_state"]
    assert len(iface_sigs) == 1
    assert iface_sigs[0].value == "up"
    assert "GigabitEthernet" in iface_sigs[0].context

def test_extractor_deduplicates_by_type_context():
    """Same (type, context) should only produce one signal."""
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    ir = parser.parse()
    extractor = SignalExtractor()
    sigs = extractor.extract(ir)

    # Check deduplication: no duplicate (type, context) pairs
    seen_keys = set()
    for sig in sigs:
        key = (sig.type, sig.context)
        assert key not in seen_keys, f"Duplicate signal: {key}"
        seen_keys.add(key)