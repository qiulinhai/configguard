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