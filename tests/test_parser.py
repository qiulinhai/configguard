"""Tests for ConfigGuard parser."""
import pytest
from configguard.parser import CiscoIOSParser

SAMPLE_CONFIG = """
hostname Router1
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
line vty 0 4
 transport input telnet ssh
 login local
!
end
"""

def test_parser_extracts_blocks():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    result = parser.parse()
    assert len(result.blocks) == 2
    assert result.blocks[0].type == "interface"
    assert result.blocks[0].name == "GigabitEthernet0/0"
    assert result.blocks[1].type == "line"
    assert result.blocks[1].name == "vty 0 4"

def test_parser_raw_lines_preserved():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    result = parser.parse()
    assert "hostname Router1" in result.raw_lines
    assert "transport input telnet ssh" in result.raw_lines

def test_parser_normalizes_services():
    parser = CiscoIOSParser(SAMPLE_CONFIG)
    result = parser.parse()
    assert result.normalized["services"]["telnet"]["status"] == "enabled"
    assert result.normalized["services"]["ssh"]["status"] == "enabled"