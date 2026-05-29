"""Tests for ConfigGuard CLI."""
import pytest
from typer.testing import CliRunner
from configguard.cli import app

def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(app, ["audit", "--help"])
    assert result.exit_code == 0
    assert "configguard audit" in result.output or "Audit a network" in result.output

def test_cli_basic_audit(tmp_path):
    runner = CliRunner()
    config_file = tmp_path / "config.txt"
    config_file.write_text("line vty 0 4\n transport input telnet ssh\n")

    result = runner.invoke(app, [str(config_file)])
    assert result.exit_code == 0
    assert "FAIL" in result.output or "telnet" in result.output.lower()

def test_cli_with_signal_extraction(tmp_path):
    """Test CLI works when signal extraction is available."""
    runner = CliRunner()
    config_file = tmp_path / "config.txt"
    config_file.write_text("line vty 0 4\n transport input telnet ssh\n")

    result = runner.invoke(app, [str(config_file)])
    assert result.exit_code == 0
    assert "FAIL" in result.output or "PASS" in result.output
    # Verify signal extraction info not leaked to user (internal)
    assert "Signal" not in result.output

def test_cli_dual_path_evaluation(tmp_path):
    """Test CLI uses both legacy and context evaluation."""
    from configguard.cli import app
    from typer.testing import CliRunner

    runner = CliRunner()
    config_file = tmp_path / "config.txt"
    config_file.write_text("""
    hostname Router1
    !
    snmp-server community public RO
    snmp-server community private RW
    !
    line vty 0 4
     transport input telnet
    !
    end
    """)

    result = runner.invoke(app, [str(config_file)])
    assert result.exit_code == 0
    # Should detect telnet and SNMP
    assert "CISCO-MGMT-001" in result.output or "telnet" in result.output
    assert "CISCO-SNMP-001" in result.output or "snmp" in result.output