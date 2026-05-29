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