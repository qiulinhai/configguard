"""End-to-end CLI integration tests for ConfigGuard.

Exercises the full `configguard audit` command via typer.testing.CliRunner
against real rule files and real config fixtures, validating the user-facing
contract: output files, stdout summary, exit codes, and edge cases.
"""
import json
import re
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from configguard.cli import app, main

RULES_DIR = Path(__file__).parent.parent.parent / "configguard" / "rules"

# A config that triggers both CISCO-SNMP-001 (HIGH) and CISCO-MGMT-002 (HIGH)
DIRTY_CONFIG = """
snmp-server community public RO
ip http server
end
"""

# A config that should be clean (no FAIL findings)
CLEAN_CONFIG = """
hostname Branch-Router-01
!
aaa new-model
username netadmin privilege 15 secret 0 ChangeMe123!
!
line vty 0 4
 transport input ssh
 login local
!
logging host 192.0.2.10
ntp server 10.0.0.1
!
end
"""

REPORT_NAME_PATTERN = re.compile(r"^\d{8}_\d{6}_.+\.report\.(json|md)$")


def _write_config(tmp_path: Path, name: str = "config.txt", content: str = DIRTY_CONFIG) -> Path:
    cfg = tmp_path / name
    cfg.write_text(content)
    return cfg


# ---------- Format gating ----------

class TestFormatGating:
    def test_format_all_writes_both_reports(self, tmp_path):
        cfg = _write_config(tmp_path)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--output-dir", str(tmp_path / "out")])
        assert result.exit_code == 0
        files = sorted((tmp_path / "out").iterdir())
        names = {f.name for f in files}
        json_files = [n for n in names if n.endswith(".report.json")]
        md_files = [n for n in names if n.endswith(".report.md")]
        assert len(json_files) == 1, f"expected 1 JSON, got {json_files}"
        assert len(md_files) == 1, f"expected 1 MD, got {md_files}"

    def test_format_json_writes_only_json(self, tmp_path):
        cfg = _write_config(tmp_path)
        result = CliRunner().invoke(app, [
            "audit", str(cfg), "--output-dir", str(tmp_path / "out"), "--format", "json"
        ])
        assert result.exit_code == 0
        names = {f.name for f in (tmp_path / "out").iterdir()}
        assert any(n.endswith(".report.json") for n in names)
        assert not any(n.endswith(".report.md") for n in names)
        assert "JSON report:" in result.output
        assert "Markdown report:" not in result.output

    def test_format_markdown_writes_only_markdown(self, tmp_path):
        cfg = _write_config(tmp_path)
        result = CliRunner().invoke(app, [
            "audit", str(cfg), "--output-dir", str(tmp_path / "out"), "--format", "markdown"
        ])
        assert result.exit_code == 0
        names = {f.name for f in (tmp_path / "out").iterdir()}
        assert any(n.endswith(".report.md") for n in names)
        assert not any(n.endswith(".report.json") for n in names)
        assert "Markdown report:" in result.output
        assert "JSON report:" not in result.output

    def test_output_filename_pattern(self, tmp_path):
        cfg = _write_config(tmp_path, name="my-router.conf")
        CliRunner().invoke(app, ["audit", str(cfg), "--output-dir", str(tmp_path / "out")])
        names = [f.name for f in (tmp_path / "out").iterdir()]
        for n in names:
            assert REPORT_NAME_PATTERN.match(n), f"unexpected filename: {n}"
            assert "my-router" in n, f"config basename missing from: {n}"


# ---------- Output dir handling ----------

class TestOutputDir:
    def test_nested_nonexistent_dir_is_created(self, tmp_path):
        cfg = _write_config(tmp_path)
        nested = tmp_path / "a" / "b" / "c" / "reports"
        assert not nested.exists()
        result = CliRunner().invoke(app, ["audit", str(cfg), "--output-dir", str(nested)])
        assert result.exit_code == 0
        assert nested.is_dir()
        assert any(nested.iterdir())


# ---------- Rules dir handling ----------

class TestRulesDir:
    def test_empty_rules_dir_falls_back_without_crash(self, tmp_path):
        cfg = _write_config(tmp_path)
        empty_rules = tmp_path / "empty_rules"
        empty_rules.mkdir()
        result = CliRunner().invoke(app, ["audit", str(cfg), "--rules-dir", str(empty_rules)])
        # No crash; should still produce reports (with no findings)
        assert result.exit_code == 0
        assert "Total: 0 findings" in result.output

    def test_custom_rules_dir_with_minimal_rule(self, tmp_path):
        cfg = _write_config(tmp_path, content=CLEAN_CONFIG)
        custom_rules = tmp_path / "custom_rules"
        custom_rules.mkdir()
        (custom_rules / "test_rule.yaml").write_text(
            "id: TEST-CUSTOM-001\n"
            "name: Always Fail\n"
            "category: test\n"
            "severity: HIGH\n"
            "match:\n"
            "  type: regex\n"
            "  pattern: 'aaa new-model'\n"
            "condition: present\n"
            "finding:\n"
            "  status: FAIL\n"
            "  evidence: true\n"
        )
        result = CliRunner().invoke(app, ["audit", str(cfg), "--rules-dir", str(custom_rules)])
        assert result.exit_code == 0
        assert "TEST-CUSTOM-001" in result.output


# ---------- --fail-on matrix ----------

class TestFailOn:
    def test_fail_on_none_never_exits_nonzero(self, tmp_path):
        cfg = _write_config(tmp_path)  # dirty
        result = CliRunner().invoke(app, ["audit", str(cfg), "--fail-on", "none"])
        assert result.exit_code == 0

    def test_fail_on_high_with_high_finding_exits_1(self, tmp_path):
        cfg = _write_config(tmp_path)  # HIGH findings
        result = CliRunner().invoke(app, ["audit", str(cfg), "--fail-on", "high"])
        assert result.exit_code == 1

    def test_fail_on_medium_with_high_finding_exits_1(self, tmp_path):
        cfg = _write_config(tmp_path)  # HIGH (>= MEDIUM)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--fail-on", "medium"])
        assert result.exit_code == 1

    def test_fail_on_low_with_high_finding_exits_1(self, tmp_path):
        cfg = _write_config(tmp_path)  # HIGH (>= LOW)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--fail-on", "low"])
        assert result.exit_code == 1

    def test_fail_on_high_with_clean_config_exits_0(self, tmp_path):
        cfg = _write_config(tmp_path, content=CLEAN_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--fail-on", "high"])
        assert result.exit_code == 0

    def test_fail_on_bogus_exits_2(self, tmp_path):
        cfg = _write_config(tmp_path)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--fail-on", "bogus"])
        assert result.exit_code == 2
        assert "Error" in result.output or "must be one of" in result.output


# ---------- Edge cases ----------

class TestEdgeCases:
    def test_empty_config_file_runs_and_writes_report(self, tmp_path):
        # Empty config has no AAA → CISCO-AUTH-001 will fail. That's correct
        # behavior, not a crash. We just want a report written and no traceback.
        cfg = tmp_path / "empty.txt"
        cfg.write_text("")
        result = CliRunner().invoke(app, ["audit", str(cfg), "--output-dir", str(tmp_path / "out")])
        assert result.exit_code == 0
        assert "Total:" in result.output  # at least one finding expected
        assert any((tmp_path / "out").iterdir())

    def test_hostname_only_config_runs_and_writes_report(self, tmp_path):
        # hostname-only config has no AAA → CISCO-AUTH-001 will fail.
        cfg = tmp_path / "minimal.txt"
        cfg.write_text("hostname Router1\n!\nend\n")
        result = CliRunner().invoke(app, ["audit", str(cfg), "--output-dir", str(tmp_path / "out")])
        assert result.exit_code == 0
        assert "Total:" in result.output
        assert any((tmp_path / "out").iterdir())

    def test_truly_clean_config_has_zero_findings(self, tmp_path):
        # CLEAN_CONFIG has AAA + SSH + syslog + NTP → all checks pass
        cfg = _write_config(tmp_path, content=CLEAN_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--output-dir", str(tmp_path / "out")])
        assert result.exit_code == 0
        assert "Total: 0 findings" in result.output

    def test_nonexistent_file_exits_1_with_error(self, tmp_path):
        missing = tmp_path / "does_not_exist.txt"
        result = CliRunner().invoke(app, ["audit", str(missing)])
        assert result.exit_code == 1
        # Error message on stderr
        assert "not found" in (result.stderr or "").lower() or "not found" in result.output.lower()

    def test_weird_inputs_never_raise_traceback(self, tmp_path):
        """Parser is tolerant; no input should produce a Python traceback in stderr.

        The Cisco IOS parser gracefully handles garbage input. This test guards
        that contract — if a future change makes the parser strict, the user
        should get a clean error, not a stack trace.
        """
        weird_inputs = [
            "interface bogus {{{{\n",  # unmatched braces
            "asdf qwer zxcv\n",         # random tokens
            "line vty\n",                # incomplete line block
            "!\n!\n!\n",                 # only comments
            " \t \n",                    # whitespace only
        ]
        for content in weird_inputs:
            cfg = tmp_path / "weird.txt"
            cfg.write_text(content)
            result = CliRunner().invoke(app, ["audit", str(cfg)])
            assert "Traceback" not in (result.stderr or ""), (
                f"Input {content!r} produced a Python traceback:\n{result.stderr}"
            )


# ---------- Flag toggles ----------

class TestFlagToggles:
    def test_use_context_default_runs(self, tmp_path):
        cfg = _write_config(tmp_path, content=CLEAN_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--output-dir", str(tmp_path / "out")])
        assert result.exit_code == 0

    def test_no_use_context_runs_legacy_path(self, tmp_path):
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--no-use-context", "--output-dir", str(tmp_path / "out")])
        # Legacy path may not detect context-based rules; should still not crash
        assert result.exit_code == 0

    def test_debug_contexts_writes_json_block(self, tmp_path):
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--debug-contexts"])
        assert result.exit_code == 0
        assert "DEBUG: SignalContexts" in result.output
        assert "END DEBUG" in result.output
        # Extract the JSON block and parse it
        match = re.search(r"--- DEBUG: SignalContexts ---\n(.*?)\n--- END DEBUG ---", result.output, re.DOTALL)
        assert match, "debug JSON block not found"
        block = json.loads(match.group(1))
        assert "contexts" in block
        assert "count" in block
        assert block["count"] == len(block["contexts"])

    def test_risk_score_adds_risk_assessment_block(self, tmp_path):
        """Compliance Assessment block appears in output (was: --risk-score opt-in, now always-on)."""
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--risk-score"])
        assert result.exit_code == 0
        assert "=== Compliance Assessment ===" in result.output
        assert "Compliance Score:" in result.output
        assert "/100" in result.output

    def test_compliance_assessment_shown_by_default(self, tmp_path):
        """Compliance block is now default (v0.2: promoted from --risk-score opt-in)."""
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg)])
        assert result.exit_code == 0
        assert "=== Compliance Assessment ===" in result.output
        assert "Overall Status:" in result.output
        assert "Compliance Score:" in result.output

    def test_compliance_status_non_compliant_when_failures(self, tmp_path):
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg)])
        assert "Overall Status: NON-COMPLIANT" in result.output

    def test_compliance_status_compliant_when_clean(self, tmp_path):
        cfg = _write_config(tmp_path, content=CLEAN_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg)])
        assert "Overall Status: COMPLIANT" in result.output

    def test_compliance_block_lists_risk_areas(self, tmp_path):
        """Risk Areas section derived from category breakdown, sorted by impact."""
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg)])
        assert "Risk Areas:" in result.output
        # DIRTY_CONFIG triggers snmp-security and management-plane; both should appear
        assert "snmp-security" in result.output
        assert "management-plane" in result.output

    def test_risk_score_with_no_fail_on_still_exits_0(self, tmp_path):
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--risk-score", "--fail-on", "none"])
        assert result.exit_code == 0

    def test_explain_flag_does_not_crash(self, tmp_path):
        """--explain is a no-op (LLM hook not wired in v0.1); should not crash."""
        cfg = _write_config(tmp_path)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--explain", "--output-dir", str(tmp_path / "out")])
        assert result.exit_code == 0
        # Reports should still be produced
        assert any((tmp_path / "out").iterdir())


# ---------- Output content ----------

class TestOutputContent:
    def test_json_report_has_expected_schema(self, tmp_path):
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        CliRunner().invoke(app, ["audit", str(cfg), "--format", "json", "--output-dir", str(tmp_path / "out")])
        json_files = [f for f in (tmp_path / "out").iterdir() if f.name.endswith(".report.json")]
        assert len(json_files) == 1
        report = json.loads(json_files[0].read_text())
        # Top-level keys
        assert "version" in report
        assert "summary" in report
        assert "findings" in report
        assert "metadata" in report
        # Summary keys
        assert "total" in report["summary"]
        assert "pass" in report["summary"]
        assert "fail" in report["summary"]
        # Each finding has the expected shape
        assert len(report["findings"]) > 0
        for finding in report["findings"]:
            assert "rule_id" in finding
            assert "severity" in finding
            assert "status" in finding
            assert "evidence" in finding

    def test_markdown_report_has_expected_sections(self, tmp_path):
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        CliRunner().invoke(app, ["audit", str(cfg), "--format", "markdown", "--output-dir", str(tmp_path / "out")])
        md_files = [f for f in (tmp_path / "out").iterdir() if f.name.endswith(".report.md")]
        assert len(md_files) == 1
        content = md_files[0].read_text()
        assert "## Summary" in content
        assert "## Failed Findings" in content
        # Should reference at least one of the known dirty findings
        assert "CISCO-SNMP-001" in content or "CISCO-MGMT-002" in content

    def test_stdout_summary_lists_findings(self, tmp_path):
        cfg = _write_config(tmp_path, content=DIRTY_CONFIG)
        result = CliRunner().invoke(app, ["audit", str(cfg), "--output-dir", str(tmp_path / "out")])
        assert "Audit Summary" in result.output
        assert "CISCO-SNMP-001" in result.output or "CISCO-MGMT-002" in result.output
        assert "Total:" in result.output
        assert "failed" in result.output


# ---------- main() entry shim ----------

class TestMainShim:
    def test_main_strips_audit_subcommand(self, tmp_path, monkeypatch):
        """main() is the console_scripts entry; it must accept `configguard audit ...` form."""
        cfg = _write_config(tmp_path, content=CLEAN_CONFIG)
        # Simulate `configguard audit <cfg> --output-dir <dir>`
        monkeypatch.setattr(sys, "argv", ["configguard", "audit", str(cfg), "--output-dir", str(tmp_path / "out")])
        # main() calls sys.exit() via typer's standalone_mode; catch it.
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        assert any((tmp_path / "out").iterdir())

    def test_main_works_without_audit_subcommand(self, tmp_path, monkeypatch):
        """main() also accepts direct invocation (no `audit` prefix)."""
        cfg = _write_config(tmp_path, content=CLEAN_CONFIG)
        monkeypatch.setattr(sys, "argv", ["configguard", str(cfg), "--output-dir", str(tmp_path / "out")])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        assert any((tmp_path / "out").iterdir())
