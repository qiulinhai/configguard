"""End-to-end CLI integration tests for `configguard fleet audit`."""
import json
import os
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from configguard.cli import app

CLEAN = """
hostname Branch-Router-01
!
aaa new-model
username netadmin privilege 15 secret 0 ChangeMe123!
line vty 0 4
 transport input ssh
 login local
!
logging host 192.0.2.10
ntp server 10.0.0.1
end
"""

DIRTY = """
snmp-server community public RO
ip http server
end
"""


def _populate(cfg_dir: Path, n_clean: int = 2, n_dirty: int = 1):
    for i in range(n_clean):
        (cfg_dir / f"core{i+1}.conf").write_text(CLEAN)
    for i in range(n_dirty):
        (cfg_dir / f"edge{i+1}.conf").write_text(DIRTY)


# ---------- Happy path ----------

class TestFleetAuditHappyPath:
    def test_writes_snapshot_and_per_device_reports(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir, n_clean=2, n_dirty=1)
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert result.exit_code == 0
        out = tmp_path / "out"
        assert (out / "fleet.snapshot.json").is_file()
        assert (out / "devices").is_dir()
        assert len(list((out / "devices").iterdir())) == 3

    def test_snapshot_is_valid_v1(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir, n_clean=2, n_dirty=0)
        CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
        ])
        snap = json.loads((tmp_path / "out" / "fleet.snapshot.json").read_text())
        assert snap["snapshot_version"] == 1
        assert "generator" in snap
        assert "configguard_version" in snap["generator"]
        assert "summary" in snap
        assert "devices" in snap
        assert len(snap["devices"]) == 2  # n_clean=2

    def test_summary_counts_match_devices(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir, n_clean=2, n_dirty=1)
        CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
        ])
        snap = json.loads((tmp_path / "out" / "fleet.snapshot.json").read_text())
        s = snap["summary"]
        assert s["device_count"] == 3
        assert s["compliant"] == 2
        assert s["non_compliant"] == 1
        assert s["errored"] == 0

    def test_per_device_report_has_v01_compliance_block(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir, n_dirty=1)
        CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
        ])
        report = json.loads((tmp_path / "out" / "devices" / "edge1.report.json").read_text())
        assert "compliance" in report
        assert report["compliance"]["status"] == "NON-COMPLIANT"


# ---------- Error handling ----------

class TestFleetAuditErrorHandling:
    def test_no_matching_files_exits_1(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        (cfg_dir / "README.md").write_text("not a config")
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert result.exit_code == 1
        output_and_err = (result.output + " " + (result.stderr or "")).lower()
        assert "no config files" in output_and_err

    def test_nonexistent_dir_exits_1(self, tmp_path):
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(tmp_path / "does_not_exist"),
        ])
        assert result.exit_code == 1

    def test_path_pointing_to_file_exits_1(self, tmp_path):
        file_path = tmp_path / "router.conf"
        file_path.write_text("hostname R1\nend\n")
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(file_path),
        ])
        assert result.exit_code == 1

    def test_unreadable_file_creates_error_device_snapshot(self, tmp_path):
        """A file the audit can't read surfaces as a per-device ERROR, not a fleet failure.

        The parser is tolerant of arbitrary input — it doesn't raise on garbage
        configs, so a syntactically-broken file would parse to an empty IR and
        produce FAIL findings. The reliable ERROR trigger is a read failure
        (chmod 000). Skip when running as root since permission denial is
        bypassed.
        """
        if os.geteuid() == 0:
            pytest.skip("chmod-based permission denial has no effect when running as root")
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        (cfg_dir / "good.conf").write_text(CLEAN)
        bad = cfg_dir / "bad.conf"
        bad.write_text("hostname bad\nend\n")
        os.chmod(bad, 0o000)
        try:
            result = CliRunner().invoke(app, [
                "fleet", "audit", str(cfg_dir),
                "--output-dir", str(tmp_path / "out"),
            ])
        finally:
            os.chmod(bad, 0o644)
        # Per-device ERROR doesn't fail the whole fleet
        assert result.exit_code == 0
        snap = json.loads((tmp_path / "out" / "fleet.snapshot.json").read_text())
        statuses = {d["device_name"]: d["status"] for d in snap["devices"]}
        assert statuses["good"] == "COMPLIANT"
        assert statuses["bad"] == "ERROR"
        assert snap["summary"]["errored"] == 1


# ---------- --fail-on ----------

class TestFleetAuditFailOn:
    def test_fail_on_none_always_exits_0(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir, n_dirty=1)
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--fail-on", "none",
        ])
        assert result.exit_code == 0

    def test_fail_on_high_with_high_finding_exits_1(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir, n_dirty=1)  # dirty has HIGH findings
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--fail-on", "high",
        ])
        assert result.exit_code == 1

    def test_fail_on_bogus_exits_2(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir)
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--fail-on", "bogus",
        ])
        assert result.exit_code == 2

    def test_fail_on_only_triggers_once_for_whole_fleet(self, tmp_path):
        """Even if 5 devices have HIGH findings, exit 1 (not 1+1+1+1+1)."""
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir, n_dirty=5)  # 5 dirty devices
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--fail-on", "high",
        ])
        assert result.exit_code == 1
        # Snapshot was still written before the exit
        # (write_fleet_outputs runs before the gate; the gate just exits)


# ---------- --quiet and --snapshot-name ----------

class TestFleetAuditFlags:
    def test_quiet_suppresses_per_device_progress(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir)
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
            "--quiet",
        ])
        assert "Auditing" not in result.output  # progress suppressed
        assert "Fleet Compliance Assessment" in result.output  # assessment still printed

    def test_snapshot_name_creates_named_file(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir)
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
            "--snapshot-name", "20260602_prod",
        ])
        assert result.exit_code == 0
        assert (tmp_path / "out" / "20260602_prod.snapshot.json").is_file()
        # Default name is NOT created
        assert not (tmp_path / "out" / "fleet.snapshot.json").exists()

    def test_include_filters_files(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        (cfg_dir / "router.conf").write_text(CLEAN)
        (cfg_dir / "notes.txt").write_text("not a config, just notes")
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
            "--include", "*.conf",
        ])
        assert result.exit_code == 0
        snap = json.loads((tmp_path / "out" / "fleet.snapshot.json").read_text())
        assert len(snap["devices"]) == 1
        assert snap["devices"][0]["device_name"] == "router"


# ---------- Stdout content ----------

class TestFleetAuditStdout:
    def test_assessment_block_appears(self, tmp_path):
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir, n_clean=1, n_dirty=1)
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert "=== Fleet Compliance Assessment ===" in result.output
        assert "Fleet Status:" in result.output
        assert "Devices:" in result.output
        assert "Findings:" in result.output
        assert "High-risk devices:" in result.output

    def test_no_fleet_score_in_stdout(self, tmp_path):
        """Per spec §3.4: Phase 1 has no numeric fleet score."""
        cfg_dir = tmp_path / "configs"
        cfg_dir.mkdir()
        _populate(cfg_dir)
        result = CliRunner().invoke(app, [
            "fleet", "audit", str(cfg_dir),
            "--output-dir", str(tmp_path / "out"),
        ])
        # Fleet Score: is NOT printed
        assert "Fleet Score:" not in result.output
        # Status and counts ARE printed
        assert "Fleet Status:" in result.output
