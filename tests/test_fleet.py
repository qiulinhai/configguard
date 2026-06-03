"""Unit tests for the fleet module."""
from pathlib import Path
import pytest
from configguard.fleet import discover_configs
from configguard.services.audit_service import AuditResult


def _make_audit_result(tmp_path, content, error=None):
    """Helper: write a config and return a real AuditResult from run_audit().

    Reuses audit_service.run_audit() so the test exercises the same
    pipeline the CLI uses — no pipeline re-implementation here.
    """
    from configguard.services.audit_service import run_audit

    cfg = tmp_path / "router.conf"
    cfg.write_text(content)
    if error:
        return AuditResult(
            config_name="router.conf",
            config_path=str(cfg),
            config_hash="",
            error=error,
        )
    return run_audit(
        config_path=cfg,
        config_name=cfg.name,
        rules_dir=Path("configguard/rules"),
    )


def test_discover_finds_matching_files_in_dir(tmp_path):
    (tmp_path / "a.conf").write_text("hostname a\nend\n")
    (tmp_path / "b.conf").write_text("hostname b\nend\n")
    (tmp_path / "c.txt").write_text("hostname c\nend\n")
    (tmp_path / "README.md").write_text("not a config")

    found = discover_configs(tmp_path, includes=["*.conf", "*.txt"])
    names = [p.name for p in found]
    assert names == ["a.conf", "b.conf", "c.txt"]


def test_discover_returns_alphabetically_sorted(tmp_path):
    (tmp_path / "z.conf").write_text("x")
    (tmp_path / "a.conf").write_text("x")
    (tmp_path / "m.conf").write_text("x")
    found = discover_configs(tmp_path, includes=["*.conf"])
    assert [p.name for p in found] == ["a.conf", "m.conf", "z.conf"]


def test_discover_ignores_subdirectories(tmp_path):
    (tmp_path / "a.conf").write_text("x")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.conf").write_text("x")
    found = discover_configs(tmp_path, includes=["*.conf"])
    assert [p.name for p in found] == ["a.conf"]


def test_discover_skips_dotfiles_and_symlinks(tmp_path):
    (tmp_path / "a.conf").write_text("x")
    (tmp_path / ".hidden.conf").write_text("x")
    (tmp_path / "regular.txt").write_text("x")
    # Symlink (skip the test if filesystem doesn't support symlinks)
    target = tmp_path / "a.conf"
    link = tmp_path / "link.conf"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported on this filesystem")

    found = discover_configs(tmp_path, includes=["*.conf", "*.txt"])
    names = [p.name for p in found]
    assert ".hidden.conf" not in names
    assert "link.conf" not in names  # symlink skipped
    assert "a.conf" in names
    assert "regular.txt" in names


def test_discover_with_no_matches_raises(tmp_path):
    (tmp_path / "README.md").write_text("not a config")
    with pytest.raises(FileNotFoundError) as exc:
        discover_configs(tmp_path, includes=["*.conf", "*.txt"])
    assert "no config files found" in str(exc.value).lower()


def test_discover_with_nonexistent_dir_raises(tmp_path):
    missing = tmp_path / "does_not_exist"
    with pytest.raises(FileNotFoundError) as exc:
        discover_configs(missing, includes=["*.conf"])
    assert "not found" in str(exc.value).lower() or "no such file" in str(exc.value).lower()


def test_discover_with_path_pointing_to_file_raises(tmp_path):
    file_path = tmp_path / "router.conf"
    file_path.write_text("x")
    with pytest.raises(NotADirectoryError):
        discover_configs(file_path, includes=["*.conf"])


# ---- device_snapshot_from_audit (Task 5) ----

from configguard.fleet import device_snapshot_from_audit


def test_device_snapshot_from_audit_non_compliant(tmp_path):
    content = "snmp-server community public RO\nip http server\nend\n"
    ar = _make_audit_result(tmp_path, content)
    ds = device_snapshot_from_audit(ar, config_dir=tmp_path)
    assert ds.device_name == "router"
    assert ds.status == "NON-COMPLIANT"
    assert ds.level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert ds.error is None
    assert len(ds.findings) > 0
    assert sum(ds.severity_breakdown.values()) == len(ds.findings)


def test_device_snapshot_from_audit_error(tmp_path):
    ar = AuditResult(
        config_name="bad.conf",
        config_path=str(tmp_path / "bad.conf"),
        config_hash="",
        error="Failed to parse: bad syntax",
    )
    ds = device_snapshot_from_audit(ar, config_dir=tmp_path)
    assert ds.status == "ERROR"
    assert ds.error is not None
    assert ds.findings == []
    assert ds.severity_breakdown == {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    assert ds.level == "LOW"  # default fill; UI should check status first


def test_device_snapshot_from_audit_compliant(tmp_path):
    content = """
hostname R1
!
aaa new-model
username admin privilege 15 secret 0 ChangeMe123!
line vty 0 4
 transport input ssh
 login local
!
logging host 192.0.2.10
ntp server 10.0.0.1
end
"""
    ar = _make_audit_result(tmp_path, content)
    ds = device_snapshot_from_audit(ar, config_dir=tmp_path)
    assert ds.status == "COMPLIANT"
    # No FAIL findings is the contract for COMPLIANT. (The current rule set
    # only emits findings on FAIL conditions, so a fully clean config
    # legitimately produces zero findings. "Rules ran" is implicitly
    # covered — an errored audit would yield status=ERROR, not COMPLIANT.)
    assert sum(1 for f in ds.findings if f.status.value == "FAIL") == 0


def test_device_snapshot_config_path_is_relative_to_config_dir(tmp_path):
    sub = tmp_path / "site-a"
    sub.mkdir()
    cfg = sub / "edge1.conf"
    cfg.write_text("hostname E1\nend\n")
    ar = AuditResult(
        config_name=cfg.name,
        config_path=str(cfg),
        config_hash="abc",
        findings=[],
    )
    ds = device_snapshot_from_audit(ar, config_dir=tmp_path)
    # Path is relative to the parent config_dir. The audit_service writes
    # the absolute path back, so device_snapshot_from_audit must relativize.
    assert "edge1" in ds.config_path
    assert Path(ds.config_path).is_absolute() is False

