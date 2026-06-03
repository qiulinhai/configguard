"""Unit tests for the audit service layer."""
import hashlib
from pathlib import Path
import pytest

from configguard.services.audit_service import run_audit, AuditResult
from configguard.risk.engine import RiskEngineResult

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
snmp-server community public RO
!
end
"""

DIRTY_CONFIG = """
snmp-server community public RO
ip http server
end
"""

# Config that contains no blocks (only comments). The parser is tolerant,
# so this parses to an empty IR. The service should still evaluate it
# and produce findings (e.g., CISCO-AUTH-001 fails because no AAA config).
EMPTY_CONFIG = "!\n!\n!\n"


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def test_run_audit_returns_audit_result_for_valid_config(tmp_path):
    cfg = _write(tmp_path, "router.conf", CLEAN_CONFIG)
    result = run_audit(
        config_path=cfg,
        config_name=cfg.name,
        rules_dir=Path("configguard/rules"),
        use_context=True,
    )
    assert isinstance(result, AuditResult)
    assert result.config_name == "router.conf"
    assert result.error is None
    assert len(result.findings) > 0
    assert result.risk_result is not None
    assert isinstance(result.risk_result, RiskEngineResult)


def test_run_audit_computes_correct_sha256_hash(tmp_path):
    cfg = _write(tmp_path, "router.conf", CLEAN_CONFIG)
    expected_hash = hashlib.sha256(CLEAN_CONFIG.encode("utf-8")).hexdigest()
    result = run_audit(
        config_path=cfg,
        config_name=cfg.name,
        rules_dir=Path("configguard/rules"),
        use_context=True,
    )
    assert result.config_hash == expected_hash


def test_run_audit_handles_empty_config(tmp_path):
    """Empty/comment-only configs are still evaluated and produce findings.

    The parser is tolerant: it returns an empty IR rather than raising.
    The service should still run the engine on the empty IR so the caller
    gets findings (e.g., CISCO-AUTH-001 fails because no AAA is configured).
    This preserves the pre-refactor CLI behavior.
    """
    cfg = _write(tmp_path, "empty.conf", EMPTY_CONFIG)
    result = run_audit(
        config_path=cfg,
        config_name=cfg.name,
        rules_dir=Path("configguard/rules"),
        use_context=True,
    )
    assert result.error is None
    assert len(result.findings) > 0
    assert result.risk_result is not None


def test_run_audit_handles_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.conf"
    result = run_audit(
        config_path=missing,
        config_name=missing.name,
        rules_dir=Path("configguard/rules"),
        use_context=True,
    )
    assert result.error is not None
    assert result.findings == []


def test_run_audit_with_use_context_false(tmp_path):
    cfg = _write(tmp_path, "router.conf", DIRTY_CONFIG)
    result = run_audit(
        config_path=cfg,
        config_name=cfg.name,
        rules_dir=Path("configguard/rules"),
        use_context=False,
    )
    # Should not raise; legacy path also produces findings
    assert result.error is None
    assert len(result.findings) > 0
