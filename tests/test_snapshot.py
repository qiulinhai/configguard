"""Unit tests for the Snapshot dataclass and JSON I/O."""
import json
import pytest
from configguard.snapshot import (
    Snapshot,
    DeviceSnapshot,
    FleetSummary,
    SnapshotValidationError,
)
from configguard.models import Finding, Severity, FindingStatus


def _sample_finding():
    return Finding(
        rule_id="CISCO-MGMT-002",
        rule_name="Disable HTTP Server",
        category="management-plane",
        severity=Severity.HIGH,
        status=FindingStatus.FAIL,
        evidence="HTTP server: enabled",
    )


def _sample_device(name="edge2", status="NON-COMPLIANT", level="CRITICAL"):
    return DeviceSnapshot(
        device_name=name,
        config_path=f"configs/{name}.conf",
        config_hash="7d865e959b2466918c9863afca942d0fb89d2c9f9b0a1e2c5d3b8e4a7f1c0d2e",
        status=status,
        level=level,
        severity_breakdown={"HIGH": 2, "MEDIUM": 1, "LOW": 0},
        findings=[_sample_finding()],
        error=None,
    )


def _sample_summary():
    return FleetSummary(
        device_count=1,
        compliant=0,
        non_compliant=1,
        errored=0,
        findings_total=1,
        findings_failed=1,
        findings_passed=0,
        high_risk_device_count=1,
    )


def test_snapshot_round_trip():
    snap = Snapshot(
        snapshot_version=1,
        generator={"configguard_version": "0.5.0", "python_version": "3.12.4"},
        generated_at="2026-06-02T14:30:22Z",
        source={"config_dir": "./configs", "rules_dir": "./configguard/rules"},
        summary=_sample_summary(),
        devices=[_sample_device()],
    )
    data = snap.to_dict()
    restored = Snapshot.from_dict(data)
    assert restored.snapshot_version == 1
    assert restored.devices[0].device_name == "edge2"
    assert restored.summary.device_count == 1


def test_snapshot_to_dict_has_v1_contract_shape():
    snap = Snapshot(
        snapshot_version=1,
        generator={"configguard_version": "0.5.0", "python_version": "3.12.4"},
        generated_at="2026-06-02T14:30:22Z",
        source={"config_dir": "./configs", "rules_dir": "./configguard/rules"},
        summary=_sample_summary(),
        devices=[],
    )
    data = snap.to_dict()
    assert data["snapshot_version"] == 1
    assert "generator" in data
    assert data["generator"]["configguard_version"] == "0.5.0"
    assert "generated_at" in data
    assert "source" in data
    assert "summary" in data
    assert "devices" in data


def test_snapshot_from_dict_rejects_missing_required_field():
    with pytest.raises(SnapshotValidationError) as exc:
        Snapshot.from_dict({
            "snapshot_version": 1,
            "generator": {"configguard_version": "0.5.0", "python_version": "3.12.4"},
            # missing "generated_at"
            "source": {"config_dir": "./configs", "rules_dir": "./configguard/rules"},
            "summary": _sample_summary().to_dict(),
            "devices": [],
        })
    assert "generated_at" in str(exc.value)


def test_snapshot_from_dict_ignores_unknown_fields():
    """Forward compat: extra fields must not break loading."""
    data = {
        "snapshot_version": 1,
        "generator": {"configguard_version": "0.5.0", "python_version": "3.12.4"},
        "generated_at": "2026-06-02T14:30:22Z",
        "source": {"config_dir": "./configs", "rules_dir": "./configguard/rules"},
        "summary": _sample_summary().to_dict(),
        "devices": [_sample_device().to_dict()],
        "future_field_added_in_v2": "should be ignored",
    }
    snap = Snapshot.from_dict(data)
    assert snap.snapshot_version == 1
    assert len(snap.devices) == 1


def test_device_snapshot_status_validation():
    with pytest.raises(SnapshotValidationError) as exc:
        DeviceSnapshot(
            device_name="edge2",
            config_path="configs/edge2.conf",
            config_hash="abc",
            status="WAT",  # invalid
            level="CRITICAL",
            severity_breakdown={"HIGH": 1, "MEDIUM": 0, "LOW": 0},
            findings=[],
            error=None,
        )
    assert "status" in str(exc.value).lower()


def test_summary_derives_from_devices():
    devices = [
        _sample_device("a", "COMPLIANT", "LOW"),
        _sample_device("b", "NON-COMPLIANT", "HIGH"),
        _sample_device("c", "ERROR", "LOW"),
    ]
    summary = FleetSummary.from_devices(devices)
    assert summary.device_count == 3
    assert summary.compliant == 1
    assert summary.non_compliant == 1
    assert summary.errored == 1
    assert summary.findings_total == 3  # one finding per non-error device
    assert summary.findings_failed == 3
    assert summary.high_risk_device_count == 1  # only "b" is HIGH/CRITICAL
