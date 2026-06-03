"""Fleet orchestrator: discover configs, audit each, build a Snapshot.

`configguard fleet audit <dir>` is a thin wrapper over `audit_service.run()`
that produces a self-contained `Snapshot` plus per-device JSON reports.

Architecture (per spec §3.1):
  cli.py  →  fleet.py  →  services/audit_service.py  →  engine
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from configguard.services.audit_service import AuditResult, run_audit
from configguard.snapshot import (
    DeviceSnapshot,
    Snapshot,
    FleetSummary,
    VALID_LEVELS,
    make_generator_metadata,
    now_iso_utc,
)

# Default globs matched in addition to user-supplied --include values.
DEFAULT_INCLUDES = ("*.conf", "*.txt", "*.cfg")

# Empty severity breakdown used as the zeroed default in the ERROR path.
EMPTY_BREAKDOWN = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}


def discover_configs(
    config_dir: Path,
    includes: Optional[list[str]] = None,
) -> list[Path]:
    """One-level scan of `config_dir` for files matching the union of
    `includes` globs. Returns paths sorted alphabetically.

    Skips dotfiles, symlinks, and subdirectories. Raises FileNotFoundError
    if no files match. Raises NotADirectoryError if `config_dir` is a file.
    """
    config_dir = Path(config_dir)
    if not config_dir.exists():
        raise FileNotFoundError(f"Config directory not found: {config_dir}")
    if not config_dir.is_dir():
        raise NotADirectoryError(f"Config path is not a directory: {config_dir}")

    if not includes:
        includes = list(DEFAULT_INCLUDES)

    matched: set[Path] = set()
    for pattern in includes:
        for p in config_dir.glob(pattern):
            # Skip dotfiles, subdirectories, symlinks
            if not p.is_file() or p.is_symlink() or p.name.startswith("."):
                continue
            matched.add(p.resolve())

    if not matched:
        joined = ",".join(includes)
        raise FileNotFoundError(
            f"No config files found in {config_dir} (patterns: {joined})"
        )

    return sorted(matched)


def device_snapshot_from_audit(ar: AuditResult, config_dir: Path) -> DeviceSnapshot:
    """Map an AuditResult to a DeviceSnapshot for the Snapshot contract.

    - ERROR AuditResult → DeviceSnapshot(status=ERROR, level=LOW default fill)
    - Otherwise → DeviceSnapshot with derived level and severity_breakdown
    """
    config_dir = Path(config_dir)
    config_path = str(ar.config_path)
    # Make path relative to config_dir if possible (for human-readable display)
    try:
        rel = Path(ar.config_path).resolve().relative_to(Path(config_dir).resolve())
        config_path = str(rel)
    except (ValueError, OSError):
        pass  # keep absolute if it doesn't resolve under config_dir

    device_name = Path(ar.config_name).stem

    if ar.is_error:
        return DeviceSnapshot(
            device_name=device_name,
            config_path=config_path,
            config_hash=ar.config_hash,
            status="ERROR",
            level="LOW",  # default fill; dashboards must check `status` first
            severity_breakdown=EMPTY_BREAKDOWN,
            findings=[],
            error=ar.error,
        )

    # Compute severity breakdown and check for any FAIL findings in one pass
    breakdown = dict(EMPTY_BREAKDOWN)  # copy; we mutate it below
    has_fail = False
    for f in ar.findings:
        sev = f.severity.value
        if sev in breakdown:
            breakdown[sev] += 1
        if f.status.value == "FAIL":
            has_fail = True
    status = "NON-COMPLIANT" if has_fail else "COMPLIANT"

    # Determine level from risk_result
    level = "LOW"
    if ar.risk_result is not None:
        level_value = ar.risk_result.risk_score.level.value
        if level_value in VALID_LEVELS:
            level = level_value

    return DeviceSnapshot(
        device_name=device_name,
        config_path=config_path,
        config_hash=ar.config_hash,
        status=status,
        level=level,
        severity_breakdown=breakdown,
        findings=ar.findings,
        error=None,
    )


def build_snapshot(
    config_dir: Path,
    rules_dir: Path,
    configguard_version: str,
    use_context: bool = True,
) -> Snapshot:
    """Discover configs in `config_dir`, audit each, build a Snapshot.

    Returns a fully-populated Snapshot. The caller is responsible for
    writing it to disk and printing the assessment block.

    Continues on per-device errors (parse failure, read failure, etc.):
    partial success is preferred over atomic failure — a fleet with one
    broken config should still report the rest.
    """
    config_dir = Path(config_dir)
    config_paths = discover_configs(config_dir)

    devices = []
    for cfg_path in config_paths:
        ar = run_audit(
            config_path=cfg_path,
            config_name=cfg_path.name,
            rules_dir=rules_dir,
            use_context=use_context,
        )
        ds = device_snapshot_from_audit(ar, config_dir=config_dir)
        devices.append(ds)

    summary = FleetSummary.from_devices(devices)

    # Generator metadata: honor the caller's configguard_version when
    # explicitly provided so the test (and any external caller) sees
    # the version they asked for rather than the imported __version__.
    generator = make_generator_metadata()
    if configguard_version is not None:
        generator["configguard_version"] = configguard_version

    return Snapshot(
        snapshot_version=1,
        generator=generator,
        generated_at=now_iso_utc(),
        source={
            "config_dir": str(config_dir),
            "rules_dir": str(rules_dir),
        },
        summary=summary,
        devices=devices,
    )
