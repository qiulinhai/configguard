"""Fleet orchestrator: discover configs, audit each, build a Snapshot.

`configguard fleet audit <dir>` is a thin wrapper over `audit_service.run()`
that produces a self-contained `Snapshot` plus per-device JSON reports.

Architecture (per spec §3.1):
  cli.py  →  fleet.py  →  services/audit_service.py  →  engine
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

# Default globs matched in addition to user-supplied --include values.
DEFAULT_INCLUDES = ("*.conf", "*.txt", "*.cfg")


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
