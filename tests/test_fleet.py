"""Unit tests for the fleet module."""
from pathlib import Path
import pytest
from configguard.fleet import discover_configs


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
