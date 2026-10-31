"""Tests for preflight.py — lock, reparse, cloud, volume, Explorer-open checks."""
from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

from hider.preflight import PreflightError, is_locked, preflight


# ── is_locked ─────────────────────────────────────────────────────────────────

def test_unlocked_file_not_locked(tmp_path: Path):
    f = tmp_path / "free.txt"
    f.write_text("x")
    assert not is_locked(f)


def test_locked_file_detected(tmp_path: Path):
    """Hold a file open with no share mode from another thread; is_locked must return True."""
    f = tmp_path / "locked.txt"
    f.write_text("x")

    import ctypes
    from hider.wintypes_ext import (
        _k32, OPEN_EXISTING, FILE_SHARE_NONE, GENERIC_READ, INVALID_HANDLE_VALUE
    )
    # Open without any share flags to simulate a locked file
    h = _k32.CreateFileW(
        "\\\\?\\" + str(f.resolve()),
        GENERIC_READ, FILE_SHARE_NONE,
        None, OPEN_EXISTING, 0, None
    )
    assert h != INVALID_HANDLE_VALUE, "Could not open test file"
    try:
        assert is_locked(f), "Expected file to appear locked"
    finally:
        _k32.CloseHandle(h)


def test_locked_dir_detected(tmp_path: Path):
    """The preflight check must detect a folder open exclusively (Explorer scenario)."""
    import ctypes
    from hider.wintypes_ext import (
        _k32, OPEN_EXISTING, FILE_SHARE_NONE, DELETE,
        FILE_FLAG_BACKUP_SEMANTICS, INVALID_HANDLE_VALUE
    )
    d = tmp_path / "opendir"
    d.mkdir()
    h = _k32.CreateFileW(
        "\\\\?\\" + str(d.resolve()),
        DELETE, FILE_SHARE_NONE,
        None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None
    )
    if h == INVALID_HANDLE_VALUE:
        pytest.skip("Could not open directory exclusively (permissions)")
    try:
        assert is_locked(d), "Expected directory to appear locked"
    finally:
        _k32.CloseHandle(h)


# ── Reparse point ─────────────────────────────────────────────────────────────

def test_reparse_point_aborts(tmp_path: Path):
    """A symlink inside the folder must trigger PreflightError before any change."""
    src  = tmp_path / "src"
    src.mkdir()
    # Create a symlink inside src (requires SeCreateSymbolicLinkPrivilege or developer mode)
    link = src / "link.txt"
    try:
        link.symlink_to(tmp_path / "target.txt")
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires developer mode or elevated rights")

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    with pytest.raises(PreflightError, match="[Rr]eparse"):
        preflight(src, vault_root)
    # Ensure nothing in src was renamed
    assert link.exists()


# ── Cross-drive ───────────────────────────────────────────────────────────────

def test_cross_drive_aborts(tmp_path: Path):
    """Source and vault on different drives must abort with a clear message."""
    # Simulate by crafting paths with different drive letters
    src_drive    = tmp_path.drive.upper()
    other_drives = [f"{l}:" for l in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if f"{l}:".upper() != src_drive]
    if not other_drives:
        pytest.skip("Only one drive available")
    fake_vault_root = Path(other_drives[0] + "\\$WinREAgent")
    with pytest.raises(PreflightError, match="drive"):
        preflight(tmp_path, fake_vault_root)


# ── Nothing modified ──────────────────────────────────────────────────────────

def test_nothing_modified_on_preflight_failure(tmp_path: Path):
    """A locking failure must leave the directory completely untouched."""
    import ctypes
    from hider.wintypes_ext import (
        _k32, OPEN_EXISTING, FILE_SHARE_NONE, GENERIC_READ, INVALID_HANDLE_VALUE
    )
    src = tmp_path / "mydir"
    src.mkdir()
    f   = src / "file.txt"
    f.write_text("original")

    h = _k32.CreateFileW(
        "\\\\?\\" + str(f.resolve()),
        GENERIC_READ, FILE_SHARE_NONE,
        None, OPEN_EXISTING, 0, None
    )
    if h == INVALID_HANDLE_VALUE:
        pytest.skip("Could not lock test file")
    try:
        vault_root = tmp_path / "vault"
        vault_root.mkdir()
        with pytest.raises(PreflightError):
            preflight(src, vault_root)
    finally:
        _k32.CloseHandle(h)

    # After releasing lock handle, file still has original name and content
    assert f.read_text() == "original"

