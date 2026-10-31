"""Tests for acl.py — deny/remove on top folder only; skip on FAT."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hider.acl     import apply_deny, current_user_sid, remove_deny
from hider.preflight import is_ntfs


# ── current_user_sid ──────────────────────────────────────────────────────────

def test_current_user_sid_format():
    sid = current_user_sid()
    assert sid.startswith("S-1-"), f"Unexpected SID format: {sid!r}"
    parts = sid.split("-")
    assert len(parts) >= 4


# ── Deny / remove on NTFS ─────────────────────────────────────────────────────

def test_deny_applied_to_top_folder_only(tmp_path: Path):
    if not is_ntfs(tmp_path):
        pytest.skip("Requires NTFS")

    folder = tmp_path / "secret"
    folder.mkdir()
    child  = folder / "child.txt"
    child.write_text("child content")

    sid = current_user_sid()
    apply_deny(folder, sid)

    # Listing the denied folder must fail with PermissionError (Access is denied)
    with pytest.raises(PermissionError):
        list(folder.iterdir())

    # Because there are no inheritance flags (no OI/CI), direct access to child by exact path
    # succeeds (thanks to Windows SeChangeNotifyPrivilege / bypass traverse checking)
    assert child.read_text() == "child content"

    # Clean up
    assert remove_deny(folder, sid)

    # After remove_deny, directory listing succeeds
    assert [p.name for p in folder.iterdir()] == ["child.txt"]


def test_remove_deny(tmp_path: Path):
    if not is_ntfs(tmp_path):
        pytest.skip("Requires NTFS")

    folder = tmp_path / "vault"
    folder.mkdir()
    sid = current_user_sid()
    apply_deny(folder, sid)
    assert remove_deny(folder, sid)

    result = subprocess.run(
        ["icacls", str(folder)], capture_output=True, text=True
    )
    assert "(DENY)" not in result.stdout


# ── FAT/non-NTFS skip ─────────────────────────────────────────────────────────

def test_acl_skipped_on_non_ntfs(tmp_path: Path, monkeypatch):
    """Monkey-patch is_ntfs to return False; apply_deny must be a no-op."""
    import hider.acl as acl_mod
    monkeypatch.setattr(acl_mod, "is_ntfs", lambda p: False)

    folder = tmp_path / "fat_folder"
    folder.mkdir()
    sid = current_user_sid()
    # Should not raise, should not call icacls
    apply_deny(folder, sid)
    remove_deny(folder, sid)

