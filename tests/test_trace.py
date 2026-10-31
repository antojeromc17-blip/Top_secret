"""Tests for trace.py — Recent .lnk cleanup and thumbcache removal."""
from __future__ import annotations

import os
from pathlib import Path
import pytest

from hider.trace import clean_traces
from hider.tree import Node


def test_clean_traces_removes_matching_recent_lnk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Mock APPDATA and LOCALAPPDATA to tmp_path
    appdata = tmp_path / "AppData" / "Roaming"
    localappdata = tmp_path / "AppData" / "Local"
    recent_dir = appdata / "Microsoft" / "Windows" / "Recent"
    explorer_dir = localappdata / "Microsoft" / "Windows" / "Explorer"

    recent_dir.mkdir(parents=True)
    explorer_dir.mkdir(parents=True)

    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("LOCALAPPDATA", str(localappdata))

    # Create dummy files
    matching_lnk = recent_dir / "secret_photo.jpg.lnk"
    matching_lnk.write_text("dummy lnk")

    unrelated_lnk = recent_dir / "unrelated_document.pdf.lnk"
    unrelated_lnk.write_text("keep this lnk")

    thumbcache1 = explorer_dir / "thumbcache_256.db"
    thumbcache1.write_bytes(b"\x00" * 64)

    other_cache = explorer_dir / "iconcache_idx.db"
    other_cache.write_bytes(b"\x00" * 32)

    # Build tree with matching name
    child_node = Node(
        original_name="secret_photo.jpg",
        random_name="uuid-1",
        node_type="file",
        original_attrs=32,
    )
    root = Node(
        original_name="Photos",
        random_name="uuid-root",
        node_type="dir",
        original_attrs=16,
        children=[child_node],
    )

    clean_traces(root)

    # matching .lnk and thumbcache_*.db should be gone
    assert not matching_lnk.exists(), "Matching .lnk was not deleted"
    assert unrelated_lnk.exists(), "Unrelated .lnk was wrongly deleted"
    assert not thumbcache1.exists(), "thumbcache DB was not deleted"
    assert other_cache.exists(), "Other cache DB should remain"

