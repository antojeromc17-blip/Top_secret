"""Tests for attrs.py — read-modify-write attribute helpers."""
from __future__ import annotations

import pytest
from pathlib import Path

from hider.attrs import (
    add_attrs, clear_not_content_indexed,
    get_attrs, restore_attrs, set_attrs,
)
from hider.wintypes_ext import (
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
    FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_SYSTEM,
)

FILE_ATTRIBUTE_ARCHIVE = 0x20   # standard "archive" bit set on new files


# ── Basic get/set ─────────────────────────────────────────────────────────────

def test_get_attrs_file(tmp_path: Path):
    f = tmp_path / "test.txt"
    f.write_text("x")
    attrs = get_attrs(f)
    assert attrs != 0xFFFFFFFF


def test_get_attrs_nonexistent_raises(tmp_path: Path):
    with pytest.raises(OSError):
        get_attrs(tmp_path / "ghost.txt")


# ── add_attrs preserves other bits ────────────────────────────────────────────

def test_add_attrs_preserves_archive_bit(tmp_path: Path):
    f = tmp_path / "test.txt"
    f.write_text("x")
    original = get_attrs(f)
    # Files typically have Archive bit; add Hidden and check Archive is still set
    add_attrs(f, FILE_ATTRIBUTE_HIDDEN)
    new_attrs = get_attrs(f)
    assert new_attrs & FILE_ATTRIBUTE_HIDDEN
    if original & FILE_ATTRIBUTE_ARCHIVE:
        assert new_attrs & FILE_ATTRIBUTE_ARCHIVE, "Archive bit was cleared by add_attrs"


def test_restore_attrs_exact(tmp_path: Path):
    f = tmp_path / "test.txt"
    f.write_text("x")
    original = get_attrs(f)
    add_attrs(f, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
    restore_attrs(f, original)
    assert get_attrs(f) == original


# ── Read-only files ───────────────────────────────────────────────────────────

def test_readonly_file_attrs_preserved(tmp_path: Path):
    f = tmp_path / "ro.txt"
    f.write_text("x")
    original = get_attrs(f)
    add_attrs(f, FILE_ATTRIBUTE_READONLY)
    ro_attrs = get_attrs(f)
    assert ro_attrs & FILE_ATTRIBUTE_READONLY
    # Restore back and check READONLY is gone
    restore_attrs(f, original)
    assert not (get_attrs(f) & FILE_ATTRIBUTE_READONLY)


# ── NOT_CONTENT_INDEXED ───────────────────────────────────────────────────────

def test_not_content_indexed_set_and_clear(tmp_path: Path):
    d = tmp_path / "subdir"
    d.mkdir()
    original = get_attrs(d)
    add_attrs(d, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
    assert get_attrs(d) & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
    clear_not_content_indexed(d)
    assert not (get_attrs(d) & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)


# ── Extensionless files ───────────────────────────────────────────────────────

def test_extensionless_file(tmp_path: Path):
    f = tmp_path / "noext"
    f.write_text("data")
    original = get_attrs(f)
    add_attrs(f, FILE_ATTRIBUTE_HIDDEN)
    restore_attrs(f, original)
    assert get_attrs(f) == original


# ── Empty directory ───────────────────────────────────────────────────────────

def test_empty_dir_attrs(tmp_path: Path):
    d = tmp_path / "empty"
    d.mkdir()
    original = get_attrs(d)
    add_attrs(d, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
    restored = get_attrs(d)
    assert restored & FILE_ATTRIBUTE_HIDDEN
    restore_attrs(d, original)
    assert get_attrs(d) == original

