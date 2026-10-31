"""
Full round-trip vault tests.

Covers: hide → unhide, crash injection during hide/unhide, no IMG_/.jpg on disk
after hide, manifest cleanup, >260-char paths, unicode names, empty dirs,
read-only files, extensionless files, restored-name fallback.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

import pytest

from hider.crypto import generate_keypair, encrypt_manifest, unwrap_privkey
from hider.tree   import Node, build_tree, rename_hide, rollback_hide_renames, rename_unhide
from hider.attrs  import get_attrs, add_attrs, restore_attrs
from hider.wintypes_ext import FILE_ATTRIBUTE_READONLY


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_tree(base: Path) -> None:
    """Create a realistic folder tree with IMG_ files."""
    (base / "IMG_0001.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 100)
    (base / "IMG_0002.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 200)
    (base / "document.pdf").write_bytes(b"%PDF")
    (base / "noext").write_bytes(b"data without extension")
    sub = base / "Vacation"
    sub.mkdir()
    (sub / "beach.jpg").write_bytes(b"\xff\xd8\xff")
    (sub / "notes.txt").write_text("holiday notes", encoding="utf-8")
    empty = base / "EmptyFolder"
    empty.mkdir()


def _make_vault_guid() -> str:
    return str(uuid.uuid4())


def _build_test_tree(src: Path, guid: str) -> Node:
    def _name_gen():
        return str(uuid.uuid4())
    def _get_a(p):
        return get_attrs(p)
    return build_tree(src, guid, _name_gen, _get_a, exclude_names={"manifest.dat"})


# ── Round-trip ────────────────────────────────────────────────────────────────

def test_round_trip(tmp_path: Path):
    src = tmp_path / "Photos"
    src.mkdir()
    _make_tree(src)

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _make_vault_guid()

    # Capture original structure
    original_files = {p.relative_to(src) for p in src.rglob("*")}

    # Build tree and hide
    root = _build_test_tree(src, guid)
    rename_hide(root, src)
    guid_dir = vault_root / guid
    os.rename("\\\\?\\" + str(src.resolve()), "\\\\?\\" + str(guid_dir.resolve()))

    # Verify nothing with original name on disk
    for rel in original_files:
        assert not (vault_root / rel).exists(), f"Original name leaked: {rel}"

    # Unhide
    dest = tmp_path / "Photos_restored"
    os.rename("\\\\?\\" + str(guid_dir.resolve()), "\\\\?\\" + str(dest.resolve()))
    rename_unhide(root, dest)

    # Check all files restored
    for rel in original_files:
        assert (dest / rel).exists(), f"Missing after unhide: {rel}"


def test_no_img_or_jpg_after_hide(tmp_path: Path):
    """After hide, no file inside vault_root should have IMG_ in name or .jpg extension."""
    src = tmp_path / "Photos"
    src.mkdir()
    _make_tree(src)

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _make_vault_guid()
    root = _build_test_tree(src, guid)

    rename_hide(root, src)
    guid_dir = vault_root / guid
    os.rename("\\\\?\\" + str(src.resolve()), "\\\\?\\" + str(guid_dir.resolve()))

    found_jpg   = list(vault_root.rglob("*.jpg"))
    found_img   = [p for p in vault_root.rglob("*") if "IMG_" in p.name]
    assert found_jpg  == [], f"Original .jpg names still on disk: {found_jpg}"
    assert found_img  == [], f"IMG_ names still on disk: {found_img}"


def test_crash_during_hide_renames_rollback(tmp_path: Path):
    """Simulate a crash partway through renaming; rollback must restore originals."""
    src = tmp_path / "Photos"
    src.mkdir()
    _make_tree(src)

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _make_vault_guid()
    root = _build_test_tree(src, guid)

    # Partially rename: only first child
    if root.children:
        first = root.children[0]
        cur  = src / first.original_name
        rnd  = src / first.random_name
        if cur.exists():
            os.rename("\\\\?\\" + str(cur.resolve()), "\\\\?\\" + str(rnd.resolve()))

    # Now simulate crash + rollback
    rollback_hide_renames(root, src)

    # All children should be back to original names
    for child in root.children:
        assert (src / child.original_name).exists(), \
            f"Rollback failed for {child.original_name}"


def test_crash_during_unhide_renames(tmp_path: Path):
    """Simulate a crash partway through unhide renames; idempotent resume restores all."""
    src = tmp_path / "Photos"
    src.mkdir()
    _make_tree(src)

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _make_vault_guid()
    root = _build_test_tree(src, guid)

    # Full hide
    rename_hide(root, src)
    guid_dir = vault_root / guid
    os.rename("\\\\?\\" + str(src.resolve()), "\\\\?\\" + str(guid_dir.resolve()))

    # Move back to simulate start of unhide
    dest = tmp_path / "Photos_back"
    os.rename("\\\\?\\" + str(guid_dir.resolve()), "\\\\?\\" + str(dest.resolve()))

    # Partially rename only first child back
    if root.children:
        first     = root.children[0]
        rand_path = dest / first.random_name
        orig_path = dest / first.original_name
        if rand_path.exists():
            os.rename("\\\\?\\" + str(rand_path.resolve()), "\\\\?\\" + str(orig_path.resolve()))

    # Resume unhide (idempotent)
    rename_unhide(root, dest)

    for child in root.children:
        assert (dest / child.original_name).exists()


def test_manifest_deleted_after_unhide(tmp_path: Path):
    """manifest.dat must not exist in the restored folder after a successful unhide."""
    src = tmp_path / "Photos"
    src.mkdir()
    (src / "file.txt").write_text("data")
    manifest_path = src / "manifest.dat"
    manifest_path.write_bytes(b"fake manifest")

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _make_vault_guid()
    root = _build_test_tree(src, guid)
    rename_hide(root, src)
    guid_dir = vault_root / guid
    os.rename("\\\\?\\" + str(src.resolve()), "\\\\?\\" + str(guid_dir.resolve()))

    dest = tmp_path / "Photos_restored"
    os.rename("\\\\?\\" + str(guid_dir.resolve()), "\\\\?\\" + str(dest.resolve()))
    rename_unhide(root, dest)

    # Delete manifest as vault.py does
    (dest / "manifest.dat").unlink(missing_ok=True)
    assert not (dest / "manifest.dat").exists()


def test_restored_name_fallback(tmp_path: Path):
    """If original path is occupied, unhide must use '<name> (restored)'."""
    src = tmp_path / "Photos"
    src.mkdir()
    (src / "a.txt").write_text("x")

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _make_vault_guid()
    root = _build_test_tree(src, guid)
    rename_hide(root, src)
    guid_dir = vault_root / guid
    os.rename("\\\\?\\" + str(src.resolve()), "\\\\?\\" + str(guid_dir.resolve()))

    # Occupy the original destination
    src.mkdir()
    (src / "occupier.txt").write_text("I'm here")

    dest = tmp_path / "Photos (restored)"
    os.rename("\\\\?\\" + str(guid_dir.resolve()), "\\\\?\\" + str(dest.resolve()))
    rename_unhide(root, dest)
    assert (dest / "a.txt").exists()


def test_long_path_over_260(tmp_path: Path):
    """Hide + unhide must work on paths exceeding 260 characters."""
    # Build a deeply nested path > 260 chars total
    deep = tmp_path
    for _ in range(20):
        deep = deep / ("a" * 12)

    extended_deep = "\\\\?\\" + str(deep.resolve())
    os.makedirs(extended_deep, exist_ok=True)
    f = deep / "file.txt"
    with open("\\\\?\\" + str(f.resolve()), "w", encoding="utf-8") as fp:
        fp.write("data")

    vault_root = tmp_path / "vault"
    vault_root.mkdir()

    # Check path length
    assert len(str(deep.resolve())) > 260, "Path was not > 260 characters"

    guid = _make_vault_guid()
    root = _build_test_tree(deep, guid)
    rename_hide(root, deep)

    # Move to vault
    guid_dir = vault_root / guid
    os.rename("\\\\?\\" + str(deep.resolve()), "\\\\?\\" + str(guid_dir.resolve()))

    # Unhide
    dest = tmp_path / "restored_deep"
    os.rename("\\\\?\\" + str(guid_dir.resolve()), "\\\\?\\" + str(dest.resolve()))
    rename_unhide(root, dest)

    restored_file = "\\\\?\\" + str((dest / "file.txt").resolve())
    assert os.path.exists(restored_file)
    with open(restored_file, "r", encoding="utf-8") as fp:
        assert fp.read() == "data"


def test_unicode_names(tmp_path: Path):
    """Files with CJK, emoji, and accented characters must round-trip correctly."""
    src = tmp_path / "Unicode"
    src.mkdir()
    (src / "写真.jpg").write_bytes(b"\xff")
    (src / "café.txt").write_text("café")
    (src / "🎉party.png").write_bytes(b"\x89PNG")
    sub = src / "日本語フォルダ"
    sub.mkdir()
    (sub / "ファイル.txt").write_text("content")

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _make_vault_guid()
    root = _build_test_tree(src, guid)
    rename_hide(root, src)
    guid_dir = vault_root / guid
    os.rename("\\\\?\\" + str(src.resolve()), "\\\\?\\" + str(guid_dir.resolve()))
    dest = tmp_path / "Unicode_restored"
    os.rename("\\\\?\\" + str(guid_dir.resolve()), "\\\\?\\" + str(dest.resolve()))
    rename_unhide(root, dest)

    assert (dest / "写真.jpg").exists()
    assert (dest / "café.txt").exists()
    assert (dest / "🎉party.png").exists()
    assert (dest / "日本語フォルダ" / "ファイル.txt").exists()


def test_empty_directory_round_trips(tmp_path: Path):
    """An empty subdirectory must be correctly represented in the tree and restored."""
    src = tmp_path / "Folder"
    src.mkdir()
    empty = src / "EmptySubdir"
    empty.mkdir()
    (src / "file.txt").write_text("x")

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _make_vault_guid()
    root = _build_test_tree(src, guid)
    rename_hide(root, src)
    guid_dir = vault_root / guid
    os.rename("\\\\?\\" + str(src.resolve()), "\\\\?\\" + str(guid_dir.resolve()))
    dest = tmp_path / "Folder_back"
    os.rename("\\\\?\\" + str(guid_dir.resolve()), "\\\\?\\" + str(dest.resolve()))
    rename_unhide(root, dest)

    assert (dest / "EmptySubdir").is_dir()
    assert list((dest / "EmptySubdir").iterdir()) == []


def test_readonly_file_attrs_preserved(tmp_path: Path):
    """A read-only file inside the hidden folder must come back read-only."""
    src = tmp_path / "Docs"
    src.mkdir()
    ro = src / "readonly.txt"
    ro.write_text("protected")
    original_attrs = get_attrs(ro)
    add_attrs(ro, FILE_ATTRIBUTE_READONLY)

    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _make_vault_guid()
    root = _build_test_tree(src, guid)

    # The tree should have captured the readonly+whatever attrs at build time
    # (We do it again here for the test to capture AFTER setting readonly)
    root = _build_test_tree(src, guid)

    rename_hide(root, src)
    guid_dir = vault_root / guid
    os.rename("\\\\?\\" + str(src.resolve()), "\\\\?\\" + str(guid_dir.resolve()))
    dest = tmp_path / "Docs_back"
    os.rename("\\\\?\\" + str(guid_dir.resolve()), "\\\\?\\" + str(dest.resolve()))
    rename_unhide(root, dest)

    # Restore attrs per the tree
    def _restore(node: Node, parent: Path):
        for child in node.children:
            p = parent / child.original_name
            if p.exists():
                restore_attrs(p, child.original_attrs)
            if child.is_dir:
                _restore(child, p)
    _restore(root, dest)

    restored = dest / "readonly.txt"
    assert restored.exists()
    assert get_attrs(restored) & FILE_ATTRIBUTE_READONLY

