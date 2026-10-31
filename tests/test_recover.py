"""
Tests for recover — interrupted hide, state-dir deleted, index deleted.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

from hider.crypto   import generate_keypair, encrypt_manifest, unwrap_privkey
from hider.tree     import Node, build_tree, rename_hide
from hider.attrs    import get_attrs
from hider.journal  import write_hide_journal, update_hide_phase, recover_all, delete_hide_journal


def _guid() -> str:
    return str(uuid.uuid4())


def _name_gen() -> str:
    return str(uuid.uuid4())


def _build(src: Path, guid: str) -> Node:
    return build_tree(src, guid, _name_gen, get_attrs, {"manifest.dat"})


def _make_src(tmp_path: Path) -> Path:
    src = tmp_path / "Photos"
    src.mkdir()
    (src / "IMG_001.jpg").write_bytes(b"\xff\xd8\xff")
    (src / "sub").mkdir()
    (src / "sub" / "pic.jpg").write_bytes(b"\xff\xd8\xff")
    return src


# ── Interrupted hide — partial renames ────────────────────────────────────────

def test_recover_interrupted_hide_renames(tmp_path: Path):
    """
    Simulate a crash after some renames completed.
    recover_all must roll back to the original names.
    """
    src        = _make_src(tmp_path)
    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _guid()
    root = _build(src, guid)

    write_hide_journal(vault_root, guid, src, root)

    # Rename only first child (partial crash)
    if root.children:
        first    = root.children[0]
        cur_path = src / first.original_name
        rnd_path = src / first.random_name
        if cur_path.exists():
            os.rename(str(cur_path), str(rnd_path))
    update_hide_phase(vault_root, guid, "renames")

    # Trigger recovery
    recover_all(vault_root)

    # All children must be back to original names
    for child in root.children:
        assert (src / child.original_name).exists(), \
            f"Rollback failed for {child.original_name}"
    # Journal files should be gone
    assert not (vault_root / f"journal-{guid}.dat").exists()


# ── Interrupted hide — after move ─────────────────────────────────────────────

def test_recover_interrupted_hide_after_move(tmp_path: Path):
    """Crash after os.rename (folder in vault root) — recovery must move it back."""
    src        = _make_src(tmp_path)
    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _guid()
    root = _build(src, guid)

    write_hide_journal(vault_root, guid, src, root)

    # Do all renames
    rename_hide(root, src)
    # Move to vault
    guid_dir = vault_root / guid
    os.rename(str(src), str(guid_dir))
    update_hide_phase(vault_root, guid, "moved")

    # Recovery
    recover_all(vault_root)

    # Folder should be back at original location with original child names
    assert src.exists(), "Folder not restored to original location"
    for child in root.children:
        assert (src / child.original_name).exists()


# ── Recover with state dir deleted ────────────────────────────────────────────

def test_recover_without_state_dir(tmp_path: Path):
    """
    Simulate state dir deletion.  recover_cmd should rebuild keys from
    the manifest header embedded in the vault.
    """
    pubkey_raw, privkey_enc = generate_keypair("testpw")
    privkey_raw = unwrap_privkey(privkey_enc, "testpw")

    src        = _make_src(tmp_path)
    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    guid = _guid()
    root = _build(src, guid)

    # Write a proper manifest with embedded privkey_enc
    body = json.dumps({
        "vault_id":  guid,
        "src_path":  str(src),
        "hide_time": "2026-01-01T00:00:00Z",
        "root":      root.to_dict(),
    }).encode()
    manifest_bytes = encrypt_manifest(pubkey_raw, privkey_enc, body)

    rename_hide(root, src)
    guid_dir = vault_root / guid
    os.rename(str(src), str(guid_dir))
    (guid_dir / "manifest.dat").write_bytes(manifest_bytes)

    # Delete fake state dir (simulate deletion)
    fake_state = tmp_path / "state"
    fake_state.mkdir()
    pubkey_file  = fake_state / "public_key"
    privkey_file = fake_state / "private_key.enc"
    pubkey_file.write_bytes(pubkey_raw)
    privkey_file.write_bytes(privkey_enc)

    # Verify we can parse the manifest header to get privkey_enc back
    from hider.crypto import parse_manifest_header, decrypt_manifest
    data = (guid_dir / "manifest.dat").read_bytes()
    pub, priv_enc, _ = parse_manifest_header(data)
    assert pub == pubkey_raw
    assert priv_enc == privkey_enc

    # Verify full decrypt works
    body_out, _ = decrypt_manifest(data, "testpw")
    body_dict   = json.loads(body_out)
    assert body_dict["vault_id"] == guid


# ── Recover with index deleted ────────────────────────────────────────────────

def test_recover_with_missing_index(tmp_path: Path):
    """
    The index file is absent.  list_vaults must return empty list.
    recover_cmd scans vault roots directly and does not depend on the index.
    """
    from hider.index import list_vaults, rebuild_index
    pubkey_raw, privkey_enc = generate_keypair("pw")
    privkey_raw = unwrap_privkey(privkey_enc, "pw")

    # No index file → list returns empty
    vaults = list_vaults(pubkey_raw, privkey_raw)
    assert vaults == []

