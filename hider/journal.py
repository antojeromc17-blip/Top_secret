"""
DPAPI-encrypted journal for crash-safe hide and unhide operations.

Layout on disk (both files at vault_root level — NOT inside the GUID dir,
so they survive the os.rename move and are found by recovery):

  <vault_root>\\journal-<GUID>.dat    DPAPI-encrypted full journal JSON
  <vault_root>\\journal-<GUID>.state  Plaintext phase name (updated at boundaries)

  <vault_root>\\unhide-journal-<GUID>.dat    (same pattern for unhide)
  <vault_root>\\unhide-journal-<GUID>.state

Journal JSON schema (hide):
  {
    "type":     "hide",
    "vault_id": "<GUID>",
    "src_path": "C:\\\\...",
    "root":     <Node.to_dict()>
  }

Journal JSON schema (unhide):
  {
    "type":      "unhide",
    "vault_id":  "<GUID>",
    "dest_path": "C:\\\\...",
    "root":      <Node.to_dict()>
  }

Phases (hide):
  start → renames → moved → attrs → acl → index → done

Phases (unhide):
  start → acl_removed → attrs_restored → moved_back → renames → done

Auto-recovery runs at the start of every CLI command without a passphrase.
Recovery on "index" state: vault is correctly hidden; ensure index entry is
present; delete journals.  (Fix C3 — do NOT remove the index entry.)

fsync: journal.state is fsynced on every write (fix S4).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from .crypto import dpapi_protect, dpapi_unprotect
from .tree import Node, rename_hide, rollback_hide_renames, rename_unhide

if TYPE_CHECKING:
    pass


# ── File naming ───────────────────────────────────────────────────────────────

def _dat(vault_root: Path, guid: str, prefix: str = "journal") -> Path:
    return vault_root / f"{prefix}-{guid}.dat"


def _state(vault_root: Path, guid: str, prefix: str = "journal") -> Path:
    return vault_root / f"{prefix}-{guid}.state"


# ── Write helpers ─────────────────────────────────────────────────────────────

def _write_dat(path: Path, payload: dict) -> None:
    raw  = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    blob = dpapi_protect(raw)
    with open(path, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())


def _write_state(path: Path, phase: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(phase)
        f.flush()
        os.fsync(f.fileno())


def _read_dat(path: Path) -> dict:
    return json.loads(dpapi_unprotect(path.read_bytes()))


# ── Hide journal ──────────────────────────────────────────────────────────────

def write_hide_journal(vault_root: Path, guid: str, src_path: Path, root: Node) -> None:
    """Write the full hide journal before any rename begins.  Phase = 'start'."""
    payload = {
        "type":     "hide",
        "vault_id": guid,
        "src_path": str(src_path.resolve()),
        "root":     root.to_dict(),
    }
    _write_dat(_dat(vault_root, guid), payload)
    _write_state(_state(vault_root, guid), "start")


def update_hide_phase(vault_root: Path, guid: str, phase: str) -> None:
    _write_state(_state(vault_root, guid), phase)


def delete_hide_journal(vault_root: Path, guid: str) -> None:
    _dat(vault_root, guid).unlink(missing_ok=True)
    _state(vault_root, guid).unlink(missing_ok=True)


# ── Unhide journal ────────────────────────────────────────────────────────────

def write_unhide_journal(
    vault_root: Path, guid: str, dest_path: Path, root: Node
) -> None:
    """
    Write the full unhide journal at vault_root level BEFORE touching any file.
    (Fix C2: explicitly at vault_root, not inside vault_root/GUID.)
    """
    payload = {
        "type":      "unhide",
        "vault_id":  guid,
        "dest_path": str(dest_path.resolve()),
        "root":      root.to_dict(),
    }
    _write_dat(_dat(vault_root, guid, "unhide-journal"), payload)
    _write_state(_state(vault_root, guid, "unhide-journal"), "start")


def update_unhide_phase(vault_root: Path, guid: str, phase: str) -> None:
    _write_state(_state(vault_root, guid, "unhide-journal"), phase)


def delete_unhide_journal(vault_root: Path, guid: str) -> None:
    _dat(vault_root, guid, "unhide-journal").unlink(missing_ok=True)
    _state(vault_root, guid, "unhide-journal").unlink(missing_ok=True)


# ── Auto-recovery (runs without passphrase at the start of every command) ─────

def recover_all(vault_root: Path, index_ensure_fn=None) -> None:
    """
    Scan *vault_root* for interrupted hide/unhide operations and resume or roll back.
    *index_ensure_fn* — optional callable(vault_id) that ensures an index entry
    exists (used when recovering a hide at the 'index' phase).
    No passphrase required — uses DPAPI.
    """
    if not vault_root.exists():
        return

    for dat_path in list(vault_root.glob("journal-*.dat")):
        guid = dat_path.stem.removeprefix("journal-")
        _recover_hide(vault_root, guid, dat_path, index_ensure_fn)

    for dat_path in list(vault_root.glob("unhide-journal-*.dat")):
        guid = dat_path.stem.removeprefix("unhide-journal-")
        _recover_unhide(vault_root, guid, dat_path)


def _recover_hide(vault_root: Path, guid: str, dat_path: Path, index_ensure_fn) -> None:
    from .attrs import restore_attrs, set_hidden_system
    from .acl import remove_deny, apply_deny

    state_path = _state(vault_root, guid)
    phase      = state_path.read_text(encoding="utf-8").strip() if state_path.exists() else "start"

    if phase == "done":
        delete_hide_journal(vault_root, guid)
        return

    try:
        payload  = _read_dat(dat_path)
        root     = Node.from_dict(payload["root"])
        src_path = Path(payload["src_path"])
    except Exception:
        # Corrupt journal — can't recover; leave for manual intervention
        return

    guid_dir = vault_root / guid

    if phase == "index":
        # Vault is correctly hidden.  Ensure the index entry exists.  (Fix C3)
        if index_ensure_fn:
            index_ensure_fn(guid)
        delete_hide_journal(vault_root, guid)
        return

    if phase == "acl":
        # ACL may be partially applied; remove it so we can access the folder
        try:
            from .acl import current_user_sid
            sid = current_user_sid()
            remove_deny(guid_dir, sid)
        except Exception:
            pass
        # Restore original attrs on vault dir
        if guid_dir.exists():
            try:
                restore_attrs(guid_dir, root.original_attrs)
            except Exception:
                pass
        # Fall through to 'moved' recovery

    if phase in ("moved", "attrs", "acl"):
        # Move back to original location
        if guid_dir.exists() and not src_path.exists():
            try:
                _w = lambda p: "\\\\?\\" + str(p.resolve())
                import os as _os
                _os.rename(_w(guid_dir), _w(src_path))
            except Exception:
                return
        # Fall through to rename rollback

    if phase in ("moved", "attrs", "acl") or phase.startswith("renames"):
        # Roll back completed renames; probe idempotently
        rollback_hide_renames(root, src_path)

    # Delete manifest.dat if it ended up in src_path (rollback cleanup)
    manifest = src_path / "manifest.dat"
    if manifest.exists():
        manifest.unlink(missing_ok=True)

    delete_hide_journal(vault_root, guid)


def _recover_unhide(vault_root: Path, guid: str, dat_path: Path) -> None:
    from .attrs import restore_attrs
    from .acl import apply_deny, remove_deny, current_user_sid

    state_path = _state(vault_root, guid, "unhide-journal")
    phase      = state_path.read_text(encoding="utf-8").strip() if state_path.exists() else "start"

    if phase == "done":
        delete_unhide_journal(vault_root, guid)
        return

    try:
        payload   = _read_dat(dat_path)
        root      = Node.from_dict(payload["root"])
        dest_path = Path(payload["dest_path"])
        guid_dir  = vault_root / guid
    except Exception:
        return

    if phase == "start":
        # Nothing done yet; just clean up the journal
        delete_unhide_journal(vault_root, guid)
        return

    if phase == "renames" or phase == "moved_back":
        # Folder is at dest; resume renames from current state (idempotent probe)
        rename_unhide(root, dest_path)
        delete_unhide_journal(vault_root, guid)
        return

    if phase == "acl_removed":
        # ACL removed, but we never got to the move.
        # Folder is still at vault_root/guid; re-apply ACL to be safe.
        try:
            sid = current_user_sid()
            apply_deny(guid_dir, sid)
        except Exception:
            pass
        delete_unhide_journal(vault_root, guid)
        return

