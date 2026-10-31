"""
Best-effort trace cleanup after a hide operation.

Purges:
1. Recent items in %APPDATA%\\Microsoft\\Windows\\Recent:
   - Matches both full name and stem (.lnk created without extension)
   - Inspects .lnk binary payloads for target path / name matches
2. Jump Lists in AutomaticDestinations and CustomDestinations:
   - Windows Explorer Recent Files / Quick Access jump list (f01b4d95cf55d32a)
   - Any destination list containing references to the hidden files
3. Explorer thumbnail caches (thumbcache_*.db)
4. Issues SHChangeNotify to force Explorer to refresh its view immediately.

All errors are silently ignored — trace cleanup never aborts a hide.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path

from .tree import Node


def _collect_all_names(root: Node) -> set[str]:
    """Return all original names, directory names, and stems in the tree."""
    names: set[str] = {root.original_name, Path(root.original_name).stem}

    def _walk(node: Node) -> None:
        names.add(node.original_name)
        stem = Path(node.original_name).stem
        if stem:
            names.add(stem)
        for child in node.children:
            _walk(child)

    for child in root.children:
        _walk(child)

    return {n for n in names if n}


def clean_traces(root: Node) -> None:
    """
    Delete Recent .lnk shortcuts, jump list destinations, and Explorer thumbcache
    entries that correspond to files and folders in *root*.
    Best-effort: any exception is swallowed; the hide is never aborted.
    """
    names = _collect_all_names(root)
    names_lower = {n.lower() for n in names}

    recent = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"

    # ── 1. Recent .lnk shortcuts ──────────────────────────────────────────────
    if recent.exists():
        for lnk in list(recent.glob("*.lnk")):
            stem_lower = lnk.stem.lower()
            should_delete = any(n in stem_lower for n in names_lower)
            if not should_delete:
                try:
                    data_lower = lnk.read_bytes().lower()
                    for n in names:
                        if (
                            n.encode("utf-8").lower() in data_lower
                            or n.encode("utf-16le").lower() in data_lower
                        ):
                            should_delete = True
                            break
                except Exception:
                    pass

            if should_delete:
                try:
                    lnk.unlink(missing_ok=True)
                except Exception:
                    pass

    # ── 2. AutomaticDestinations and CustomDestinations (Jump Lists) ──────────
    for sub in ("AutomaticDestinations", "CustomDestinations"):
        dest_dir = recent / sub
        if not dest_dir.exists():
            continue
        pattern = "*.automaticDestinations-ms" if sub == "AutomaticDestinations" else "*.customDestinations-ms"
        for ms_file in list(dest_dir.glob(pattern)):
            try:
                data_lower = ms_file.read_bytes().lower()
                for n in names:
                    if (
                        n.encode("utf-8").lower() in data_lower
                        or n.encode("utf-16le").lower() in data_lower
                    ):
                        ms_file.unlink(missing_ok=True)
                        break
            except Exception:
                pass

    # ── 3. Explorer thumbcache ────────────────────────────────────────────────
    tc_dir = (
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "Microsoft"
        / "Windows"
        / "Explorer"
    )
    if tc_dir.exists():
        for db in tc_dir.glob("thumbcache_*.db"):
            try:
                db.unlink(missing_ok=True)
            except Exception:
                pass

    # ── 4. Notify Windows Shell to refresh recent / explorer views ────────────
    try:
        # SHCNE_UPDATEDIR (0x00001000) with SHCNF_PATHW (0x0005)
        ctypes.windll.shell32.SHChangeNotify(0x00001000, 0x0005, None, None)
    except Exception:
        pass
