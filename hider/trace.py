"""
Best-effort trace cleanup after a hide operation.

Matching strategy: <filename>.lnk in the Recent folder, no COM / pywin32 needed.
thumbcache_*.db files are deleted wholesale (Explorer rebuilds them on demand).
All errors are silently ignored — trace cleanup never aborts a hide.
"""
from __future__ import annotations

import os
from pathlib import Path

from .tree import Node


def _collect_all_names(root: Node) -> set[str]:
    """Return all original_name values in the tree (files and dirs)."""
    names: set[str] = set()

    def _walk(node: Node) -> None:
        names.add(node.original_name)
        for child in node.children:
            _walk(child)

    for child in root.children:
        _walk(child)
    return names


def clean_traces(root: Node) -> None:
    """
    Delete Recent .lnk shortcuts and Explorer thumbcache entries
    that correspond to files and folders in *root*.
    Best-effort: any exception is swallowed; the hide is never aborted.
    """
    names = _collect_all_names(root)

    # ── Recent .lnk shortcuts ─────────────────────────────────────────────────
    recent = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
    for name in names:
        lnk = recent / f"{name}.lnk"
        try:
            lnk.unlink(missing_ok=True)
        except Exception:
            pass

    # ── Explorer thumbcache ───────────────────────────────────────────────────
    tc_dir = (
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "Microsoft" / "Windows" / "Explorer"
    )
    for db in tc_dir.glob("thumbcache_*.db"):
        try:
            db.unlink(missing_ok=True)
        except Exception:
            pass

