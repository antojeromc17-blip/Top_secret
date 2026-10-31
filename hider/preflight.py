"""
Pre-flight checks.  Every check runs BEFORE any file is modified.
Any failure raises PreflightError with a human-readable message.
"""
from __future__ import annotations

import ctypes
from pathlib import Path

from .wintypes_ext import (
    DELETE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS,
    FILE_SHARE_ALL,
    FILE_SHARE_NONE,
    INVALID_FILE_ATTRIBUTES,
    INVALID_HANDLE_VALUE,
    OPEN_EXISTING,
    _k32,
)


class PreflightError(Exception):
    """Raised when a pre-flight condition is not met.  Nothing has been modified."""


def _w(path: Path) -> str:
    return "\\\\?\\" + str(path.resolve())


# ── Win32 helpers ──────────────────────────────────────────────────────────────

def _get_attrs(path: Path) -> int:
    a = _k32.GetFileAttributesW(_w(path))
    if a == INVALID_FILE_ATTRIBUTES:
        raise PreflightError(f"Cannot read attributes of '{path}' (error {ctypes.get_last_error()})")
    return a


def is_locked(path: Path) -> bool:
    """
    True if the file/dir cannot be opened for DELETE access with no share mode.
    Opening with FILE_SHARE_NONE + DELETE means any other holder that did not
    grant FILE_SHARE_DELETE will cause a sharing violation — we detect that as locked.
    """
    flags = FILE_FLAG_BACKUP_SEMANTICS if path.is_dir() else 0
    h = _k32.CreateFileW(
        _w(path), DELETE, FILE_SHARE_NONE,
        None, OPEN_EXISTING, flags, None
    )
    if h == INVALID_HANDLE_VALUE:
        return True
    _k32.CloseHandle(h)
    return False


def can_write_and_delete(path: Path) -> bool:
    """
    Check that we can open the path for DELETE access (basic deletability check).
    Uses FILE_SHARE_ALL (READ | WRITE | DELETE) so other background readers
    (such as Explorer watching directory changes) are not blocked and do not
    cause false-positive sharing violations.
    """
    flags = FILE_FLAG_BACKUP_SEMANTICS if path.is_dir() else 0
    h = _k32.CreateFileW(
        _w(path), DELETE, FILE_SHARE_ALL,
        None, OPEN_EXISTING, flags, None
    )
    if h == INVALID_HANDLE_VALUE:
        return False
    _k32.CloseHandle(h)
    return True


def is_ntfs(path: Path) -> bool:
    """Return True if the volume containing *path* is NTFS."""
    buf = ctypes.create_unicode_buffer(32)
    _k32.GetVolumeInformationW(
        str(path.anchor), None, 0, None, None, None, buf, 32
    )
    return buf.value.upper() == "NTFS"


# ── Known system folder names (case-insensitive) ───────────────────────────────
_SYSTEM_NAMES = frozenset({
    "windows", "system32", "syswow64",
    "program files", "program files (x86)",
    "programdata", "users",
})


# ── Main pre-flight entry point ────────────────────────────────────────────────

def preflight(src: Path, vault_root: Path) -> None:
    """
    Run all pre-flight checks on *src* against *vault_root*.
    Raises PreflightError on the first failure; nothing is modified.
    """
    src = src.resolve()

    # 1. Not a drive root
    if src == Path(src.anchor):
        raise PreflightError(f"Cannot hide a drive root: {src}")

    # 2. Not a known system folder
    if src.name.lower() in _SYSTEM_NAMES:
        raise PreflightError(f"Refusing to hide a system folder: '{src.name}'")

    # 3. Same volume as vault root (os.rename cannot cross drives)
    if src.drive.upper() != vault_root.drive.upper():
        raise PreflightError(
            f"Source drive ({src.drive}) differs from vault drive ({vault_root.drive}). "
            "Move the vault root to the same volume, or use a secondary vault root."
        )

    # 4. We can delete/rename the source folder itself
    if not can_write_and_delete(src):
        raise PreflightError(
            f"Cannot rename/delete '{src}'. "
            "Ensure you have full-control rights over the folder."
        )

    # 5. Walk all children
    for item in src.rglob("*"):
        attrs = _get_attrs(item)

        if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            raise PreflightError(
                f"Reparse point (symlink or junction) found inside source:\n  {item}\n"
                "Remove it before hiding."
            )

        if attrs & (FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS):
            raise PreflightError(
                f"Cloud-only placeholder (file not downloaded locally):\n  {item}\n"
                "Download all files from the cloud before hiding."
            )

        # Lock check: folder open in Explorer triggers this on the folder itself (test coverage)
        if is_locked(item):
            raise PreflightError(
                f"File or folder is locked by another process:\n  {item}\n"
                "Close any programs that have this folder or its contents open."
            )

