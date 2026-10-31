"""
Windows file attribute helpers.

All calls use \\?\\-prefixed paths and check return values.
set_attrs / add_attrs raise OSError on failure (fixes W2, W3).
"""
from __future__ import annotations

import ctypes
from pathlib import Path

from .wintypes_ext import (
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
    FILE_ATTRIBUTE_SYSTEM,
    INVALID_FILE_ATTRIBUTES,
    _k32,
)


def _w(path: Path) -> str:
    return "\\\\?\\" + str(path.resolve())


def get_attrs(path: Path) -> int:
    """Return the raw Windows attribute DWORD.  Raises OSError on failure (fix W2)."""
    attrs = _k32.GetFileAttributesW(_w(path))
    if attrs == INVALID_FILE_ATTRIBUTES:
        raise OSError(
            f"GetFileAttributesW failed on '{path}' "
            f"(error {ctypes.get_last_error()})"
        )
    return attrs


def set_attrs(path: Path, attrs: int) -> None:
    """Set the raw Windows attribute DWORD.  Raises OSError on failure (fix W3)."""
    if not _k32.SetFileAttributesW(_w(path), attrs):
        raise OSError(
            f"SetFileAttributesW failed on '{path}' "
            f"(error {ctypes.get_last_error()})"
        )


def add_attrs(path: Path, bits: int) -> int:
    """
    Read-modify-write: OR in *bits*, preserving all other attribute bits.
    Returns the original value so the caller can restore it later.
    """
    original = get_attrs(path)
    set_attrs(path, original | bits)
    return original


def restore_attrs(path: Path, original: int) -> None:
    """Write back the previously captured attribute value (exact restore)."""
    set_attrs(path, original)


def set_hidden_system(path: Path) -> int:
    """Set Hidden + System.  Returns original attrs."""
    return add_attrs(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)


def set_not_content_indexed(path: Path) -> int:
    """Set NOT_CONTENT_INDEXED.  Returns original attrs."""
    return add_attrs(path, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)


def clear_not_content_indexed(path: Path) -> None:
    """Clear NOT_CONTENT_INDEXED, preserving all other bits."""
    original = get_attrs(path)
    set_attrs(path, original & ~FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)

