"""
ACL helpers: apply / remove deny ACEs and takeown fallback.

icacls is called with the *S-1-... SID form (fix for local accounts).
The deny is applied to the top-level folder only — no (OI)(CI) flags,
so child files are never touched (keeps things fast for 20k-file trees).
On non-NTFS volumes all ACL operations are silently skipped.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import subprocess
from pathlib import Path

from .preflight import is_ntfs
from .wintypes_ext import TOKEN_QUERY, TokenUser, _advapi32, _k32


def _w(path: Path) -> str:
    return "\\\\?\\" + str(path.resolve())


# ── SID retrieval ─────────────────────────────────────────────────────────────

def current_user_sid() -> str:
    """
    Return the string SID of the current user, e.g. 'S-1-5-21-...-1001'.
    All advapi32 functions have argtypes/restype set in wintypes_ext.py (fix W2).
    Token handle is always closed (fix W1).
    """
    token = ctypes.c_void_p()
    proc  = _k32.GetCurrentProcess()
    if not _advapi32.OpenProcessToken(proc, TOKEN_QUERY, ctypes.byref(token)):
        raise OSError(f"OpenProcessToken failed: {ctypes.get_last_error()}")

    try:
        # First call: get required buffer size
        needed = wt.DWORD(0)
        _advapi32.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not _advapi32.GetTokenInformation(
            token, TokenUser, buf, needed, ctypes.byref(needed)
        ):
            raise OSError(f"GetTokenInformation failed: {ctypes.get_last_error()}")

        # TOKEN_USER.User.Sid is the first pointer in the buffer
        sid_ptr = ctypes.c_void_p.from_buffer_copy(buf[:ctypes.sizeof(ctypes.c_void_p)])

        str_ptr = wt.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(str_ptr)):
            raise OSError(f"ConvertSidToStringSidW failed: {ctypes.get_last_error()}")
        try:
            return str_ptr.value
        finally:
            _k32.LocalFree(ctypes.cast(str_ptr, ctypes.c_void_p))
    finally:
        _k32.CloseHandle(token)   # fix W1: always close the token handle


def _sid_arg(sid: str) -> str:
    """Prefix SID with * for icacls (fix for local-account name resolution)."""
    return f"*{sid}"


# ── ACL operations ─────────────────────────────────────────────────────────────

def apply_deny(path: Path, sid: str) -> None:
    """
    Deny RX,W,D,DC on *path* for *sid*.
    Top-level folder only — no (OI)(CI) inheritance flags.
    Silently skipped on non-NTFS volumes.
    """
    if not is_ntfs(path):
        return
    subprocess.run(
        ["icacls", str(path), "/deny", f"{_sid_arg(sid)}:(RX,W,D,DC)"],
        check=True, capture_output=True,
    )


def remove_deny(path: Path, sid: str) -> bool:
    """
    Remove the deny ACE.  Returns True on success.
    If icacls fails (e.g. we're not the owner), attempts takeown first and retries.
    Silently skipped on non-NTFS volumes.
    """
    if not is_ntfs(path):
        return True

    def _try_remove() -> bool:
        result = subprocess.run(
            ["icacls", str(path), "/remove:d", _sid_arg(sid)],
            capture_output=True,
        )
        return result.returncode == 0

    if _try_remove():
        return True

    # Fallback: take ownership, then retry
    subprocess.run(["takeown", "/f", str(path)], capture_output=True)
    return _try_remove()

