"""
State directory and vault root management.

State directory
───────────────
%LOCALAPPDATA%\\Microsoft\\CLR_v4.0\\UsageLogs\\
  public_key          — raw 32-byte X25519 public key (plaintext)
  private_key.enc     — FORMAT_VERSION | salt | nonce | ct+tag  (93 bytes)
  index               — ECIES-encrypted JSON index

Vault roots
───────────
  System drive : same as state_dir()
  Other drives : <DRIVE>:\\$WinREAgent\\

Both are created with Hidden+System on first use.

Process mutex
─────────────
A named Windows mutex prevents two simultaneous write operations from
corrupting the index.  Acquire it before any hide / unhide / change-passphrase
and release it when done.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .attrs import set_hidden_system
from .wintypes_ext import WAIT_OBJECT_0, WAIT_TIMEOUT, _k32

# ── Paths ─────────────────────────────────────────────────────────────────────

_STATE_SUBDIR = Path("Microsoft") / "CLR_v4.0" / "UsageLogs"
_MUTEX_NAME   = "Local\\HiderSingleInstance_v1"


def state_dir() -> Path:
    return Path(os.environ["LOCALAPPDATA"]) / _STATE_SUBDIR


def ensure_state_dir() -> Path:
    sd = state_dir()
    created = not sd.exists()
    sd.mkdir(parents=True, exist_ok=True)
    if created:
        set_hidden_system(sd)
    return sd


def vault_roots() -> list[Path]:
    """
    Return a list of vault-root Paths for all available drives.
    Does not create or check existence.
    """
    roots: list[Path] = [state_dir()]
    system_drive = os.environ.get("SystemDrive", "C:").upper().rstrip("\\")
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:"
        if drive.upper() == system_drive.upper():
            continue
        drive_root = Path(f"{drive}\\")
        if drive_root.exists():
            roots.append(Path(f"{drive}\\$WinREAgent"))
    return roots


def ensure_vault_root(vault_root: Path) -> None:
    """Create *vault_root* and mark it Hidden+System if it doesn't exist."""
    created = not vault_root.exists()
    vault_root.mkdir(parents=True, exist_ok=True)
    if created:
        set_hidden_system(vault_root)


def choose_vault_root(src: Path) -> Path:
    """
    Return the vault root on the same drive as *src*.
    Raises RuntimeError if no matching root can be determined.
    """
    src_drive = src.resolve().drive.upper()
    for root in vault_roots():
        if root.drive.upper() == src_drive:
            return root
    raise RuntimeError(
        f"No vault root found on drive {src_drive}. "
        "Ensure the drive letter is accessible."
    )


# ── Key files ─────────────────────────────────────────────────────────────────

def pubkey_path() -> Path:
    return state_dir() / "public_key"


def privkey_enc_path() -> Path:
    return state_dir() / "private_key.enc"


def index_path() -> Path:
    return state_dir() / "index"


def has_keypair() -> bool:
    return pubkey_path().exists() and privkey_enc_path().exists()


def load_pubkey() -> bytes:
    return pubkey_path().read_bytes()


def load_privkey_enc() -> bytes:
    return privkey_enc_path().read_bytes()


def save_keypair(pubkey_raw: bytes, privkey_enc: bytes) -> None:
    ensure_state_dir()
    pubkey_path().write_bytes(pubkey_raw)
    privkey_enc_path().write_bytes(privkey_enc)


# ── Process mutex ─────────────────────────────────────────────────────────────

_mutex_handle = None   # module-level so it stays alive


def acquire_mutex(timeout_ms: int = 5000) -> None:
    """
    Acquire the named single-instance mutex.
    Raises RuntimeError if another hider process is already running.
    """
    global _mutex_handle
    h = _k32.CreateMutexW(None, False, _MUTEX_NAME)
    if h is None or h == 0:
        raise RuntimeError(f"CreateMutexW failed: could not create process mutex")
    result = _k32.WaitForSingleObject(h, timeout_ms)
    if result == WAIT_TIMEOUT:
        raise RuntimeError(
            "Another hider operation is already running. "
            "Wait for it to finish before starting a new one."
        )
    _mutex_handle = h   # keep reference alive


def release_mutex() -> None:
    global _mutex_handle
    if _mutex_handle is not None:
        _k32.ReleaseMutex(_mutex_handle)
        _k32.CloseHandle(_mutex_handle)
        _mutex_handle = None


# ── Stealth installation & PATH registration ──────────────────────────────────

def get_stealth_install_dir() -> Path:
    return state_dir() / "Runtime"


def install_stealth() -> Path:
    """
    Copy runner scripts and hider package into the hidden system directory
    (%LOCALAPPDATA%\\Microsoft\\CLR_v4.0\\UsageLogs\\Runtime).
    """
    import shutil

    target = get_stealth_install_dir()
    target.mkdir(parents=True, exist_ok=True)
    try:
        set_hidden_system(target)
    except Exception:
        pass

    if getattr(sys, "frozen", False):
        exe_src = Path(sys.executable).resolve()
        shutil.copy2(exe_src, target / exe_src.name)
    else:
        pkg_src = Path(__file__).parent.resolve()
        repo_root = pkg_src.parent.resolve()

        # Copy hider package
        dst_pkg = target / "hider"
        shutil.copytree(pkg_src, dst_pkg, dirs_exist_ok=True)

        # Copy launcher scripts and main.py
        for name in ("main.py", "hider.cmd", "hider.bat", "hider.ps1"):
            src_file = repo_root / name
            if src_file.exists():
                shutil.copy2(src_file, target / name)

        # Provide stealth aliases
        for alias in ("clrmon.cmd", "sysdiag.cmd"):
            alias_path = target / alias
            if not alias_path.exists():
                alias_path.write_text("@echo off\npython \"%~dp0main.py\" %*\n", encoding="utf-8")

    return target


def add_to_user_path() -> None:
    """
    Deploy to stealth system directory and add that directory to HKCU\\Environment\\Path.
    Cleans up any visible repo/desktop paths from PATH.
    """
    import ctypes
    import winreg

    try:
        stealth_dir = install_stealth()
    except Exception:
        if getattr(sys, "frozen", False):
            stealth_dir = Path(sys.executable).parent.resolve()
        else:
            stealth_dir = Path(__file__).parent.parent.resolve()

    exe_dir = str(stealth_dir).rstrip("\\")

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, "Environment", 0,
        winreg.KEY_READ | winreg.KEY_WRITE,
    )
    try:
        try:
            current, _ = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current = ""

        entries = [e.strip() for e in current.split(";") if e.strip()]
        # Remove visible desktop / download entries that contain 'hider'
        cleaned = []
        for e in entries:
            low = e.lower()
            if ("desktop" in low or "download" in low) and "hider" in low:
                continue
            cleaned.append(e)

        if exe_dir.lower() not in [e.lower() for e in cleaned]:
            cleaned.append(exe_dir)

        new_path = ";".join(cleaned)
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
    finally:
        winreg.CloseKey(key)

    # Broadcast so open shells pick up the change without a logoff
    try:
        result = ctypes.c_ulong(0)
        _k32_user = ctypes.WinDLL("user32", use_last_error=True)
        _k32_user.SendMessageTimeoutW(
            0xFFFF, 0x001A, 0, "Environment", 2, 5000,
            ctypes.byref(result),
        )
    except Exception:
        pass

