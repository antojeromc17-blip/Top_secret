# HIDER (bro)

HIDER is a Windows utility that hides folders so they leave no visible trace, directions, or plaintext metadata on disk.

---

## Prerequisites & Dependencies

### Operating System & Environment
- **OS**: Windows 10 or Windows 11 (NTFS volume recommended for full ACL protection)
- **Python**: Version `3.11` or newer (tested on Python 3.11, 3.12, 3.13)

### Dependencies Breakdown

| Component | Package | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Runtime** | `cryptography` | `>=42.0.0` | X25519 ECIES, AES-256-GCM, HKDF, and Scrypt KDF |
| **Runtime** | `typer` | `>=0.12.0` | CLI command-line interface & argument parsing |
| **Testing** | `pytest` | `>=8.0.0` | Automated test runner (unit & integration tests) |
| **Testing** | `pytest-timeout` | `>=2.3.0` | Prevents test hangs on lock or concurrency checks |
| **Build** | `pyinstaller` | `>=6.0.0` | Compiles the standalone `.exe` and onedir release bundle |
| **OS APIs** | Standard Windows DLLs | Built-in | `kernel32`, `advapi32`, `crypt32`, `user32`, `shell32` (via Python `ctypes`) |

> **Note:** No external C/C++ compiler or Windows SDK is required. All Win32 APIs (DPAPI, ACLs, file locks, long paths) are invoked directly through Python's standard `ctypes` library with fully typed signatures.

---

## Quick Start: Virtual Environment Setup

### 1. Create and Activate a Virtual Environment

Open PowerShell in the project directory:

```powershell
# Create a fresh virtual environment
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1
```

*(If PowerShell blocks script execution, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

### 2. Install Dependencies

You can install dependencies using either method:

#### Option A: Using `requirements-dev.txt` (Recommended)
```powershell
pip install -r requirements-dev.txt
```

#### Option B: Using `pyproject.toml`
```powershell
pip install -e ".[dev]"
```

*(For minimal runtime only without tests/compiler: `pip install -r requirements.txt`)*

---

## Running the Automated Test Suite

To run all 53 automated tests:

```powershell
pytest --tb=short -v
```

The test suite covers:
- **Crypto & ECIES**: Round-trip encryption, AAD integrity validation, version byte checking, tampering detection.
- **Attributes**: Read-modify-write preservation of archive, read-only, and system flags, plus `NOT_CONTENT_INDEXED`.
- **Preflight & Locks**: Sharing violations (DELETE access with `FILE_SHARE_ALL`), OneDrive/cloud recall attribute detection, reparse point detection.
- **Vault Operations**: Round-trip hiding/unhiding, verifying zero `IMG_` or `.jpg` plaintext leaks on disk, `\\?\` long paths (>260 characters), Unicode & CJK filenames, empty folders, and restored-name collision fallbacks.
- **ACLs**: Validating that deny ACE is applied only to the vault folder without child inheritance, plus non-NTFS volume handling.
- **Crash Recovery**: Idempotent DPAPI journal rollback during renames, recovery after folder move, recovery with missing index, and recovery after state directory deletion.
- **Trace Cleanup**: Automated removal of matching `.lnk` shortcuts in Recent and jump lists in `AutomaticDestinations` / `CustomDestinations`.

---

## Usage Commands

Once installed or running from this folder, you can use the `bro` command:

```powershell
# 1. Hide a folder (asks for passphrase once on initial run):
bro hide "C:\Users\Username\Desktop\MySecretPhotos"

# 2. Unhide vaults (restores original folder name, files, and attributes):
bro unhide
# Or unhide a specific folder matching text:
bro unhide MySecretPhotos

# 3. List all currently hidden vaults:
bro list

# 4. Change secret key / passphrase across all vaults:
bro change-key

# 5. Emergency recover (scans drives even if local app data was wiped):
bro recover
```

---

## Building Standalone Binaries (PyInstaller)

To compile self-contained Windows distributions:

```powershell
# Build onedir release (recommended — faster startup, minimal AV false positives):
pyinstaller --onedir --name bro main.py

# Build single-file executable:
pyinstaller --onefile --name bro_onefile main.py
```

Outputs will be placed in the `dist/` directory.
