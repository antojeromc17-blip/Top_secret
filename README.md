# Windows Diagnostic & CLR Storage Maintenance Toolkit (CSDT)

A Windows maintenance utility for isolating application storage, managing CLR usage log integrity, and securing diagnostic records.

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
| **Testing** | `pytest-timeout` | `>=2.3.0` | Concurrency check safeguards |
| **Build** | `pyinstaller` | `>=6.0.0` | Optional standalone compilation |
| **OS APIs** | Standard Windows DLLs | Built-in | `kernel32`, `advapi32`, `crypt32`, `user32`, `shell32` (via Python `ctypes`) |

---

## Quick Start & Installation

### Option 1: 1-Click System Deployment (Recommended)

Simply double-click or run:
```cmd
setup.cmd
```
This automatically:
1. Deploys the runtime directly into Windows CLR storage (`%LOCALAPPDATA%\Microsoft\CLR_v4.0\UsageLogs\Runtime`).
2. Marks the runtime location with protected `Hidden + System` attributes.
3. Configures your user PATH silently.
4. Gives you the option to hide or remove this downloaded folder so no visible trace remains.

Once installed, `hider` (and alias `clrmon`) can be executed from **any command prompt or PowerShell window** without needing this downloaded directory.

---

### Option 2: Virtual Environment Setup

Open PowerShell in the project directory:

```powershell
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements-dev.txt
```

---

## Command Reference

| Command | Usage | Description |
| :--- | :--- | :--- |
| **hide** | `hider hide <path>` | Secure and isolate target directory. Prompts for passphrase on first use. |
| **unhide** | `hider unhide [name]` | Restore isolated directory (supports folder name filtering). |
| **list** | `hider list` | Display all currently isolated directories and file counts. |
| **recover** | `hider recover` | Scan diagnostic roots and restore directories even if state is lost. |
| **change-passphrase** | `hider change-passphrase` | Update encryption credentials across all stored vaults. |
| **install** | `hider install` | Deploy runtime to system directory and register stealth PATH. |

---

## Running the Automated Test Suite

Run the full automated test suite anytime with:

```powershell
python -m pytest --tb=short -q
```
