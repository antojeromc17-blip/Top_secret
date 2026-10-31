# HIDER

HIDER is a Windows utility that hides folders so they leave no visible trace, directions, or plaintext metadata on disk.

## Security & Architectural Design

1. **Key Model**:
   - At first run (`hider hide <folder>`), HIDER generates an X25519 keypair.
   - The public key is stored in the local state directory (`%LOCALAPPDATA%\Microsoft\CLR_v4.0\UsageLogs`).
   - The private key is encrypted using `scrypt` (memory-hard KDF) + `AES-256-GCM` with a user passphrase.
   - `hide` uses the public key (ECIES: X25519 + HKDF-SHA256 + AES-256-GCM) and **never prompts for a passphrase** after initial setup.
   - `unhide`, `list`, `recover`, and `change-passphrase` prompt for the passphrase to decrypt.

2. **No Plaintext Leaks**:
   - All filenames and folder names inside hidden vaults are randomized to UUIDs.
   - Original directory structure and filenames are encrypted inside `manifest.dat` using ECIES with the plaintext header bound as AAD.
   - Plaintext manifest headers contain an encrypted copy of the private key (`privkey_enc`), allowing full vault recovery even if `%LOCALAPPDATA%` is wiped.
   - The index stores no plaintext original paths.

3. **Crash Safety & Idempotent Journal**:
   - Interrupted hides and unhides are recorded in a DPAPI-protected journal (`journal-<GUID>.dat`) at the vault root level.
   - Separate `.state` file tracks phases (`start`, `renames`, `moved`, `attrs`, `acl`, `index`, `done`).
   - Silent auto-recovery probes which files exist and resumes or rolls back safely at the beginning of every command without requiring a passphrase.

4. **Stealth & Permissions**:
   - Vault roots: `%LOCALAPPDATA%\Microsoft\CLR_v4.0\UsageLogs` on the system drive and `<Drive>:\$WinREAgent` on other drives.
   - Marked `Hidden | System` and `NOT_CONTENT_INDEXED`.
   - Deny ACL (`(RX,W,D,DC)`) applied to top-level vault folder only (no `(OI)(CI)` inheritance overhead). Skipped on non-NTFS volumes.
   - Trace cleanup automatically purges matching Recent `.lnk` files and thumbnail caches.

## Usage

```bash
# Hide a directory (asks for passphrase on very first run to initialize keys)
hider hide "C:\Users\Username\SecretFolder"

# Unhide vaults (prompts for passphrase; optionally filter by folder name)
hider unhide
hider unhide SecretFolder

# List all hidden vaults with decrypted folder names
hider list

# Recover vaults after index or profile wipe
hider recover

# Change the encryption passphrase across all vaults
hider change-passphrase
```

## Running Tests

```bash
pytest --tb=short -q
```

