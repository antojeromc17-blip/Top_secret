"""
Encrypted index of all hidden vaults.

The index is a single ECIES-encrypted JSON file at state_dir()/index.
It stores no original paths — only vault_id, file_count, hide_time.
Folder names come from decrypting each vault's manifest individually.

Schema (the plaintext JSON inside the ECIES blob):
  {"vaults": [
    {"vault_id": "<GUID>", "vault_root": "<path>", "file_count": 123,
     "hide_time": "2026-10-31T16:00:00Z"},
    ...
  ]}
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .crypto import ecies_encrypt, ecies_decrypt
from .state  import index_path, load_pubkey


# ── I/O ───────────────────────────────────────────────────────────────────────

def _load_raw(pubkey_raw: bytes, privkey_raw: bytes) -> dict:
    p = index_path()
    if not p.exists():
        return {"vaults": []}
    data = p.read_bytes()
    body = ecies_decrypt(privkey_raw, data)
    return json.loads(body)


def _save_raw(pubkey_raw: bytes, payload: dict) -> None:
    raw  = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    blob = ecies_encrypt(pubkey_raw, raw)
    tmp  = index_path().with_suffix(".tmp")
    tmp.write_bytes(blob)
    tmp.replace(index_path())       # atomic replace


# ── Public API ────────────────────────────────────────────────────────────────

def list_vaults(pubkey_raw: bytes, privkey_raw: bytes) -> list[dict]:
    """Return list of vault dicts."""
    return _load_raw(pubkey_raw, privkey_raw)["vaults"]


def append_vault(
    pubkey_raw: bytes,
    privkey_raw: bytes,
    vault_id:   str,
    vault_root: Path,
    file_count: int,
    hide_time:  str,
) -> None:
    payload = _load_raw(pubkey_raw, privkey_raw)
    # Avoid duplicates (idempotent; called from journal recovery)
    if not any(v["vault_id"] == vault_id for v in payload["vaults"]):
        payload["vaults"].append({
            "vault_id":   vault_id,
            "vault_root": str(vault_root),
            "file_count": file_count,
            "hide_time":  hide_time,
        })
        _save_raw(pubkey_raw, payload)


def ensure_vault_entry(
    pubkey_raw: bytes,
    privkey_raw: bytes,
    vault_id:   str,
    vault_root: Path,
) -> None:
    """
    Make sure *vault_id* appears in the index.  Used by journal recovery at
    'index' state so the entry is preserved, not removed.  (Fix C3.)
    """
    payload = _load_raw(pubkey_raw, privkey_raw)
    if not any(v["vault_id"] == vault_id for v in payload["vaults"]):
        # The hide completed but the index entry is missing; rebuild a minimal entry
        payload["vaults"].append({
            "vault_id":   vault_id,
            "vault_root": str(vault_root),
            "file_count": -1,       # unknown; user can see it via recover
            "hide_time":  "unknown",
        })
        _save_raw(pubkey_raw, payload)


def remove_vault(pubkey_raw: bytes, privkey_raw: bytes, vault_id: str) -> None:
    payload = _load_raw(pubkey_raw, privkey_raw)
    payload["vaults"] = [v for v in payload["vaults"] if v["vault_id"] != vault_id]
    _save_raw(pubkey_raw, payload)


def rebuild_index(pubkey_raw: bytes, privkey_raw: bytes, entries: list[dict]) -> None:
    """Overwrite the index with a fresh *entries* list (used by recover)."""
    _save_raw(pubkey_raw, {"vaults": entries})

