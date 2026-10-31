"""
Encrypted index of all hidden vaults.

The index file at state_dir()/index stores a sequence of length-prefixed,
ECIES-encrypted JSON records. Each record stores:
  {"vault_id": "<GUID>", "vault_root": "<path>", "file_count": 123, "hide_time": "..."}

Because each record is independently encrypted to the recipient public key:
- hide ONLY needs pubkey_raw to append a new record — it never prompts for or needs the passphrase!
- list and unhide decrypt the records using privkey_raw (prompting for the passphrase).
- remove_vault reads all records with privkey_raw, filters out the removed vault, and rewrites the index.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

from .crypto import ecies_encrypt, ecies_decrypt
from .state  import index_path


def append_vault(
    pubkey_raw: bytes,
    vault_id:   str,
    vault_root: Path,
    file_count: int,
    hide_time:  str,
) -> None:
    """Encrypt and append a new vault record to index_path() without needing privkey."""
    record_dict = {
        "vault_id":   vault_id,
        "vault_root": str(vault_root),
        "file_count": file_count,
        "hide_time":  hide_time,
    }
    raw  = json.dumps(record_dict, ensure_ascii=False).encode("utf-8")
    blob = ecies_encrypt(pubkey_raw, raw)
    entry = struct.pack(">I", len(blob)) + blob

    p = index_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "ab") as f:
        f.write(entry)
        f.flush()


def list_vaults(pubkey_raw: bytes, privkey_raw: bytes) -> list[dict]:
    """Read and decrypt all vault records in index_path()."""
    p = index_path()
    if not p.exists():
        return []

    data   = p.read_bytes()
    offset = 0
    vaults = []
    seen   = set()

    while offset + 4 <= len(data):
        rec_len, = struct.unpack(">I", data[offset:offset + 4])
        offset += 4
        if offset + rec_len > len(data):
            break   # truncated or incomplete record
        blob = data[offset:offset + rec_len]
        offset += rec_len
        try:
            plain = ecies_decrypt(privkey_raw, blob)
            v = json.loads(plain)
            vid = v.get("vault_id")
            if vid and vid not in seen:
                seen.add(vid)
                vaults.append(v)
        except Exception:
            continue

    return vaults


def remove_vault(pubkey_raw: bytes, privkey_raw: bytes, vault_id: str) -> None:
    """Remove vault_id from the index and rewrite remaining records."""
    vaults = list_vaults(pubkey_raw, privkey_raw)
    remaining = [v for v in vaults if v["vault_id"] != vault_id]
    rebuild_index(pubkey_raw, privkey_raw, remaining)


def rebuild_index(pubkey_raw: bytes, privkey_raw: bytes, entries: list[dict]) -> None:
    """Rewrite the entire index with length-prefixed records."""
    p = index_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with open(tmp, "wb") as f:
        for v in entries:
            raw  = json.dumps(v, ensure_ascii=False).encode("utf-8")
            blob = ecies_encrypt(pubkey_raw, raw)
            f.write(struct.pack(">I", len(blob)) + blob)
        f.flush()
    tmp.replace(p)
