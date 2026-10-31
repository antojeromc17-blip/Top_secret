"""
Core vault operations: hide, unhide, list, recover, change_passphrase.

Hide order (all fixes applied)
───────────────────────────────
 1. preflight            — abort on any problem; nothing modified
 2. auto-setup           — generate keypair on first run (scan existing manifests first)
 3. ensure vault root    — create + Hidden|System if needed
 4. build tree           — capture original_attrs; exclude manifest.dat
 5. write hide journal   — DPAPI, vault_root level, before any rename
 6. write manifest.dat   — INTO src folder (plaintext header + ECIES body)
                           manifest excluded from rename walk
 7. set NOT_CONTENT_INDEXED on src
 8. rename children      — post-order, children before parents (root excluded — fix C1)
 9. move root folder     — os.rename(src, vault_root/GUID)
10. set Hidden|System    — on vault_root/GUID (read-modify-write)
11. apply deny ACL       — top folder only, no (OI)(CI), skip on non-NTFS
12. trace cleanup        — best-effort, never aborts
13. append index entry
14. delete journals      — phase = done then delete

Unhide order
────────────
 1. recover_all          — silent DPAPI recovery
 2. prompt passphrase    — unwrap private key
 3. decrypt all manifests
 4. filter / menu
 5. for each vault:
    a. write unhide journal at vault_root level (fix C2)
    b. remove deny ACL
    c. restore original_attrs on all children (NOT root — fix S2)
    d. determine dest
    e. os.rename(vault_root/GUID, dest)
    f. restore original_attrs on root (after move — fix S2)
    g. rename children back  (pre-order — fix C1)
    h. clear NOT_CONTENT_INDEXED on dest
    i. delete manifest.dat from dest  (fix C10: journal.dat is NOT here)
    j. remove index entry
    k. delete unhide journal
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .acl     import apply_deny, current_user_sid, remove_deny
from .attrs   import (
    add_attrs, clear_not_content_indexed,
    get_attrs, restore_attrs, set_hidden_system, set_not_content_indexed,
)
from .crypto  import (
    decrypt_manifest, encrypt_manifest,
    generate_keypair, unwrap_privkey, reencrypt_privkey,
    parse_manifest_header,
)
from .index   import (
    append_vault, ensure_vault_entry, list_vaults,
    rebuild_index, remove_vault,
)
from .journal import (
    delete_hide_journal, delete_unhide_journal,
    recover_all, update_hide_phase, update_unhide_phase,
    write_hide_journal, write_unhide_journal,
)
from .preflight import PreflightError, preflight
from .state   import (
    acquire_mutex, choose_vault_root, ensure_state_dir,
    ensure_vault_root, has_keypair, load_privkey_enc,
    load_pubkey, release_mutex, save_keypair,
)
from .trace   import clean_traces
from .tree    import Node, build_tree, rename_hide, rename_unhide, rollback_hide_renames

MANIFEST_NAME = "manifest.dat"
_EXCLUDE      = {MANIFEST_NAME}


def _w(path: Path) -> str:
    return "\\\\?\\" + str(path.resolve())


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────── Setup / keypair ──────────────────────────────────

def _scan_for_existing_keypair(passphrase: str) -> tuple[bytes, bytes] | None:
    """
    Scan all vault roots for an existing manifest header.
    If found, attempt to unwrap privkey_enc using *passphrase*.
    Returns (pubkey_raw, privkey_enc) on success, None if not found.
    (Fix from §7: reuse keypair instead of generating a new one.)
    """
    from .state import vault_roots
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    for vault_root in vault_roots():
        if not vault_root.exists():    # fix L6: guard iterdir()
            continue
        for guid_dir in vault_root.iterdir():
            if not guid_dir.is_dir():
                continue
            mf = guid_dir / MANIFEST_NAME
            if not mf.exists():
                continue
            try:
                data = mf.read_bytes()
                pubkey_raw, privkey_enc, _ = parse_manifest_header(data)
                # Try to unwrap — raises on wrong passphrase
                unwrap_privkey(privkey_enc, passphrase)
                return pubkey_raw, privkey_enc
            except Exception:
                continue
    return None


def ensure_keypair(passphrase: str) -> tuple[bytes, bytes]:
    """
    Return (pubkey_raw, privkey_enc).
    Uses existing keys if available; scans manifests if state dir is missing;
    generates fresh keys only as a last resort.
    """
    if has_keypair():
        return load_pubkey(), load_privkey_enc()

    existing = _scan_for_existing_keypair(passphrase)
    if existing:
        pubkey_raw, privkey_enc = existing
        save_keypair(pubkey_raw, privkey_enc)
        # Rebuild the index from all manifests
        privkey_raw = unwrap_privkey(privkey_enc, passphrase)
        _rebuild_index_from_vaults(pubkey_raw, privkey_raw, passphrase)
        return pubkey_raw, privkey_enc

    pubkey_raw, privkey_enc = generate_keypair(passphrase)
    ensure_state_dir()
    save_keypair(pubkey_raw, privkey_enc)
    return pubkey_raw, privkey_enc


def _rebuild_index_from_vaults(pubkey_raw: bytes, privkey_raw: bytes, passphrase: str) -> None:
    """Scan all vault roots; rebuild the encrypted index from manifest headers."""
    from .state import vault_roots
    entries = []
    for vault_root in vault_roots():
        if not vault_root.exists():
            continue
        for guid_dir in vault_root.iterdir():
            if not guid_dir.is_dir():
                continue
            mf = guid_dir / MANIFEST_NAME
            if not mf.exists():
                continue
            try:
                data      = mf.read_bytes()
                body_json, _ = decrypt_manifest(data, passphrase)
                body      = json.loads(body_json)
                root_node = Node.from_dict(body["root"])
                entries.append({
                    "vault_id":   body["vault_id"],
                    "vault_root": str(vault_root),
                    "file_count": _count_nodes(root_node),
                    "hide_time":  body.get("hide_time", "unknown"),
                })
            except Exception:
                continue
    rebuild_index(pubkey_raw, privkey_raw, entries)


def _count_nodes(root: Node) -> int:
    count = 0
    def _walk(n: Node) -> None:
        nonlocal count
        count += 1
        for c in n.children:
            _walk(c)
    for child in root.children:
        _walk(child)
    return count


# ─────────────────────────────── HIDE ────────────────────────────────────────

def hide(src_path: Path, passphrase_fn) -> None:
    """
    Hide the folder at *src_path*.
    *passphrase_fn* is called at most once (on first run to generate the keypair).
    Raises PreflightError on any pre-flight failure.
    """
    src = src_path.resolve()

    # Step 1: choose vault root for this drive
    vault_root = choose_vault_root(src)

    # Run auto-recovery on any interrupted previous operation
    recover_all(vault_root)

    # Step 1: pre-flight (abort on any issue — nothing modified yet)
    preflight(src, vault_root)

    # Step 2: keypair setup (auto, at most one prompt ever)
    if not has_keypair():
        passphrase = passphrase_fn()
        pubkey_raw, privkey_enc = ensure_keypair(passphrase)
    else:
        pubkey_raw  = load_pubkey()
        privkey_enc = load_privkey_enc()

    acquire_mutex()
    try:
        _do_hide(src, vault_root, pubkey_raw, privkey_enc)
    finally:
        release_mutex()


def _do_hide(src: Path, vault_root: Path, pubkey_raw: bytes, privkey_enc: bytes) -> None:
    from .attrs import get_attrs as _get_attrs

    # Step 3: ensure vault root exists and is hidden
    ensure_vault_root(vault_root)

    # Generate vault GUID
    guid = str(uuid.uuid4())

    # Step 4: build tree, capture attrs, exclude manifest.dat
    def _name_gen() -> str:
        return str(uuid.uuid4())

    root = build_tree(src, guild := guid, _name_gen, _get_attrs, _EXCLUDE)

    file_count = _count_nodes(root)
    hide_time  = _now_iso()

    # Step 5: write DPAPI journal (at vault_root level)
    write_hide_journal(vault_root, guid, src, root)

    # Step 6: write manifest.dat INTO src folder (excluded from rename walk)
    body_json = json.dumps({
        "vault_id":  guid,
        "src_path":  str(src),
        "hide_time": hide_time,
        "root":      root.to_dict(),
    }, ensure_ascii=False).encode("utf-8")
    manifest_bytes = encrypt_manifest(pubkey_raw, privkey_enc, body_json)
    manifest_path  = src / MANIFEST_NAME
    manifest_path.write_bytes(manifest_bytes)
    manifest_path_tmp = src / (MANIFEST_NAME + ".tmp")
    # Write via tmp for safety
    manifest_path_tmp.write_bytes(manifest_bytes)
    manifest_path_tmp.replace(manifest_path)

    # Step 7: NOT_CONTENT_INDEXED on src
    try:
        set_not_content_indexed(src)
    except OSError:
        pass

    # Step 8: rename children, post-order (root excluded — fix C1)
    try:
        rename_hide(root, src)
    except Exception as exc:
        rollback_hide_renames(root, src)
        manifest_path.unlink(missing_ok=True)
        delete_hide_journal(vault_root, guid)
        raise RuntimeError(f"Rename failed; rolled back. Cause: {exc}") from exc

    update_hide_phase(vault_root, guid, "renames")

    # Step 9: move root folder → vault_root/GUID
    guid_dir = vault_root / guid
    try:
        os.rename(_w(src), _w(guid_dir))
    except Exception as exc:
        rollback_hide_renames(root, src)
        manifest_path.unlink(missing_ok=True)
        delete_hide_journal(vault_root, guid)
        raise RuntimeError(f"Move failed; rolled back. Cause: {exc}") from exc

    update_hide_phase(vault_root, guid, "moved")

    # Step 10: Hidden|System on vault_root/GUID (read-modify-write)
    try:
        set_hidden_system(guid_dir)
    except OSError:
        pass

    update_hide_phase(vault_root, guid, "attrs")

    # Step 11: deny ACL (top folder only, no inheritance)
    try:
        sid = current_user_sid()
        apply_deny(guid_dir, sid)
    except Exception:
        pass  # non-NTFS or icacls not available — not fatal

    update_hide_phase(vault_root, guid, "acl")

    # Step 12: trace cleanup (best-effort)
    clean_traces(root)

    # Step 13: append to index
    privkey_raw = None  # don't need it for index write (uses pubkey only)
    append_vault(
        pubkey_raw, _dummy_privkey(),
        guid, vault_root, file_count, hide_time,
    )

    update_hide_phase(vault_root, guid, "index")

    # Step 14: delete journals
    delete_hide_journal(vault_root, guid)


def _dummy_privkey() -> bytes:
    # append_vault only needs pubkey (encrypt path); privkey not used there
    # We pass a zero key — index.py _load_raw is not called during append
    return b"\x00" * 32


# ─────────────────────────────── UNHIDE ──────────────────────────────────────

def unhide(passphrase: str, text_filter: str | None = None) -> int:
    """
    Unhide all vaults (or those matching *text_filter* in their folder name).
    Returns the number of vaults restored.
    """
    from .state import vault_roots as _vault_roots

    privkey_enc = load_privkey_enc()
    privkey_raw = unwrap_privkey(privkey_enc, passphrase)
    pubkey_raw  = load_pubkey()

    # Auto-recovery on all vault roots
    for vr in _vault_roots():
        recover_all(vr)

    acquire_mutex()
    try:
        return _do_unhide(pubkey_raw, privkey_raw, privkey_enc, passphrase, text_filter)
    finally:
        release_mutex()


def _do_unhide(
    pubkey_raw:  bytes,
    privkey_raw: bytes,
    privkey_enc: bytes,
    passphrase:  str,
    text_filter: str | None,
) -> int:
    from .state import vault_roots as _vault_roots

    vaults = list_vaults(pubkey_raw, privkey_raw)
    if not vaults:
        print("No hidden vaults found.")
        return 0

    # Decrypt each manifest to get original folder name
    candidates = []
    for entry in vaults:
        vault_root = Path(entry["vault_root"])
        guid       = entry["vault_id"]
        guid_dir   = vault_root / guid
        mf         = guid_dir / MANIFEST_NAME
        if not mf.exists():
            continue
        try:
            body_json, _ = decrypt_manifest(mf.read_bytes(), passphrase)
            body         = json.loads(body_json)
            root_node    = Node.from_dict(body["root"])
            src_path     = Path(body["src_path"])
            folder_name  = src_path.name
        except Exception:
            continue

        if text_filter and text_filter.lower() not in folder_name.lower():
            continue

        candidates.append((entry, root_node, src_path, vault_root, guid))

    if not candidates:
        print("No matching vaults found.")
        return 0

    # Menu if multiple
    if len(candidates) > 1:
        print("\nMatching vaults:")
        for i, (entry, _, src_path, _, _) in enumerate(candidates):
            print(f"  [{i+1}] {src_path.name}  ({entry['file_count']} files, hidden {entry['hide_time']})")
        choice = input("\nRestore which? [number / 'all']: ").strip().lower()
        if choice == "all":
            selected = candidates
        else:
            try:
                idx = int(choice) - 1
                selected = [candidates[idx]]
            except (ValueError, IndexError):
                print("Invalid choice.")
                return 0
    else:
        selected = candidates

    count = 0
    for entry, root_node, src_path, vault_root, guid in selected:
        _restore_vault(pubkey_raw, privkey_raw, entry, root_node, src_path, vault_root, guid, passphrase)
        count += 1
    return count


def _restore_vault(
    pubkey_raw:  bytes,
    privkey_raw: bytes,
    entry:       dict,
    root_node:   Node,
    src_path:    Path,
    vault_root:  Path,
    guid:        str,
    passphrase:  str,
) -> None:
    guid_dir = vault_root / guid

    # Step 5a: write unhide journal at vault_root level (fix C2)
    write_unhide_journal(vault_root, guid, src_path, root_node)

    # Step 5b: remove deny ACL
    try:
        sid = current_user_sid()
        remove_deny(guid_dir, sid)
    except Exception:
        pass
    update_unhide_phase(vault_root, guid, "acl_removed")

    # Step 5c: restore original_attrs on all CHILDREN (not root — fix S2)
    #          Root attrs restored AFTER the move (fix S2)
    def _restore_children_attrs(node: Node, parent: Path) -> None:
        for child in node.children:
            child_path = parent / child.random_name
            if child_path.exists():
                try:
                    restore_attrs(child_path, child.original_attrs)
                except OSError:
                    pass
            if child.is_dir:
                _restore_children_attrs(child, child_path)

    _restore_children_attrs(root_node, guid_dir)
    update_unhide_phase(vault_root, guid, "attrs_restored")

    # Step 5d: determine destination
    dest = src_path
    if dest.exists():
        dest = src_path.parent / (src_path.name + " (restored)")

    # Step 5e: move folder back
    try:
        os.rename(_w(guid_dir), _w(dest))
    except Exception as exc:
        # Rollback: re-apply ACL
        try:
            apply_deny(guid_dir, current_user_sid())
        except Exception:
            pass
        delete_unhide_journal(vault_root, guid)
        raise RuntimeError(f"Move back failed: {exc}") from exc

    update_unhide_phase(vault_root, guid, "moved_back")

    # Step 5f: restore root folder's original_attrs AFTER the move (fix S2)
    try:
        restore_attrs(dest, root_node.original_attrs)
    except OSError:
        pass

    # Step 5g: rename children back, pre-order (parents before children)
    try:
        rename_unhide(root_node, dest)
    except Exception as exc:
        # Rollback: reverse renames, move back, re-apply ACL
        rollback_hide_renames(root_node, dest)   # use hide-rollback in reverse
        try:
            os.rename(_w(dest), _w(guid_dir))
            apply_deny(guid_dir, current_user_sid())
        except Exception:
            pass
        delete_unhide_journal(vault_root, guid)
        raise RuntimeError(f"Rename restore failed; rolled back. Cause: {exc}") from exc

    # Step 5h: clear NOT_CONTENT_INDEXED
    try:
        clear_not_content_indexed(dest)
    except OSError:
        pass

    # Step 5i: delete manifest.dat from dest (fix C10: journal.dat NOT deleted here)
    #          manifest.dat moved with the folder at step 5e
    (dest / MANIFEST_NAME).unlink(missing_ok=True)

    # Step 5j: remove index entry
    remove_vault(pubkey_raw, privkey_raw, guid)

    # Step 5k: delete unhide journal
    delete_unhide_journal(vault_root, guid)

    print(f"Restored: {dest}")


# ─────────────────────────────── LIST ────────────────────────────────────────

def list_vaults_cmd(passphrase: str) -> None:
    """Print a table of all hidden vaults (decrypts each manifest for the folder name)."""
    from .state import vault_roots as _vault_roots

    privkey_enc = load_privkey_enc()
    privkey_raw = unwrap_privkey(privkey_enc, passphrase)
    pubkey_raw  = load_pubkey()

    vaults = list_vaults(pubkey_raw, privkey_raw)
    if not vaults:
        print("No hidden vaults.")
        return

    print(f"\n{'GUID':36}  {'Folder':20}  {'Files':>7}  Hidden at")
    print("-" * 80)
    for v in vaults:
        vault_root = Path(v["vault_root"])
        guid       = v["vault_id"]
        guid_dir   = vault_root / guid
        mf         = guid_dir / MANIFEST_NAME
        folder_name = "?"
        if mf.exists():
            try:
                # Temporarily remove ACL to read manifest
                sid = current_user_sid()
                remove_deny(guid_dir, sid)
                body_json, _ = decrypt_manifest(mf.read_bytes(), passphrase)
                body = json.loads(body_json)
                folder_name = Path(body["src_path"]).name
                apply_deny(guid_dir, sid)
            except Exception:
                try:
                    apply_deny(guid_dir, current_user_sid())
                except Exception:
                    pass

        print(f"{guid:36}  {folder_name:20}  {v['file_count']:>7}  {v['hide_time']}")


# ─────────────────────────────── RECOVER ─────────────────────────────────────

def recover_cmd(passphrase: str) -> None:
    """
    Scan all vault roots for readable manifests.
    Works even if the state directory has been deleted.
    Rebuilds state dir and index after recovery.
    """
    from .state import vault_roots as _vault_roots

    # Auto-recovery of interrupted operations first
    for vr in _vault_roots():
        recover_all(vr)

    # Try to find a keypair from manifests if state dir is gone
    pubkey_raw, privkey_enc = ensure_keypair(passphrase)
    privkey_raw = unwrap_privkey(privkey_enc, passphrase)

    # Scan for all readable manifests
    candidates = []
    for vault_root in _vault_roots():
        if not vault_root.exists():
            continue
        for guid_dir in vault_root.iterdir():
            if not guid_dir.is_dir():
                continue
            mf = guid_dir / MANIFEST_NAME

            sid = None
            try:
                sid = current_user_sid()
                remove_deny(guid_dir, sid)
            except Exception:
                pass

            try:
                if not mf.exists():
                    continue
                data         = mf.read_bytes()
                body_json, _ = decrypt_manifest(data, passphrase)
                body         = json.loads(body_json)
                candidates.append((vault_root, guid_dir.name, body, root := Node.from_dict(body["root"])))
            except Exception:
                pass
            finally:
                if sid:
                    try:
                        apply_deny(guid_dir, sid)
                    except Exception:
                        pass

    if not candidates:
        print("No readable vaults found.")
        return

    print(f"\n{'#':>3}  {'Folder':25}  Files  Hidden at")
    print("-" * 60)
    for i, (vault_root, guid, body, root) in enumerate(candidates):
        folder_name = Path(body["src_path"]).name
        print(f"  {i+1:>2}  {folder_name:25}  {_count_nodes(root):>5}  {body.get('hide_time','?')}")

    choice = input("\nRestore which? [number / 'all' / Enter to cancel]: ").strip().lower()
    if not choice:
        return

    to_restore = candidates if choice == "all" else []
    if choice != "all":
        try:
            idx = int(choice) - 1
            to_restore = [candidates[idx]]
        except (ValueError, IndexError):
            print("Invalid choice.")
            return

    acquire_mutex()
    try:
        for vault_root, guid, body, root in to_restore:
            entry = {
                "vault_id":   guid,
                "vault_root": str(vault_root),
                "file_count": _count_nodes(root),
                "hide_time":  body.get("hide_time", "?"),
            }
            _restore_vault(
                pubkey_raw, privkey_raw, entry, root,
                Path(body["src_path"]), vault_root, guid, passphrase,
            )
    finally:
        release_mutex()

    # Rebuild state dir keys and index
    save_keypair(pubkey_raw, privkey_enc)
    _rebuild_index_from_vaults(pubkey_raw, privkey_raw, passphrase)


# ─────────────────────── CHANGE PASSPHRASE ────────────────────────────────────

def change_passphrase(old_passphrase: str, new_passphrase: str) -> None:
    """
    Re-encrypt the private key with *new_passphrase* and update the header in
    every vault manifest.  Each manifest write is atomic (tmp→rename — fix C5).
    The deny ACL is removed before writing and restored after.
    """
    from .state import vault_roots as _vault_roots

    privkey_enc_old = load_privkey_enc()
    privkey_enc_new = reencrypt_privkey(privkey_enc_old, old_passphrase, new_passphrase)

    privkey_raw = unwrap_privkey(privkey_enc_old, old_passphrase)
    pubkey_raw  = load_pubkey()

    acquire_mutex()
    try:
        # Update state dir
        save_keypair(pubkey_raw, privkey_enc_new)

        # Update every vault manifest
        sid = current_user_sid()
        for vault_root in _vault_roots():
            if not vault_root.exists():
                continue
            for guid_dir in vault_root.iterdir():
                if not guid_dir.is_dir():
                    continue
                mf = guid_dir / MANIFEST_NAME
                if not mf.exists():
                    continue

                acl_removed = False
                try:
                    remove_deny(guid_dir, sid)
                    acl_removed = True

                    data = mf.read_bytes()
                    _, _, hdr_len = parse_manifest_header(data)
                    ecies_body = data[hdr_len:]

                    # Rebuild header with new privkey_enc; ECIES body unchanged
                    new_header = __import__(
                        "hider.crypto", fromlist=["build_manifest_header"]
                    ).build_manifest_header(pubkey_raw, privkey_enc_new)
                    new_data = new_header + ecies_body

                    # Atomic write (fix C5: tmp → rename, then restore ACL)
                    tmp = mf.with_suffix(".tmp")
                    tmp.write_bytes(new_data)
                    tmp.replace(mf)

                except Exception as exc:
                    print(f"Warning: could not update manifest in {guid_dir}: {exc}")
                finally:
                    if acl_removed:
                        try:
                            apply_deny(guid_dir, sid)
                        except Exception:
                            pass
    finally:
        release_mutex()

    print("Passphrase changed successfully.")

