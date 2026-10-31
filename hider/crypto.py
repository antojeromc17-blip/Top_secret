"""
Cryptographic primitives for HIDER.

Key model
─────────
One X25519 keypair is generated at first use and reused across all vaults.

  private_key.enc  =  FORMAT_VERSION(1) | salt(32) | nonce(12) | AESGCM(privkey_raw)(48)
                    =  93 bytes total
  public_key       =  raw 32-byte X25519 public key (no wrapping)

ECIES wire format
─────────────────
  FORMAT_VERSION(1) | eph_pub(32) | nonce(12) | ciphertext+tag(n+16)
  AAD = plaintext manifest header bytes (C4 fix: header bound to body).

Manifest file layout
────────────────────
  PLAINTEXT HEADER:
    HDR_VERSION(1) | pubkey(32) | privkey_enc_len(2 BE u16) | privkey_enc(N)
  ECIES BODY:  (rest of file; AAD = header bytes)
    ECIES wire format above

Notes
─────
- AESGCM returns ciphertext||tag combined (tag appended, not prepended).
- Private key bytes are zeroed immediately after use where possible.
- DPAPI uses CRYPTPROTECT_SENSITIVE to keep plaintext in non-pageable memory.
"""
from __future__ import annotations

import ctypes
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .wintypes_ext import (
    CRYPTPROTECT_SENSITIVE,
    DATA_BLOB,
    _crypt32,
    _k32,
)

# ── Format markers ─────────────────────────────────────────────────────────────
FORMAT_VERSION: bytes = b"\x01"   # private_key.enc and ECIES wire
HDR_VERSION:    bytes = b"\x01"   # manifest header

# ── Scrypt parameters ─────────────────────────────────────────────────────────
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1


# ─────────────────────────────── DPAPI ───────────────────────────────────────

def _make_blob(data: bytes) -> DATA_BLOB:
    arr = (ctypes.c_ubyte * len(data))(*data)
    return DATA_BLOB(cbData=len(data), pbData=arr)


def dpapi_protect(data: bytes) -> bytes:
    """Encrypt *data* with the current Windows user's DPAPI key (no prompt)."""
    blob_in  = _make_blob(data)
    blob_out = DATA_BLOB()
    if not _crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None,
        CRYPTPROTECT_SENSITIVE,         # keep plaintext in non-pageable memory
        ctypes.byref(blob_out),
    ):
        raise OSError(f"CryptProtectData failed: {ctypes.get_last_error()}")
    try:
        return bytes(blob_out.pbData[: blob_out.cbData])
    finally:
        # Fix W4: cast pbData to c_void_p before LocalFree
        _k32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def dpapi_unprotect(data: bytes) -> bytes:
    """Decrypt a DPAPI blob. Only works under the same Windows user account."""
    blob_in  = _make_blob(data)
    blob_out = DATA_BLOB()
    if not _crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0,
        ctypes.byref(blob_out),
    ):
        raise OSError(f"CryptUnprotectData failed: {ctypes.get_last_error()}")
    try:
        return bytes(blob_out.pbData[: blob_out.cbData])
    finally:
        _k32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


# ─────────────────────────── Passphrase → wrap key ───────────────────────────

def _derive_wrap_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt_privkey(privkey_raw: bytes, passphrase: str) -> bytes:
    """Return FORMAT_VERSION | salt(32) | nonce(12) | ct+tag(48)  = 93 bytes."""
    salt     = os.urandom(32)
    wrap_key = _derive_wrap_key(passphrase, salt)
    nonce    = os.urandom(12)
    ct_tag   = AESGCM(wrap_key).encrypt(nonce, privkey_raw, None)
    return FORMAT_VERSION + salt + nonce + ct_tag


def _decrypt_privkey(privkey_enc: bytes, passphrase: str) -> bytes:
    """Return the raw 32-byte X25519 private key."""
    if privkey_enc[:1] != FORMAT_VERSION:
        raise ValueError(f"Unknown private-key format version: {privkey_enc[0]:#x}")
    salt     = privkey_enc[1:33]
    nonce    = privkey_enc[33:45]
    ct_tag   = privkey_enc[45:]
    wrap_key = _derive_wrap_key(passphrase, salt)
    # InvalidTag is raised automatically by AESGCM on wrong passphrase
    return AESGCM(wrap_key).decrypt(nonce, ct_tag, None)


# ──────────────────────────── Keypair helpers ─────────────────────────────────

def generate_keypair(passphrase: str) -> tuple[bytes, bytes]:
    """
    Generate a fresh X25519 keypair.
    Returns *(pubkey_raw, privkey_enc)*.  Nothing is written to disk here.
    """
    privkey     = X25519PrivateKey.generate()
    pubkey_raw  = privkey.public_key().public_bytes_raw()
    privkey_raw = privkey.private_bytes_raw()
    try:
        privkey_enc = _encrypt_privkey(privkey_raw, passphrase)
    finally:
        # Zero the raw private key bytes in the buffer (best-effort in Python)
        ctypes.memset((ctypes.c_char * len(privkey_raw)).from_buffer_copy(privkey_raw), 0, len(privkey_raw))
    return pubkey_raw, privkey_enc


def unwrap_privkey(privkey_enc: bytes, passphrase: str) -> bytes:
    """
    Unwrap the passphrase-protected private key.
    Returns the raw 32-byte key.  Raises InvalidTag on wrong passphrase.
    """
    return _decrypt_privkey(privkey_enc, passphrase)


def reencrypt_privkey(privkey_enc: bytes, old_passphrase: str, new_passphrase: str) -> bytes:
    """Decrypt with old passphrase and re-encrypt with new passphrase."""
    raw = _decrypt_privkey(privkey_enc, old_passphrase)
    try:
        return _encrypt_privkey(raw, new_passphrase)
    finally:
        ctypes.memset((ctypes.c_char * len(raw)).from_buffer_copy(raw), 0, len(raw))


# ──────────────────────────────── ECIES ──────────────────────────────────────

def ecies_encrypt(recipient_pub_raw: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    Encrypt *plaintext* to *recipient_pub_raw* using ephemeral X25519 + HKDF-SHA256
    + AES-256-GCM.

    Wire format:  FORMAT_VERSION(1) | eph_pub(32) | nonce(12) | ct+tag(n+16)
    AAD: pass the plaintext manifest header bytes so the body is bound to the header.
         An empty *aad* is valid for non-manifest uses.
    HKDF info: eph_pub_raw || recipient_pub_raw  — both keys bound (C4/C8 fix).
    """
    eph_priv    = X25519PrivateKey.generate()
    eph_pub_raw = eph_priv.public_key().public_bytes_raw()
    shared      = eph_priv.exchange(X25519PublicKey.from_public_bytes(recipient_pub_raw))

    # Both public keys bound into HKDF info (fix from audit C4)
    info = eph_pub_raw + recipient_pub_raw
    key  = HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(shared)

    nonce  = os.urandom(12)
    # AESGCM.encrypt returns ciphertext||tag (tag appended, not prepended)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, aad if aad else None)

    return FORMAT_VERSION + eph_pub_raw + nonce + ct_tag


def ecies_decrypt(recipient_priv_raw: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """
    Inverse of *ecies_encrypt*.  *aad* must match exactly — raises InvalidTag on mismatch.
    """
    if ciphertext[:1] != FORMAT_VERSION:
        raise ValueError(f"Unknown ECIES format version: {ciphertext[0]:#x}")
    eph_pub_raw = ciphertext[1:33]
    nonce       = ciphertext[33:45]
    ct_tag      = ciphertext[45:]

    recipient_priv    = X25519PrivateKey.from_private_bytes(recipient_priv_raw)
    recipient_pub_raw = recipient_priv.public_key().public_bytes_raw()
    shared = recipient_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub_raw))

    info = eph_pub_raw + recipient_pub_raw
    key  = HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(shared)

    return AESGCM(key).decrypt(nonce, ct_tag, aad if aad else None)


# ────────────────────────── Manifest header I/O ──────────────────────────────

def build_manifest_header(pubkey_raw: bytes, privkey_enc: bytes) -> bytes:
    """
    HDR_VERSION(1) | pubkey_raw(32) | privkey_enc_len(2 BE u16) | privkey_enc(N)
    """
    return HDR_VERSION + pubkey_raw + struct.pack(">H", len(privkey_enc)) + privkey_enc


def parse_manifest_header(data: bytes) -> tuple[bytes, bytes, int]:
    """
    Parse the plaintext manifest header.
    Returns *(pubkey_raw, privkey_enc, header_length_in_bytes)*.
    Raises ValueError on bad version or truncation.
    """
    if len(data) < 35:
        raise ValueError("Manifest too short for header")
    if data[:1] != HDR_VERSION:
        raise ValueError(f"Unknown manifest header version: {data[0]:#x}")
    pubkey_raw  = data[1:33]
    enc_len     = struct.unpack(">H", data[33:35])[0]
    end         = 35 + enc_len
    if len(data) < end:
        raise ValueError("Manifest header truncated")
    return pubkey_raw, data[35:end], end


def encrypt_manifest(pubkey_raw: bytes, privkey_enc: bytes, body_json: bytes) -> bytes:
    """
    Build and return the complete manifest file bytes:
      header (plaintext) + ECIES body (with header as AAD).
    """
    header = build_manifest_header(pubkey_raw, privkey_enc)
    body   = ecies_encrypt(pubkey_raw, body_json, aad=header)   # AAD binds header to body
    return header + body


def decrypt_manifest(data: bytes, passphrase: str) -> tuple[bytes, bytes]:
    """
    Decrypt a manifest file.
    Returns *(body_json_bytes, pubkey_raw)*.
    Raises InvalidTag if the passphrase is wrong OR if the header was tampered with.
    """
    pubkey_raw, privkey_enc, hdr_len = parse_manifest_header(data)
    header      = data[:hdr_len]        # same bytes used as AAD during encryption
    body_ct     = data[hdr_len:]
    privkey_raw = _decrypt_privkey(privkey_enc, passphrase)
    try:
        body_json = ecies_decrypt(privkey_raw, body_ct, aad=header)
    finally:
        ctypes.memset((ctypes.c_char * len(privkey_raw)).from_buffer_copy(privkey_raw), 0, len(privkey_raw))
    return body_json, pubkey_raw

