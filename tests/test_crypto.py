"""Tests for crypto.py — ECIES, DPAPI, scrypt, manifest header."""
from __future__ import annotations

import os
import pytest
from cryptography.exceptions import InvalidTag

from hider.crypto import (
    FORMAT_VERSION, HDR_VERSION,
    build_manifest_header, parse_manifest_header,
    decrypt_manifest, encrypt_manifest,
    dpapi_protect, dpapi_unprotect,
    ecies_decrypt, ecies_encrypt,
    generate_keypair, unwrap_privkey, reencrypt_privkey,
)


# ── DPAPI ─────────────────────────────────────────────────────────────────────

def test_dpapi_round_trip():
    data = b"secret key material 1234567890"
    assert dpapi_unprotect(dpapi_protect(data)) == data


def test_dpapi_empty():
    assert dpapi_unprotect(dpapi_protect(b"")) == b""


# ── ECIES ─────────────────────────────────────────────────────────────────────

def test_ecies_round_trip():
    pubkey, privkey_enc = generate_keypair("pw")
    privkey = unwrap_privkey(privkey_enc, "pw")
    plaintext = b"hello world"
    ct = ecies_encrypt(pubkey, plaintext)
    assert ecies_decrypt(privkey, ct) == plaintext


def test_ecies_version_byte():
    pubkey, _ = generate_keypair("pw")
    ct = ecies_encrypt(pubkey, b"data")
    assert ct[:1] == FORMAT_VERSION


def test_ecies_with_aad():
    pubkey, privkey_enc = generate_keypair("pw")
    privkey = unwrap_privkey(privkey_enc, "pw")
    aad = b"authenticated header"
    ct = ecies_encrypt(pubkey, b"data", aad=aad)
    assert ecies_decrypt(privkey, ct, aad=aad) == b"data"


def test_ecies_wrong_aad_fails():
    pubkey, privkey_enc = generate_keypair("pw")
    privkey = unwrap_privkey(privkey_enc, "pw")
    ct = ecies_encrypt(pubkey, b"data", aad=b"correct-aad")
    with pytest.raises(Exception):  # InvalidTag
        ecies_decrypt(privkey, ct, aad=b"wrong-aad")


def test_ecies_wrong_privkey_fails():
    pubkey, privkey_enc = generate_keypair("pw")
    pubkey2, privkey_enc2 = generate_keypair("pw")
    privkey2 = unwrap_privkey(privkey_enc2, "pw")
    ct = ecies_encrypt(pubkey, b"data")
    with pytest.raises(Exception):
        ecies_decrypt(privkey2, ct)


def test_ecies_hkdf_binding():
    """Different recipient pubkey → different HKDF info → decrypt fails."""
    pubkey, privkey_enc = generate_keypair("pw")
    privkey = unwrap_privkey(privkey_enc, "pw")
    pubkey2, privkey_enc2 = generate_keypair("pw")
    privkey2 = unwrap_privkey(privkey_enc2, "pw")

    ct = ecies_encrypt(pubkey, b"secret")
    # privkey2 corresponds to a different pubkey, so HKDF info mismatch
    with pytest.raises(Exception):
        ecies_decrypt(privkey2, ct)


# ── Keypair wrapping ──────────────────────────────────────────────────────────

def test_keypair_wrong_passphrase_fails():
    _, privkey_enc = generate_keypair("correct")
    with pytest.raises(Exception):
        unwrap_privkey(privkey_enc, "wrong")


def test_privkey_enc_version_byte():
    _, privkey_enc = generate_keypair("pw")
    assert privkey_enc[:1] == FORMAT_VERSION


def test_privkey_enc_length():
    """93 bytes: 1 + 32 + 12 + 32 + 16."""
    _, privkey_enc = generate_keypair("pw")
    assert len(privkey_enc) == 93


def test_reencrypt_privkey():
    pubkey, privkey_enc = generate_keypair("old")
    privkey_raw = unwrap_privkey(privkey_enc, "old")
    new_enc = reencrypt_privkey(privkey_enc, "old", "new")
    assert unwrap_privkey(new_enc, "new") == privkey_raw
    with pytest.raises(Exception):
        unwrap_privkey(new_enc, "old")


# ── Manifest header ───────────────────────────────────────────────────────────

def test_manifest_header_round_trip():
    pubkey_raw  = os.urandom(32)
    privkey_enc = os.urandom(93)
    header = build_manifest_header(pubkey_raw, privkey_enc)
    p_pub, p_priv, hdr_len = parse_manifest_header(header)
    assert p_pub  == pubkey_raw
    assert p_priv == privkey_enc
    assert hdr_len == len(header)


def test_manifest_header_version_byte():
    header = build_manifest_header(os.urandom(32), os.urandom(93))
    assert header[:1] == HDR_VERSION


def test_manifest_header_truncated():
    with pytest.raises(ValueError):
        parse_manifest_header(b"\x01" + os.urandom(10))


def test_manifest_header_bad_version():
    with pytest.raises(ValueError):
        parse_manifest_header(b"\xff" + os.urandom(100))


# ── Full manifest encrypt/decrypt ─────────────────────────────────────────────

def test_manifest_round_trip():
    pubkey_raw, privkey_enc = generate_keypair("pw")
    body = b'{"vault_id": "test", "root": {}}'
    data = encrypt_manifest(pubkey_raw, privkey_enc, body)
    decrypted, pub = decrypt_manifest(data, "pw")
    assert decrypted == body
    assert pub == pubkey_raw


def test_manifest_wrong_passphrase():
    pubkey_raw, privkey_enc = generate_keypair("correct")
    data = encrypt_manifest(pubkey_raw, privkey_enc, b"body")
    with pytest.raises(Exception):
        decrypt_manifest(data, "wrong")


def test_manifest_header_tampering_detected():
    """Modify one byte of the plaintext header; ECIES AAD check must fail."""
    pubkey_raw, privkey_enc = generate_keypair("pw")
    data = encrypt_manifest(pubkey_raw, privkey_enc, b"body")
    # Flip a byte in the pubkey portion of the header
    tampered = bytearray(data)
    tampered[5] ^= 0xFF
    with pytest.raises(Exception):
        decrypt_manifest(bytes(tampered), "pw")

