import io
import os

import pytest

from cipherforge.crypto import SymmetricCipher, StreamCipher, SUPPORTED_SYMMETRIC
from cipherforge.core.errors import DecryptionFailedError, ValidationError


@pytest.mark.parametrize("algo", SUPPORTED_SYMMETRIC)
def test_symmetric_roundtrip(algo):
    c = SymmetricCipher(algo)
    pt = b"roundtrip-" * 20 + bytes(range(16))
    blob = c.encrypt(pt, password="pw123", aad=b"AAD")
    assert c.decrypt(blob, password="pw123", aad=b"AAD") == pt


@pytest.mark.parametrize("algo", SUPPORTED_SYMMETRIC)
def test_wrong_password_fails(algo):
    c = SymmetricCipher(algo)
    blob = c.encrypt(b"x" * 50, password="right")
    with pytest.raises(DecryptionFailedError):
        c.decrypt(blob, password="wrong")


def test_wrong_aad_fails():
    c = SymmetricCipher("AES-256-GCM")
    blob = c.encrypt(b"data", password="p", aad=b"aad1")
    with pytest.raises(DecryptionFailedError):
        c.decrypt(blob, password="p", aad=b"aad2")


def test_raw_key_mode():
    c = SymmetricCipher("ChaCha20-Poly1305")
    key = os.urandom(32)
    ct = c.encrypt_with_key(b"hello raw", key)
    assert c.decrypt_with_key(ct, key) == b"hello raw"


def test_unknown_algo():
    with pytest.raises(Exception):
        SymmetricCipher("NO-SUCH-ALGO")


def test_stream_roundtrip_libsodium():
    sc = StreamCipher(algorithm="XChaCha20-Poly1305")
    data = os.urandom(2 * 1024 * 1024)
    src = io.BytesIO(data)
    dst = io.BytesIO()
    sc.encrypt_stream(src, dst, password="sp")
    dst.seek(0)
    back = io.BytesIO()
    sc.decrypt_stream(dst, back, password="sp")
    assert back.getvalue() == data


def test_stream_wrong_password():
    sc = StreamCipher(algorithm="AES-256-GCM")
    src = io.BytesIO(b"payload data here")
    dst = io.BytesIO()
    sc.encrypt_stream(src, dst, password="p")
    dst.seek(0)
    back = io.BytesIO()
    with pytest.raises(DecryptionFailedError):
        sc.decrypt_stream(dst, back, password="wrong")
