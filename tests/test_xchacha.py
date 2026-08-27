import os

import pytest

import cipherforge.crypto._xchacha as xc
from cipherforge.crypto._xchacha import XChaCha20Poly1305Cipher
from cipherforge.core.errors import DecryptionFailedError


# ----------------------------------------------------------------------
#  RFC 8439 已知答案测试（KAT）
# ----------------------------------------------------------------------
def test_chacha20_block_kat():
    key = bytes(range(32))
    nonce = bytes([0, 0, 0, 9, 0, 0, 0, 0x4A, 0, 0, 0, 0])
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert xc._chacha20_block(key, 1, nonce) == expected


def test_poly1305_kat():
    # RFC 8439 §2.5.2 官方测试向量（注意密钥后 16 字节）
    key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    msg = b"Cryptographic Forum Research Group"
    expected = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
    assert xc._poly1305_mac(msg, key) == expected


# ----------------------------------------------------------------------
#  纯 Python 兜底路径（强制关闭 libsodium 后端）
# ----------------------------------------------------------------------
@pytest.fixture
def pure_mode(monkeypatch):
    monkeypatch.setattr(xc, "_LIBSODIUM_AVAILABLE", False)
    yield


def test_pure_aead_roundtrip(pure_mode):
    key = os.urandom(32)
    nonce = os.urandom(24)
    c = XChaCha20Poly1305Cipher(key)
    assert c.backend == "pure-python"
    ct = c.encrypt(nonce, b"hello pure", b"aad")
    assert c.decrypt(nonce, ct, b"aad") == b"hello pure"


def test_pure_tamper_detected(pure_mode):
    key = os.urandom(32)
    nonce = os.urandom(24)
    c = XChaCha20Poly1305Cipher(key)
    ct = bytearray(c.encrypt(nonce, b"data", b""))
    ct[0] ^= 0xFF
    with pytest.raises(DecryptionFailedError):
        c.decrypt(nonce, bytes(ct), b"")


def test_pure_wrong_aad(pure_mode):
    key = os.urandom(32)
    nonce = os.urandom(24)
    c = XChaCha20Poly1305Cipher(key)
    ct = c.encrypt(nonce, b"data", b"aad1")
    with pytest.raises(DecryptionFailedError):
        c.decrypt(nonce, ct, b"aad2")


def test_pure_symmetric_integration(pure_mode):
    from cipherforge.crypto import SymmetricCipher

    c = SymmetricCipher("XChaCha20-Poly1305")
    blob = c.encrypt(b"x" * 100, password="p")
    assert c.decrypt(blob, password="p") == b"x" * 100
