"""XChaCha20-Poly1305 纯 Python 兜底实现补充测试（本环境无 libsodium）。"""

import os

import pytest

from cipherforge.crypto._xchacha import (
    XChaCha20Poly1305Cipher,
    _chacha20_block,
    _poly1305_mac,
    _poly1305_key_gen,
    hchacha20,
    _bytes_to_words,
    _words_to_bytes,
    _constant_time_eq,
    _xor_stream,
)
from cipherforge.core.errors import DecryptionFailedError


KEY = os.urandom(32)
NONCE24 = os.urandom(24)
# 纯 ChaCha20 原语（_chacha20_block / _poly1305_key_gen / _xor_stream）使用 12 字节 nonce；
# 仅 HChaCha20 与 XChaCha 外层使用 16/24 字节 nonce。
NONCE12 = os.urandom(12)


def test_key_length_validation():
    with pytest.raises(ValueError):
        XChaCha20Poly1305Cipher(b"tooshort")


def test_nonce_length_validation():
    c = XChaCha20Poly1305Cipher(KEY)
    with pytest.raises(ValueError):
        c.encrypt(b"\x00" * 23, b"pt")  # nonce 长度非 24
    with pytest.raises(ValueError):
        c.decrypt(b"\x00" * 23, b"data")


def test_decrypt_too_short():
    c = XChaCha20Poly1305Cipher(KEY)
    with pytest.raises(DecryptionFailedError):
        c.decrypt(NONCE24, b"short")  # 不足 16 字节标签


def test_aead_roundtrip():
    c = XChaCha20Poly1305Cipher(KEY)
    pt = b"XChaCha20 AEAD roundtrip payload"
    blob = c.encrypt(NONCE24, pt)
    assert blob[-16:] != pt[-16:]  # 至少被加密
    assert c.decrypt(NONCE24, blob) == pt


def test_aad_sensitivity():
    c = XChaCha20Poly1305Cipher(KEY)
    blob = c.encrypt(NONCE24, b"pt", associated_data=b"aad1")
    assert c.decrypt(NONCE24, blob, associated_data=b"aad1") == b"pt"
    with pytest.raises(DecryptionFailedError):
        c.decrypt(NONCE24, blob, associated_data=b"aad2")


def test_tampered_tag_fails():
    c = XChaCha20Poly1305Cipher(KEY)
    blob = bytearray(c.encrypt(NONCE24, b"secret-data"))
    blob[-1] ^= 0xFF
    with pytest.raises(DecryptionFailedError):
        c.decrypt(NONCE24, bytes(blob))


def test_empty_plaintext_pure():
    c = XChaCha20Poly1305Cipher(KEY)
    blob = c.encrypt(NONCE24, b"")  # 触发 _xor_stream 空输入分支
    assert c.decrypt(NONCE24, blob) == b""


def test_backend_property():
    c = XChaCha20Poly1305Cipher(KEY)
    assert c.backend in ("libsodium", "pure-python")


def test_primitive_helpers():
    n = os.urandom(16)
    h = hchacha20(KEY, n)
    assert len(h) == 32
    blk = _chacha20_block(KEY, 1, NONCE12)
    assert len(blk) == 64
    otk = _poly1305_key_gen(KEY, NONCE12)
    assert len(otk) == 32
    mac = _poly1305_mac(b"hello", otk)
    assert len(mac) == 16
    assert _constant_time_eq(mac, mac)
    assert not _constant_time_eq(mac, b"\x00" * 16)
    # 字/字节互转
    w = _bytes_to_words(b"\x01\x00\x00\x00\x02\x00\x00\x00")
    assert w == [1, 2]
    assert _words_to_bytes(w) == b"\x01\x00\x00\x00\x02\x00\x00\x00"
    # 空明文异或
    assert _xor_stream(b"", b"\x00" * 64, KEY, NONCE12, 1) == b""
