"""Serpent 纯 Python 封装测试：覆盖各类密钥长度、异常与自检。"""

import os

import pytest

from cipherforge.crypto._serpent import Serpent, _selftest


KEY128 = os.urandom(16)
KEY192 = os.urandom(24)
KEY256 = os.urandom(32)
PT = os.urandom(16)


def test_invalid_key_length():
    with pytest.raises(ValueError):
        Serpent(b"short")


def test_invalid_block_length_encrypt():
    s = Serpent(KEY256)
    with pytest.raises(ValueError):
        s.encrypt_block(b"tooshort")


def test_invalid_block_length_decrypt():
    s = Serpent(KEY256)
    with pytest.raises(ValueError):
        s.decrypt_block(b"tooshort")


def test_roundtrip_all_key_lengths():
    for key in (KEY128, KEY192, KEY256):
        s = Serpent(key)
        ct = s.encrypt_block(PT)
        assert ct != PT
        assert s.decrypt_block(ct) == PT


def test_selftest():
    assert _selftest() is True
