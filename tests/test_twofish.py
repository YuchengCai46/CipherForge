"""Twofish 纯 Python 实现测试：覆盖三种密钥长度、异常、辅助函数与自检。"""

import os

import pytest

from cipherforge.crypto._twofish import (
    Twofish,
    _selftest,
    _byteswap32,
    _rotl32,
    _rotr32,
)


KEY16 = os.urandom(16)
KEY24 = os.urandom(24)
KEY32 = os.urandom(32)
PT = os.urandom(16)


def test_invalid_key_length():
    with pytest.raises(ValueError):
        Twofish(b"short")


def test_invalid_block_length_encrypt():
    c = Twofish(KEY32)
    with pytest.raises(ValueError):
        c.encrypt_block(b"tooshort")


def test_invalid_block_length_decrypt():
    c = Twofish(KEY32)
    with pytest.raises(ValueError):
        c.decrypt_block(b"tooshort")


def test_roundtrip_all_key_lengths():
    # 三种长度覆盖 _gen_mk_tab 的 k_len==2/3/4 分支与 _h_fun 各条件分支
    for key in (KEY16, KEY24, KEY32):
        c = Twofish(key)
        ct = c.encrypt_block(PT)
        assert ct != PT
        assert c.decrypt_block(ct) == PT


def test_known_answer():
    # 官方 Twofish KAT
    key = bytes.fromhex("D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F")
    pt = bytes.fromhex("90AFE91BB288544F2C32DC239B2635E6")
    expected = bytes.fromhex("6CB4561C40BF0A9705931CB6D408E7FA")
    assert Twofish(key).encrypt_block(pt) == expected


def test_selftest():
    assert _selftest() is True


def test_helper_primitives():
    assert _byteswap32(0x12345678) == 0x78563412
    assert _rotl32(0x00000001, 1) == 0x00000002
    assert _rotr32(0x80000000, 1) == 0x40000000
