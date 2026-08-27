"""密码 / 密语生成器补充测试。"""

import math

import pytest

from cipherforge.crypto import PasswordGenerator
from cipherforge.crypto.password_generator import _WORDLIST
from cipherforge.core.errors import ValidationError


def test_default_charset():
    g = PasswordGenerator()
    cs = g.default_charset()
    assert len(cs) >= 60
    # 默认不含易混淆字符移除
    assert "a" in cs and "A" in cs and "0" in cs


def test_default_charset_exclude_ambiguous():
    g = PasswordGenerator()
    cs = g.default_charset(exclude_ambiguous=True)
    for bad in "Il1O0oZ2S5B8":
        assert bad not in cs
    # 去重且保持顺序稳定
    assert len(cs) == len(set(cs))


def test_generate_length_and_charset():
    g = PasswordGenerator()
    pw = g.generate(20)
    assert len(pw) == 20
    assert all(c in g.default_charset() for c in pw)
    # 指定字符集
    pw2 = g.generate(10, charset="abc")
    assert set(pw2) <= set("abc")
    # 空字符集回退默认
    pw3 = g.generate(5, charset="")
    assert len(pw3) == 5


def test_generate_invalid():
    g = PasswordGenerator()
    with pytest.raises(ValidationError):
        g.generate(0)
    with pytest.raises(ValidationError):
        g.generate(-3)
    with pytest.raises(ValidationError):
        g.generate(5, charset="x")  # 字符集过短


def test_generate_passphrase():
    g = PasswordGenerator()
    ph = g.generate_passphrase(6)
    parts = ph.split("-")
    assert len(parts) == 6
    assert all(p in _WORDLIST for p in parts)


def test_generate_passphrase_invalid():
    g = PasswordGenerator()
    with pytest.raises(ValidationError):
        g.generate_passphrase(0)
    with pytest.raises(ValidationError):
        g.generate_passphrase(3, wordlist=["onlyone"])


def test_entropy_and_strength():
    g = PasswordGenerator()
    assert g.entropy_bits("abcd", 26) == pytest.approx(4 * math.log2(26))
    assert g.entropy_bits("", 26) == 0.0
    assert g.entropy_bits("x", 1) == 0.0
    assert g.passphrase_entropy(6, 64) == 6 * 6
    assert g.passphrase_entropy(4, 1) == 0.0
    assert g.strength_label(30) == "弱"
    assert g.strength_label(50) == "中"
    assert g.strength_label(80) == "强"
    assert g.strength_label(200) == "极强"
