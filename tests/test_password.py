import pytest

from cipherforge.crypto import PasswordGenerator
from cipherforge.core.errors import ValidationError


def test_generate_length_and_charset():
    pg = PasswordGenerator()
    pw = pg.generate(24)
    assert len(pw) == 24
    # 默认字符集不含控制字符
    assert all(32 <= ord(c) <= 126 for c in pw)


def test_generate_custom_charset():
    pg = PasswordGenerator()
    cs = "abc123"
    pw = pg.generate(10, charset=cs)
    assert all(c in cs for c in pw)


def test_generate_exclude_ambiguous():
    pg = PasswordGenerator()
    pw = pg.generate(40, exclude_ambiguous=True)
    assert all(c not in "Il1O0oZ2S5B8|`'\";:" for c in pw)


def test_generate_zero_length():
    pg = PasswordGenerator()
    with pytest.raises(ValidationError):
        pg.generate(0)


def test_generate_passphrase():
    pg = PasswordGenerator()
    pp = pg.generate_passphrase(6)
    parts = pp.split("-")
    assert len(parts) == 6
    assert all(parts)


def test_entropy_and_strength():
    pg = PasswordGenerator()
    bits = pg.entropy_bits("a" * 20, 52)
    assert abs(bits - 20 * 5.7) < 1.0
    assert pg.strength_label(30) == "弱"
    assert pg.strength_label(50) == "中"
    assert pg.strength_label(80) == "强"
    assert pg.strength_label(200) == "极强"


def test_default_charset_dedup():
    pg = PasswordGenerator()
    cs = pg.default_charset()
    assert len(cs) == len(set(cs))
