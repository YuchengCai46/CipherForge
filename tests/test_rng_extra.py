"""随机数源补充测试：覆盖参数校验与全部公开函数。"""

import pytest

from cipherforge.core import rng
from cipherforge.core.errors import ValidationError


def test_random_bytes_invalid():
    with pytest.raises(ValidationError):
        rng.random_bytes(0)
    with pytest.raises(ValidationError):
        rng.random_bytes(-5)
    with pytest.raises(ValidationError):
        rng.random_bytes(1 << 31)  # 超过 1 GiB 上限


def test_random_bytes_ok():
    b = rng.random_bytes(32)
    assert len(b) == 32
    # 两次结果应不同（极高概率）
    assert rng.random_bytes(32) != rng.random_bytes(32)


def test_random_nonce_and_salt():
    assert len(rng.random_nonce()) == rng.NONCE_BYTES
    assert len(rng.random_nonce(24)) == 24
    assert len(rng.random_salt()) == rng.SALT_BYTES


def test_randbelow_invalid():
    with pytest.raises(ValidationError):
        rng.randbelow(0)
    with pytest.raises(ValidationError):
        rng.randbelow(-1)


def test_randbelow_range():
    for _ in range(200):
        v = rng.randbelow(10)
        assert 0 <= v < 10


def test_random_int_range():
    for _ in range(200):
        v = rng.random_int_range(3, 9)
        assert 3 <= v <= 9


def test_random_int_range_invalid():
    with pytest.raises(ValidationError):
        rng.random_int_range(9, 3)


def test_random_permutation():
    p = rng.random_permutation(20)
    assert sorted(p) == list(range(20))
    assert len(set(p)) == 20
    assert rng.random_permutation(0) == []
    with pytest.raises(ValidationError):
        rng.random_permutation(-1)


def test_random_token_hex():
    t = rng.random_token_hex(8)
    assert len(t) == 16  # 8 字节 -> 16 十六进制字符


def test_random_choice():
    seq = ["a", "b", "c"]
    assert rng.random_choice(seq) in seq
    with pytest.raises(ValidationError):
        rng.random_choice([])


def test_entropy_selftest():
    report = rng.entropy_selftest(2048)
    assert "passed" in report
    assert report["passed"] is True
    # 全零种子应被检出（均值检查失败）
    real = rng.random_bytes
    try:
        rng.random_bytes = lambda n: b"\x00" * n
        bad = rng.entropy_selftest(256)
        assert bad["passed"] is False
    finally:
        rng.random_bytes = real
