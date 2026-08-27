import pytest

from cipherforge.core import rng
from cipherforge.core.errors import ValidationError


def test_random_bytes_length():
    assert len(rng.random_bytes(32)) == 32


def test_random_bytes_invalid():
    with pytest.raises(ValidationError):
        rng.random_bytes(0)
    with pytest.raises(ValidationError):
        rng.random_bytes(-1)


def test_random_salt_default():
    s = rng.random_salt()
    assert len(s) == 16


def test_randbelow_range():
    for _ in range(200):
        v = rng.randbelow(10)
        assert 0 <= v < 10


def test_randbelow_invalid():
    with pytest.raises(ValidationError):
        rng.randbelow(0)


def test_permutation_uniform():
    perm = rng.random_permutation(10)
    assert sorted(perm) == list(range(10))


def test_permutation_negative():
    with pytest.raises(ValidationError):
        rng.random_permutation(-1)


def test_entropy_selftest():
    res = rng.entropy_selftest()
    assert res["passed"] is True
    assert 110 <= res["均值"] <= 145


def test_choice():
    seq = [1, 2, 3, 4, 5]
    assert rng.random_choice(seq) in seq
