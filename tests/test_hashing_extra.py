"""高级哈希引擎补充测试：覆盖全部算法、XOF、文件哈希与校验。"""

import os

import pytest

from cipherforge.crypto import HashEngine, generate_pepper
from cipherforge.core.errors import UnsupportedAlgorithmError, ValidationError


@pytest.fixture
def he():
    return HashEngine()


def test_supported_and_info(he):
    assert "SHA-256" in he.supported()
    info = he.info("SHA3-256")
    assert info.xof is False
    assert info.default_len == 32
    repr(info)  # 触发 __repr__


def test_hash_raw_with_and_without_pepper(he):
    d = b"hello world"
    h1 = he.hash_raw(d, "SHA-256")
    assert len(h1) == 32
    h2 = he.hash_raw(d, "SHA-256")
    assert h1 == h2
    pepper = generate_pepper()
    hp = he.hash_raw(d, "SHA-256", pepper=pepper)
    assert hp != h1


def test_hash_hex(he):
    h = he.hash(b"data", "SHA-512")
    assert isinstance(h, str) and len(h) == 128


def test_all_fixed_algorithms(he):
    for algo in ("SHA-224", "SHA-256", "SHA-384", "SHA-512",
                 "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
                 "BLAKE2b", "BLAKE2s"):
        out = he.hash(b"x" * 50, algo)
        assert len(out) == he.info(algo).default_len * 2


def test_shake_xof(he):
    a = he.hash_raw(b"msg", "SHAKE128", shake_len=32)
    b = he.hash_raw(b"msg", "SHAKE128", shake_len=64)
    assert len(a) == 32 and len(b) == 64
    c = he.hash_raw(b"msg", "SHAKE256", shake_len=16)
    assert len(c) == 16


def test_shake_invalid_length(he):
    with pytest.raises(ValidationError):
        he.hash_raw(b"x", "SHAKE128", shake_len=0)


def test_unsupported_algorithm(he):
    with pytest.raises(UnsupportedAlgorithmError):
        he.hash(b"x", "MD5")


def test_verify(he):
    d = b"verify me"
    algo = "SHA-256"
    digest = he.hash(d, algo)
    assert he.verify(d, digest, algo) is True
    assert he.verify(b"other", digest, algo) is False
    # 坏十六进制
    assert he.verify(d, "zzzz", algo) is False
    # 错误算法构造
    assert he.verify(d, digest, "SHA3-256") is False


def test_verify_with_pepper(he):
    pepper = generate_pepper()
    digest = he.hash(b"secret", "SHA-256", pepper=pepper)
    assert he.verify(b"secret", digest, "SHA-256", pepper=pepper)
    assert not he.verify(b"secret", digest, "SHA-256", pepper=b"wrong")


def test_generate_pepper_invalid():
    with pytest.raises(ValidationError):
        generate_pepper(0)
    assert len(generate_pepper(16)) == 16


def test_file_hash(he, tmp_path):
    p = tmp_path / "f.bin"
    data = os.urandom(5000)
    p.write_bytes(data)
    direct = he.hash(data, "SHA-256")
    fh = he.file_hash(str(p), "SHA-256")
    assert fh == direct
    # XOF 文件哈希
    fx = he.file_hash(str(p), "SHAKE256", shake_len=48)
    assert len(fx) == 96
