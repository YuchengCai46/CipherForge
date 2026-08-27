import os

import pytest

from cipherforge.crypto import HashEngine, SUPPORTED_HASHES, generate_pepper
from cipherforge.core.errors import ValidationError


def test_all_algorithms_roundtrip():
    he = HashEngine()
    d = b"hashtest" * 17 + b"\x00\x01"
    for a in he.supported():
        hx = he.hash(d, a)
        assert he.verify(d, hx, a), a
        # 不同数据不应通过
        assert not he.verify(d + b"x", hx, a), a


def test_xof_lengths():
    he = HashEngine()
    d = b"shake-data"
    for a in ("SHAKE128", "SHAKE256"):
        r32 = he.hash_raw(d, a, shake_len=32)
        assert len(r32) == 32
        r100 = he.hash_raw(d, a, shake_len=100)
        assert len(r100) == 100
        assert he.verify(d, r32.hex(), a, shake_len=32)


def test_xof_invalid_length():
    he = HashEngine()
    with pytest.raises(ValidationError):
        he.hash_raw(b"x", "SHAKE128", shake_len=0)
    with pytest.raises(ValidationError):
        he.hash_raw(b"x", "SHAKE128", shake_len=-5)


def test_pepper_flow():
    he = HashEngine()
    d = b"pepper me"
    pepper = generate_pepper()
    h = he.hash(d, "SHA-256", pepper=pepper)
    assert he.verify(d, h, "SHA-256", pepper=pepper)
    assert not he.verify(d, h, "SHA-256")  # 无 pepper 不应通过


def test_pepper_invalid_size():
    with pytest.raises(ValidationError):
        generate_pepper(0)


def test_file_hash(tmp_path):
    he = HashEngine()
    p = tmp_path / "f.bin"
    data = os.urandom(5000)
    p.write_bytes(data)
    h1 = he.file_hash(str(p), "BLAKE2b")
    # 等价内存哈希
    assert h1 == he.hash(data, "BLAKE2b")


def test_info_metadata():
    he = HashEngine()
    for a in SUPPORTED_HASHES:
        info = he.info(a)
        assert info.xof == (a.startswith("SHAKE"))
