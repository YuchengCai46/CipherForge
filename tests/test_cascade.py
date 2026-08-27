import pytest

from cipherforge.crypto import CascadeEngine
from cipherforge.core.errors import (
    DecryptionFailedError,
    DowngradeAttackError,
    IntegrityError,
    ValidationError,
)


def test_cascade_roundtrip_default():
    eng = CascadeEngine()
    pt = b"cascade payload " * 12 + b"\x00\xff"
    blob = eng.encrypt(pt, password="master")
    assert eng.decrypt(blob, password="master") == pt


def test_cascade_custom_layers():
    eng = CascadeEngine(["XChaCha20-Poly1305", "Twofish-GCM", "AES-256-GCM"])
    pt = b"x" * 200
    blob = eng.encrypt(pt, password="p")
    assert eng.decrypt(blob, password="p") == pt


def test_cascade_wrong_password():
    eng = CascadeEngine()
    blob = eng.encrypt(b"secret", password="right")
    with pytest.raises(DecryptionFailedError):
        eng.decrypt(blob, password="wrong")


def test_cascade_tamper_header_mac():
    eng = CascadeEngine()
    blob = bytearray(eng.encrypt(b"data", password="p"))
    # 篡改头体某个字节，MAC 必失配
    blob[20] ^= 0xFF
    with pytest.raises(DecryptionFailedError):
        eng.decrypt(bytes(blob), password="p")


def test_cascade_downgrade_trailing_bytes():
    eng = CascadeEngine()
    blob = bytearray(eng.encrypt(b"data", password="p"))
    body, mac = blob[:-32], blob[-32:]
    # 追加残余字节 -> 结构降级
    bad = bytes(body) + b"\x00" * 16 + bytes(mac)
    with pytest.raises(DowngradeAttackError):
        eng.decrypt(bad, password="p")


def test_cascade_invalid_algo():
    with pytest.raises(Exception):
        CascadeEngine(["NOT-AN-ALGO"])


def test_cascade_empty_plaintext():
    eng = CascadeEngine()
    with pytest.raises(ValidationError):
        eng.encrypt(b"", password="p")


def test_cascade_too_many_layers():
    with pytest.raises(ValidationError):
        CascadeEngine(["AES-256-GCM"] * 20)
