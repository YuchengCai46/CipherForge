"""级联加密补充测试：构造异常、PBKDF2 路径、头解析与降级检测。"""

import pytest

from cipherforge.crypto import CascadeEngine
from cipherforge.core.config import load_config
from cipherforge.core.errors import (
    ValidationError,
    DecryptionFailedError,
    DowngradeAttackError,
    IntegrityError,
)


def test_roundtrip_default():
    eng = CascadeEngine(["AES-256-GCM", "ChaCha20-Poly1305", "Serpent-GCM"])
    data = b"cascade payload " * 50
    blob = eng.encrypt(data, password="master")
    assert eng.decrypt(blob, password="master") == data
    with pytest.raises(DecryptionFailedError):
        eng.decrypt(blob, password="wrong")


def test_single_layer_roundtrip():
    eng = CascadeEngine(["Twofish-GCM"])
    data = b"single layer"
    blob = eng.encrypt(data, password="p")
    assert eng.decrypt(blob, password="p") == data


def test_roundtrip_pbkdf2():
    cfg = load_config()
    cfg.set("kdf.default", "pbkdf2")
    eng = CascadeEngine(["AES-256-GCM", "ChaCha20-Poly1305"], config=cfg)
    data = b"pbkdf2 cascade " * 30
    blob = eng.encrypt(data, password="p")
    assert eng.decrypt(blob, password="p") == data


def test_empty_plaintext():
    eng = CascadeEngine()
    with pytest.raises(ValidationError):
        eng.encrypt(b"", password="p")


def test_empty_password_encrypt():
    eng = CascadeEngine()
    with pytest.raises(ValidationError):
        eng.encrypt(b"x", password="")


def test_empty_password_decrypt():
    eng = CascadeEngine()
    with pytest.raises(ValidationError):
        eng.decrypt(b"x", password="")


def test_too_few_layers():
    with pytest.raises(ValidationError):
        CascadeEngine([])


def test_too_many_layers():
    with pytest.raises(ValidationError):
        CascadeEngine(["AES-256-GCM"] * 17)


def test_unsupported_algo_in_constructor():
    with pytest.raises(Exception):
        CascadeEngine(["AES-256-GCM", "NOT-REAL"])


def test_decrypt_wrong_magic():
    eng = CascadeEngine()
    with pytest.raises(DecryptionFailedError):
        eng.decrypt(b"XXXX" + b"\x00" * 40, password="p")


def test_parse_header_too_short():
    eng = CascadeEngine()
    with pytest.raises(DowngradeAttackError):
        eng._parse_header(b"\x00" * 4)


def test_parse_header_bad_magic():
    eng = CascadeEngine()
    with pytest.raises(DowngradeAttackError):
        eng._parse_header(b"XXXX" + b"\x00" * 40)


def test_split_mac_too_short():
    eng = CascadeEngine()
    with pytest.raises(DowngradeAttackError):
        eng._split_mac(b"short")
