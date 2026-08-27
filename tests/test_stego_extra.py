"""隐写补充测试：容量边界、载荷加解密底层、口令校验与 capacity。"""

from PIL import Image

import pytest

from cipherforge.crypto import LSBSteganography, lsb_capacity
from cipherforge.crypto.steganography import _encrypt_payload, _decrypt_payload
from cipherforge.core.errors import (
    ValidationError,
    NoHiddenDataError,
)


def _carrier(path, size=(128, 128)):
    Image.new("RGB", size, (10, 20, 30)).save(path)


def test_lsb_capacity_invalid_bitdepth():
    with pytest.raises(ValidationError):
        lsb_capacity(1000, 0)
    with pytest.raises(ValidationError):
        lsb_capacity(1000, 5)


def test_decrypt_payload_too_short():
    with pytest.raises(NoHiddenDataError):
        _decrypt_payload(b"\x00" * 10, "p")


def test_decrypt_payload_bad_ciphertext():
    blob = b"\x00" * (16 + 12) + b"garbage" * 5
    with pytest.raises(NoHiddenDataError):
        _decrypt_payload(blob, "p")


def test_encrypt_decrypt_payload_roundtrip():
    blob = _encrypt_payload(b"secret payload", "pw")
    assert _decrypt_payload(blob, "pw") == b"secret payload"
    with pytest.raises(NoHiddenDataError):
        _decrypt_payload(blob, "wrong")


def test_hide_empty_password(tmp_path):
    c = tmp_path / "c.png"
    _carrier(str(c))
    with pytest.raises(ValidationError):
        LSBSteganography(bit_depth=1).hide(b"data", str(c), str(tmp_path / "h.png"), password="")


def test_reveal_empty_password(tmp_path):
    c = tmp_path / "c2.png"
    _carrier(str(c))
    LSBSteganography(bit_depth=1).hide(b"data", str(c), str(tmp_path / "h2.png"), password="p")
    with pytest.raises(ValidationError):
        LSBSteganography(bit_depth=1).reveal(str(tmp_path / "h2.png"), password="")


def test_capacity_method(tmp_path):
    c = tmp_path / "cap.png"
    _carrier(str(c), (256, 256))
    cap = LSBSteganography(bit_depth=1).capacity(str(c))
    assert cap > 0
    # 与 lsb_capacity 一致
    from PIL import Image as _PILImage

    n = len(_PILImage.open(str(c)).tobytes())
    assert cap == lsb_capacity(n, 1)


def test_reveal_bitdepth_mismatch(tmp_path):
    c = tmp_path / "c3.png"
    _carrier(str(c))
    LSBSteganography(bit_depth=1).hide(b"data", str(c), str(tmp_path / "h3.png"), password="p")
    # 以错误位深提取 -> 结构不匹配
    with pytest.raises(NoHiddenDataError):
        LSBSteganography(bit_depth=1).reveal(
            str(tmp_path / "h3.png"), password="p", bit_depth=2
        )
