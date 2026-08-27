import os

import pytest
from PIL import Image

from cipherforge.crypto import LSBSteganography, lsb_capacity
from cipherforge.core.errors import NoHiddenDataError, CarrierTooSmallError, ValidationError


def _carrier(path, size=(256, 256)):
    Image.new("RGB", size, (123, 200, 77)).save(path)


def test_capacity_scales_with_bitdepth():
    n = 256 * 256 * 3
    assert lsb_capacity(n, 1) < lsb_capacity(n, 2) < lsb_capacity(n, 4)


def test_hide_reveal_roundtrip():
    _carrier("c.png")
    lsb = LSBSteganography(bit_depth=1)
    data = os.urandom(1500)
    lsb.hide(data, "c.png", "h.png", password="p")
    assert lsb.reveal("h.png", password="p", bit_depth=1) == data


def test_hide_reveal_4bit_larger():
    _carrier("c4.png", (512, 512))
    lsb = LSBSteganography(bit_depth=4)
    data = os.urandom(30000)
    lsb.hide(data, "c4.png", "h4.png", password="p")
    assert lsb.reveal("h4.png", password="p", bit_depth=4) == data


def test_wrong_password():
    _carrier("cw.png")
    LSBSteganography(bit_depth=1).hide(os.urandom(500), "cw.png", "hw.png", password="p")
    with pytest.raises(NoHiddenDataError):
        LSBSteganography(bit_depth=1).reveal("hw.png", password="WRONG", bit_depth=1)


def test_wrong_bitdepth():
    _carrier("cb.png")
    LSBSteganography(bit_depth=1).hide(os.urandom(300), "cb.png", "hb.png", password="p")
    with pytest.raises(NoHiddenDataError):
        LSBSteganography(bit_depth=2).reveal("hb.png", password="p", bit_depth=2)


def test_carrier_too_small():
    Image.new("RGB", (8, 8)).save("tiny.png")
    with pytest.raises(CarrierTooSmallError):
        LSBSteganography(bit_depth=1).hide(os.urandom(300), "tiny.png", "x.png", password="p")


def test_invalid_bitdepth():
    with pytest.raises(ValidationError):
        LSBSteganography(bit_depth=0)
    with pytest.raises(ValidationError):
        LSBSteganography(bit_depth=5)


def test_empty_data():
    _carrier("ce.png")
    with pytest.raises(ValidationError):
        LSBSteganography(bit_depth=1).hide(b"", "ce.png", "xe.png", password="p")
