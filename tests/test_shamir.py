import base64
import os

import pytest

from cipherforge.crypto import ShamirSecretSharing
from cipherforge.crypto.shamir import GF256, _lagrange_at_zero, _poly_eval
from cipherforge.core.errors import (
    InsufficientSharesError,
    ShareCorruptedError,
    ValidationError,
)


def test_gf_arithmetic():
    assert GF256.mul(0, 9) == 0
    assert GF256.mul(1, 1) == 1
    for v in (2, 7, 100, 200, 255):
        assert GF256.mul(v, GF256.inv(v)) == 1
    assert GF256.div(GF256.mul(11, 13), 13) == 11


def test_lagrange_recovers_constant():
    for deg in (1, 2, 3):
        coeffs = [123]
        for _ in range(deg):
            coeffs.append((os.urandom(1)[0]))
        xs = [5, 50, 123, 200][: deg + 1]
        ys = [_poly_eval(coeffs, x) for x in xs]
        assert _lagrange_at_zero(xs, ys) == 123


def test_split_combine_thresholds():
    secret = os.urandom(32)
    s = ShamirSecretSharing(3, 5)
    shares = s.split(secret)
    assert len(shares) == 5
    # 任意 3 份
    assert s.combine(s.split_to_text(secret)[0:3]) == secret
    # 全部 5 份
    assert s.combine(s.split_to_text(secret)) == secret


def test_insufficient_shares():
    s = ShamirSecretSharing(3, 5)
    texts = s.split_to_text(os.urandom(16))
    with pytest.raises(InsufficientSharesError):
        s.combine(texts[0:2])


def test_corrupted_share():
    s = ShamirSecretSharing(3, 5)
    texts = s.split_to_text(os.urandom(16))
    bad = bytearray(base64.b64decode(texts[0]))
    bad[-1] ^= 0xFF
    bad_text = base64.b64encode(bytes(bad)).decode()
    with pytest.raises(ShareCorruptedError):
        s.combine([bad_text] + texts[1:3])


def test_tampered_full_secret_fails():
    s = ShamirSecretSharing(2, 4)
    texts = s.split_to_text(os.urandom(20))
    # 篡改一份的若干字节（仍保持 base64 合法）
    raw = bytearray(base64.b64decode(texts[0]))
    raw[8] ^= 0xAA
    texts[0] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(ShareCorruptedError):
        s.combine(texts[0:2])


def test_large_secret_and_threshold_bounds():
    secret = os.urandom(600)
    s = ShamirSecretSharing(2, 2)
    assert s.combine(s.split_to_text(secret)) == secret


def test_invalid_threshold_total():
    with pytest.raises(ValidationError):
        ShamirSecretSharing(1, 3)  # 阈值需 >= 2
    with pytest.raises(ValidationError):
        ShamirSecretSharing(3, 300)  # total 上限 255


def test_empty_secret():
    s = ShamirSecretSharing(2, 3)
    with pytest.raises(ValidationError):
        s.split(b"")


def test_qr_requires_dependency(tmp_path):
    s = ShamirSecretSharing(2, 3)
    # 未安装 qrcode 时应优雅降级
    try:
        import qrcode  # noqa
    except ImportError:
        with pytest.raises(Exception):
            s.split_to_qr(os.urandom(8), str(tmp_path))
