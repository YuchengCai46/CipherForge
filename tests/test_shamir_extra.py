"""Shamir 秘密共享补充测试：GF(256) 边界、分片解码错误与合并异常路径。"""

import base64

import pytest

from cipherforge.crypto import ShamirSecretSharing
from cipherforge.crypto.shamir import GF256, _MAGIC
from cipherforge.core.errors import (
    InsufficientSharesError,
    ShareCorruptedError,
    DependencyMissingError,
)


def test_gf_inverse_and_division():
    assert GF256.inv(1) == 1
    # 零不可逆
    with pytest.raises(ZeroDivisionError):
        GF256.inv(0)
    assert GF256.div(0, 123) == 0
    with pytest.raises(ZeroDivisionError):
        GF256.div(123, 0)
    assert GF256.div(1, 1) == 1


def test_decode_share_too_short():
    with pytest.raises(ShareCorruptedError):
        ShamirSecretSharing._decode_share(b"short")


def test_decode_share_bad_magic():
    blob = b"XXXX" + b"\x00" * 8
    with pytest.raises(ShareCorruptedError):
        ShamirSecretSharing._decode_share(blob)


def test_decode_share_crc_mismatch():
    s = ShamirSecretSharing(2, 3)
    raw = bytearray(base64.b64decode(s.split_to_text(b"hello")[0]))
    raw[-1] ^= 0xFF  # 破坏 body -> CRC 失配
    with pytest.raises(ShareCorruptedError):
        ShamirSecretSharing._decode_share(bytes(raw))


def test_decode_share_length_field_mismatch():
    # 手动构造一个 slen 字段与实际 payload 不符的分片
    s = ShamirSecretSharing(2, 3)
    raw = bytearray(base64.b64decode(s.split_to_text(b"hello")[0]))
    # body 从偏移 8 开始；slen 占 body[1:3]（小端，2 字节）
    raw[9] ^= 0xFF  # 篡改 slen 低字节
    with pytest.raises(ShareCorruptedError):
        ShamirSecretSharing._decode_share(bytes(raw))


def test_combine_empty_shares():
    s = ShamirSecretSharing(3, 5)
    with pytest.raises(InsufficientSharesError) as exc:
        s.combine_shares([])
    assert exc.value.context["已提供"] == 0


def test_combine_insufficient_distinct_due_to_duplicate_x():
    # 用相同 x 构造重复分片，触发去重 -> 有效分片数不足
    s = ShamirSecretSharing(4, 5)
    p = b"\x00" * 8
    dup = [
        ShamirSecretSharing._encode_share(1, 8, 3, 5, p),
        ShamirSecretSharing._encode_share(1, 8, 3, 5, p),  # 同 x -> 去重
        ShamirSecretSharing._encode_share(2, 8, 3, 5, p),
        ShamirSecretSharing._encode_share(3, 8, 3, 5, p),
    ]
    with pytest.raises(InsufficientSharesError) as exc:
        s.combine_shares(dup)
    assert exc.value.context["已提供"] == 3


def test_combine_inconsistent_share_lengths():
    s = ShamirSecretSharing(3, 5)
    dup = [
        ShamirSecretSharing._encode_share(1, 10, 3, 5, b"x" * 10),
        ShamirSecretSharing._encode_share(2, 11, 3, 5, b"y" * 11),
        ShamirSecretSharing._encode_share(3, 10, 3, 5, b"z" * 10),
    ]
    with pytest.raises(ShareCorruptedError):
        s.combine_shares(dup)


def test_combine_bad_base64():
    s = ShamirSecretSharing(2, 3)
    with pytest.raises(ShareCorruptedError):
        s.combine(["not valid base64 !!!"])


def test_combine_from_qr_requires_dependency(tmp_path):
    s = ShamirSecretSharing(2, 3)
    try:
        import pyzbar  # noqa
    except ImportError:
        with pytest.raises(DependencyMissingError):
            s.combine_from_qr([str(tmp_path / "x.png")])


def test_split_to_qr_requires_dependency(tmp_path):
    s = ShamirSecretSharing(2, 3)
    try:
        import qrcode  # noqa
    except ImportError:
        with pytest.raises(DependencyMissingError):
            s.split_to_qr(b"secret", str(tmp_path))


def test_repr():
    s = ShamirSecretSharing(3, 5)
    assert "threshold=3" in repr(s) and "total=5" in repr(s)
