"""Shamir 补充覆盖（续）：构造参数校验、分片解码错误、QR 拆分/合并路径。

本环境 ``qrcode`` / ``PIL`` 已安装，故 ``split_to_qr`` 可直接覆盖；
``pyzbar`` 缺失，故 ``combine_from_qr`` 通过注入伪 ``pyzbar`` 模块覆盖。
"""

import os
import struct
import sys
import types
import zlib

import pytest

from cipherforge.crypto import ShamirSecretSharing
from cipherforge.crypto.shamir import _MAGIC
from cipherforge.core.errors import (
    ShareCorruptedError,
    ValidationError,
)


def _x_of(blob: bytes) -> int:
    return ShamirSecretSharing._decode_share(blob)[0]


def test_init_non_integer_params():
    with pytest.raises(ValidationError):
        ShamirSecretSharing("2", 3)
    with pytest.raises(ValidationError):
        ShamirSecretSharing(2, "3")


def test_init_total_out_of_range():
    with pytest.raises(ValidationError):
        ShamirSecretSharing(2, 1)
    with pytest.raises(ValidationError):
        ShamirSecretSharing(2, 256)


def test_init_threshold_out_of_range():
    with pytest.raises(ValidationError):
        ShamirSecretSharing(1, 3)
    with pytest.raises(ValidationError):
        ShamirSecretSharing(4, 3)


def test_decode_share_slen_mismatch():
    # 手工构造 slen 字段与实际 payload 长度不符的分片
    x, slen, thresh, total = 1, 10, 2, 3
    payload = b"\x00" * 5  # 实际只有 5 字节，slen 却写 10
    body = struct.pack("<B H B B", x, slen, thresh, total) + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    blob = _MAGIC + struct.pack("<I", crc) + body
    with pytest.raises(ShareCorruptedError):
        ShamirSecretSharing._decode_share(blob)


def test_split_to_qr_real(tmp_path):
    s = ShamirSecretSharing(2, 3)
    paths = s.split_to_qr(b"secret-data-here", str(tmp_path))
    assert len(paths) == 3
    for p in paths:
        assert os.path.exists(p)
        assert p.endswith(".png")


def test_combine_digest_mismatch():
    # 用两份不同秘密、相同长度的分片交叉合并 -> 校验前缀不匹配
    s_a = ShamirSecretSharing(2, 3)
    shares_a = s_a.split(b"AAAA")
    s_b = ShamirSecretSharing(2, 3)
    shares_b = s_b.split(b"BBBB")

    xa = _x_of(shares_a[0])
    pick_b = next(b for b in shares_b if _x_of(b) != xa)
    with pytest.raises(ShareCorruptedError):
        s_a.combine_shares([shares_a[0], pick_b])


def test_combine_from_qr_via_mock(monkeypatch):
    # 注入伪 pyzbar + 伪 PIL.Image.open，覆盖 combine_from_qr 的二维码解码路径
    fake_pyzbar = types.ModuleType("pyzbar")
    fake_pyzbar_pyzbar = types.ModuleType("pyzbar.pyzbar")

    s = ShamirSecretSharing(2, 3)
    texts = s.split_to_text(b"hello-qr")
    it = iter(texts)

    def fake_decode(image):
        return [types.SimpleNamespace(data=next(it).encode("utf-8"))]

    fake_pyzbar_pyzbar.decode = fake_decode
    monkeypatch.setitem(sys.modules, "pyzbar", fake_pyzbar)
    monkeypatch.setitem(sys.modules, "pyzbar.pyzbar", fake_pyzbar_pyzbar)
    monkeypatch.setattr("PIL.Image.open", lambda p: object())

    img_paths = [str(tmp_p) for tmp_p in (None,) * len(texts)]
    # combine_from_qr 仅用路径触发 decode，decode 内部已忽略路径
    img_paths = [os.path.join("p", f"x{i}.png") for i in range(len(texts))]
    assert s.combine_from_qr(img_paths) == b"hello-qr"
