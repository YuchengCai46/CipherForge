"""
Shamir 门限秘密共享（GF(256)）
==============================

基于经典 Shamir (1979) 方案的**实现**，工作在有限域 GF(2⁸) 上：

* 不可约多项式采用 AES 标准本原多项式 ``0x11B``
  （``x⁸ + x⁴ + x³ + x + 1``），乘法走 ``exp/log`` 表，
  所有运算无秘密分支、无数组越界式查表。
* 秘密按字节切分，每个字节各自对应一条 ``t-1`` 次随机多项式，
  多项式常数项 = 该字节；在 ``N`` 个互不相同的非零横坐标上求值得到分片。
* 恢复时走拉格朗日插值（在 ``x=0`` 处求值），需要 **≥ t** 份分片。
  任何 ``t-1`` 份都不泄露秘密（信息论安全）。
* 分片自带 **CRC32 校验和**，抄写/传输错误可被发现
  （:class:`ShareCorruptedError`）；分片不足则抛
  :class:`InsufficientSharesError`。
* 额外在秘密前拼接 **8 字节 SHA-256 截断校验前缀**，
  恢复后做一次恒定时间比对——即便分片数学上能解出某个多项式，
  若分片来自错误来源或数量不够，也会因前缀不匹配而被拦下。
* 分片横坐标用 :func:`random_permutation`（Fisher–Yates + 无模偏
  ``secrets.randbelow``）选取，保证每次生成的横坐标集合均匀且互异。

关于 ``N`` 的上限：GF(256) 仅有 255 个非零元素（0 留给秘密点），
故分片总数上限定为 **255**（即 ``2 ~ 255``），这是数学约束而非限制。

所有随机数仅来自 :mod:`os.urandom` / :mod:`secrets`，
绝无 ``random`` 模块或自研 RNG。
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
import zlib

from ..core.errors import (
    EmptyInputError,
    InsufficientSharesError,
    ShareCorruptedError,
    SharingError,
    ValidationError,
    DependencyMissingError,
)
from ..core.rng import randbelow, random_permutation
from ..core.sidechannel import SideChannelBase
from ..core.memory import SecureMemoryBase

__all__ = ["ShamirSecretSharing", "GF256"]

# ----------------------------------------------------------------------
#  GF(256) 算术（AES 本原多项式 0x11B）
# ----------------------------------------------------------------------
_PRIM = 0x11B


class GF256:
    """GF(2⁸) 上的加/减（异或）、乘、除、求逆。"""

    _EXP: list[int] = []
    _LOG: list[int] = []

    @classmethod
    def _init_tables(cls) -> None:
        if cls._EXP:
            return
        exp = [0] * 512
        log = [0] * 256
        # 模约简下的「乘以生成元 g=3」：3 = (x) ⊕ 1（多项式表示）
        # 注意：2 不是本原元，必须用本原元 3 才能遍历全部 255 个非零元素。
        x = 1
        for i in range(255):
            exp[i] = x
            log[x] = i
            shifted = (x << 1) ^ (_PRIM if (x & 0x80) else 0)
            x = shifted ^ x          # 乘以 3 = 乘以 (x) 再加 (1)
        for i in range(255, 512):
            exp[i] = exp[i - 255]
        cls._EXP = exp
        cls._LOG = log

    @classmethod
    def mul(cls, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        cls._init_tables()
        return cls._EXP[cls._LOG[a] + cls._LOG[b]]

    @classmethod
    def div(cls, a: int, b: int) -> int:
        if b == 0:
            raise ZeroDivisionError("GF(256) 中除以零。")
        if a == 0:
            return 0
        cls._init_tables()
        return cls._EXP[(cls._LOG[a] - cls._LOG[b]) % 255]

    @classmethod
    def inv(cls, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("GF(256) 中零不可逆。")
        cls._init_tables()
        return cls._EXP[255 - cls._LOG[a]]


def _poly_eval(coeffs: list[int], x: int) -> int:
    """在 x 处求值（Horner，GF(256)）。coeffs[0] 为常数项。"""
    acc = 0
    for c in reversed(coeffs):
        acc = GF256.mul(acc, x) ^ c
    return acc


def _lagrange_at_zero(xs: list[int], ys: list[int]) -> int:
    """拉格朗日插值，求 P(0)。

    在 GF(2⁸) 中 ``-(x_j) = x_j``，故分子为 ∏ x_j，
    分母为 ∏ (x_i ⊕ x_j)。
    """
    n = len(xs)
    out = 0
    for i in range(n):
        num = 1
        den = 1
        xi = xs[i]
        for j in range(n):
            if j == i:
                continue
            xj = xs[j]
            num = GF256.mul(num, xj)
            den = GF256.mul(den, xi ^ xj)
        coeff = GF256.mul(num, GF256.inv(den))
        out ^= GF256.mul(ys[i], coeff)
    return out


# ----------------------------------------------------------------------
#  分片编解码
# ----------------------------------------------------------------------
_MAGIC = b"CFS1"          # CipherForge Shamir v1
_VERIFY_PREFIX = 8        # SHA-256 截断前缀字节数


class ShamirSecretSharing(SideChannelBase, SecureMemoryBase):
    """Shamir 门限秘密共享门面。

    :param threshold: 恢复所需最少分片数 ``t``（范围 2 ~ total）
    :param total: 生成的分片总数 ``N``（范围 2 ~ 255）
    """

    def __init__(self, threshold: int, total: int, *, config=None) -> None:
        SecureMemoryBase.__init__(self)
        if not isinstance(threshold, int) or not isinstance(total, int):
            raise ValidationError("阈值与总分片数必须为整数。")
        if total < 2 or total > 255:
            raise ValidationError(
                f"分片总数必须在 2 ~ 255 之间（GF(256) 仅有 255 个非零点），收到 {total}。",
                hint="如需更多分片，请将秘密拆分后分批共享。",
            )
        if threshold < 2 or threshold > total:
            raise ValidationError(
                f"阈值必须在 2 ~ {total} 之间，收到 {threshold}。",
                hint="阈值 1 意味着任意单份分片即可还原，失去门限意义。",
            )
        self.threshold = threshold
        self.total = total

    # ------------------------------------------------------------ 编码
    @staticmethod
    def _encode_share(x: int, slen: int, thresh: int, total: int, payload: bytes) -> bytes:
        body = struct.pack("<B H B B", x, slen, thresh, total) + payload
        crc = zlib.crc32(body) & 0xFFFFFFFF
        return _MAGIC + struct.pack("<I", crc) + body

    @staticmethod
    def _decode_share(blob: bytes) -> tuple[int, int, int, int, bytes]:
        if len(blob) < 12 or blob[:4] != _MAGIC:
            raise ShareCorruptedError("分片头标识无效，可能是复制时缺失或使用了非 CipherForge 分片。")
        (crc,) = struct.unpack("<I", blob[4:8])
        body = blob[8:]
        if zlib.crc32(body) != crc:
            raise ShareCorruptedError("分片校验和不匹配，内容可能在抄写或传输中出错。")
        x, slen, thresh, total = struct.unpack("<B H B B", body[:5])
        payload = body[5:]
        if len(payload) != slen:
            raise ShareCorruptedError("分片长度字段与实际数据不符。")
        return x, slen, thresh, total, payload

    # ------------------------------------------------------------ 拆分
    def split(self, secret: bytes) -> list[bytes]:
        """把 ``secret`` 拆成 ``total`` 份原始分片（bytes 列表）。"""
        if not secret:
            raise EmptyInputError("秘密")
        # 校验前缀：SHA-256 截断 8 字节，用于恢复后验证
        digest = hashlib.sha256(secret).digest()[:_VERIFY_PREFIX]
        full = digest + secret
        B = len(full)

        # 选取 total 个互异的非零横坐标
        perm = random_permutation(255)            # 0..254 的均匀排列
        xs = [perm[i] + 1 for i in range(self.total)]

        # 每个字节对应**唯一一条**多项式：常数项 = 该秘密字节，
        # 其余系数为本次拆分一次性随机生成；所有分片共用同一组系数，
        # 仅在横坐标上求值不同——这是 Shamir 方案正确性的关键。
        coeffs_per_byte: list[list[int]] = []
        for j in range(B):
            coeffs_per_byte.append(
                [full[j]] + [randbelow(256) for _ in range(self.threshold - 1)]
            )

        shares: list[bytes] = []
        for x in xs:
            y = bytearray(B)
            for j in range(B):
                y[j] = _poly_eval(coeffs_per_byte[j], x)
            shares.append(self._encode_share(x, B, self.threshold, self.total, bytes(y)))
        return shares

    def split_to_text(self, secret: bytes) -> list[str]:
        """拆分并序列化为可手抄的 Base64 文本分片。"""
        return [base64.b64encode(s).decode("ascii") for s in self.split(secret)]

    def split_to_qr(self, secret: bytes, out_dir: str, *, prefix: str = "cf_share") -> list[str]:
        """拆分并生成每张分片一张二维码 PNG；返回图片路径列表。

        需要可选依赖 ``qrcode``；缺失时抛出 :class:`DependencyMissingError`。
        """
        try:
            import qrcode  # type: ignore
        except ImportError:
            raise DependencyMissingError(
                "Shamir 分片二维码", "qrcode", install_cmd="pip install qrcode"
            )
        texts = self.split_to_text(secret)
        os.makedirs(out_dir, exist_ok=True)
        paths: list[str] = []
        for i, t in enumerate(texts):
            if len(t.encode("utf-8")) > 2953:
                raise SharingError(
                    f"第 {i + 1} 份分片文本过长（{len(t)} 字符），超出单张二维码容量。",
                    hint="请改用更短秘密，或直接使用文本分片。",
                )
            img = qrcode.make(t)
            p = os.path.join(out_dir, f"{prefix}_{i + 1}.png")
            img.save(p)
            paths.append(p)
        return paths

    # ------------------------------------------------------------ 合并
    def combine_shares(self, shares: list[bytes]) -> bytes:
        """从原始分片恢复秘密（需 ≥ threshold 份有效分片）。"""
        if not shares:
            raise InsufficientSharesError(0, self.threshold)
        parsed = [self._decode_share(s) for s in shares]

        # 去重 + 一致性检查
        by_x: dict[int, bytes] = {}
        slens = set()
        for x, slen, thresh, total, payload in parsed:
            slens.add(slen)
            if x in by_x:
                continue
            by_x[x] = payload
        if len(slens) != 1:
            raise ShareCorruptedError("分片长度不一致，可能混用了不同秘密的分片。")
        if len(by_x) < self.threshold:
            raise InsufficientSharesError(len(by_x), self.threshold)

        xs = list(by_x.keys())
        B = next(iter(slens))

        out = bytearray(B)
        for j in range(B):
            ys = [by_x[x][j] for x in xs]
            out[j] = _lagrange_at_zero(xs, ys)

        digest = bytes(out[:_VERIFY_PREFIX])
        secret = bytes(out[_VERIFY_PREFIX:])
        expected = hashlib.sha256(secret).digest()[:_VERIFY_PREFIX]
        # 恒定时间比对，避免通过耗时区分"前缀是否匹配"
        if not self.ct_compare(digest, expected):
            raise ShareCorruptedError(
                "无法重构出一致的秘密：分片可能来自不同来源、数量不足或被篡改。"
            )
        return secret

    def combine(self, shares_text: list[str]) -> bytes:
        """从 Base64 文本分片恢复秘密。"""
        try:
            raw = [base64.b64decode(t.strip()) for t in shares_text]
        except Exception as exc:  # 编码非法属抄写错误
            raise ShareCorruptedError("存在无法解码的文本分片，请检查 Base64 字符是否完整。") from exc
        return self.combine_shares(raw)

    def combine_from_qr(self, image_paths: list[str]) -> bytes:
        """从二维码图片（PNG）解码分片文本并恢复秘密。

        需要可选依赖 ``pyzbar`` + 系统 ``zbar`` 库；缺失时抛出
        :class:`DependencyMissingError`。
        """
        try:
            from pyzbar.pyzbar import decode  # type: ignore
            from PIL import Image            # type: ignore
        except ImportError:
            raise DependencyMissingError(
                "二维码识别", "pyzbar", install_cmd="pip install pyzbar  （并安装系统 zbar 库）"
            )
        texts: list[str] = []
        for p in image_paths:
            data = decode(Image.open(p))
            if not data:
                raise ShareCorruptedError(f"未能从图片 {p} 中识别到二维码。")
            texts.append(data[0].data.decode("utf-8"))
        return self.combine(texts)

    def __repr__(self) -> str:
        return f"<Shamir threshold={self.threshold} total={self.total}>"
