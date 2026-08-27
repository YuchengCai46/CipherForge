"""
LSB 隐写（PNG / BMP / JPG）
==========================

把**已加密**的载荷藏入位图载体图像的最低有效位（Least Significant Bit）。

设计要点
--------

* **载体支持**：PNG、BMP 为有损无关格式，LSB 写入后无损保存；
  JPG 因有损重编码会破坏 LSB，故读取 JPG 载体后**始终以 PNG 输出**，
  以保证隐藏数据可完整提取。
* **位深 1~4 bit**：每个颜色通道字节可藏 1~4 个比特。位深越高容量越大，
  但视觉异常与统计异常也越明显——这是容量与隐蔽性的权衡。
* **随机化嵌入顺序**：嵌入位置由口令派生的起点 ``start`` 驱动，沿一条
  大素数步长 ``s`` 的**单环置换**遍历全部像素字节（``gcd(s, N)=1``，
  一次遍历恰好覆盖所有位置，且无需 O(N) 内存的置换数组）。
  口令不同 → 起点不同 → 嵌入位置完全不同，攻击者即使拿到载体也无法
  预判数据散布规律。
* **机密性 + 完整性**：载荷在嵌入前先用 **HKDF-SHA256 派生密钥 +
  AES-256-GCM**（均来自 ``cryptography`` 的 OpenSSL 后端，恒定时间）加密，
  再 zlib 压缩后写入 LSB。因此即便隐写层被剥离，数据仍不可读；
  口令错误则 GCM 认证失败，绝不会吐出明文。
* **自校验**：载荷尾部带 CRC32，提取后先校验再解密，错误口令 / 错误载体
  统一抛 :class:`NoHiddenDataError`，不向攻击者泄露差异。

所有随机数（盐、Nonce、起点熵）仅来自 :mod:`os.urandom` / :mod:`secrets`。
"""

from __future__ import annotations

import hashlib
import math
import struct
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from PIL import Image

from ..core.errors import (
    ValidationError,
    NoHiddenDataError,
    CarrierTooSmallError,
)
from ..core.rng import random_nonce, random_salt

__all__ = ["LSBSteganography", "lsb_capacity"]

_MAGIC = b"CFST"       # CipherForge Stego v1
_VERSION = 1
_INFO = b"CipherForge-Stego-v1"
_MASK_REF = (1 << 4) - 1   # 用于位深上限 4

# ----------------------------------------------------------------------
#  容量计算
# ----------------------------------------------------------------------
def lsb_capacity(pixels_bytes: int, bit_depth: int) -> int:
    """返回在 ``pixels_bytes`` 个通道字节、``bit_depth`` 位深下可容纳的
    载荷**字节数**（含本模块的固定头/校验开销）。
    """
    if bit_depth <= 0 or bit_depth > 4:
        raise ValidationError("位深必须在 1 ~ 4 之间。")
    usable_bits = pixels_bytes * bit_depth
    # 固定结构：magic(4) + version(1) + len(4) + flags(1) + enc + crc(4)
    overhead = 14
    return max(0, usable_bits // 8 - overhead)


# ----------------------------------------------------------------------
#  加密辅助（HKDF + AES-256-GCM，均来自经审计的 cryptography 后端）
# ----------------------------------------------------------------------
def _encrypt_payload(data: bytes, password: str) -> bytes:
    salt = random_salt(16)
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=_INFO
    ).derive(password.encode("utf-8"))
    nonce = random_nonce(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    # 自包含密文 = salt(16) || nonce(12) || ct(tag)
    return salt + nonce + ct


def _decrypt_payload(blob: bytes, password: str) -> bytes:
    if len(blob) < 16 + 12 + 16:
        raise NoHiddenDataError()
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=_INFO
    ).derive(password.encode("utf-8"))
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as exc:  # GCM 认证失败：口令错误或数据被破坏
        raise NoHiddenDataError() from exc


# ----------------------------------------------------------------------
#  隐写引擎
# ----------------------------------------------------------------------
class LSBSteganography:
    """LSB 隐写引擎。

    :param bit_depth: 每个通道字节嵌入的比特数（1~4）
    """

    def __init__(self, bit_depth: int = 1) -> None:
        if not isinstance(bit_depth, int) or not (1 <= bit_depth <= 4):
            raise ValidationError("位深必须在 1 ~ 4 之间（整数）。")
        self.bit_depth = bit_depth
        self._mask = (1 << bit_depth) - 1

    # ------------------------------------------------------------ 隐藏
    def hide(self, data: bytes, carrier_path: str, out_path: str, *, password: str) -> int:
        """把 ``data`` 加密后藏入 ``carrier_path``，结果写至 ``out_path``。

        :return: 实际写入的载荷字节数
        """
        if not data:
            raise ValidationError("待隐藏数据不能为空。", hint="请先提供要隐藏的内容。")
        if not password:
            raise ValidationError("隐写必须设置口令。")

        img = Image.open(carrier_path)
        img = img.convert("RGB")
        buf = bytearray(img.tobytes())
        N = len(buf)

        enc = _encrypt_payload(data, password)
        comp = zlib.compress(enc, 9)
        frame = _MAGIC + struct.pack("<B I B", _VERSION, len(comp), self.bit_depth) + comp
        crc = zlib.crc32(frame) & 0xFFFFFFFF
        blob = frame + struct.pack("<I", crc)

        struct_len = len(blob)
        # 计算所需通道字节数（每个通道字节承载 bit_depth 比特）
        need_bytes = (struct_len * 8 + self.bit_depth - 1) // self.bit_depth
        if need_bytes > N:
            raise CarrierTooSmallError(struct_len, lsb_capacity(N, self.bit_depth), self.bit_depth)

        start = self._start(password, N)
        s = self._step(N)
        self._embed(buf, blob, start, s, N)

        out = Image.frombytes("RGB", img.size, bytes(buf))
        # JPG 重编码会破坏 LSB，故始终以 PNG 保存
        out.save(out_path, format="PNG")
        return struct_len

    # ------------------------------------------------------------ 提取
    def reveal(self, stego_path: str, *, password: str, bit_depth: int | None = None) -> bytes:
        """从隐写图片中提取并解密数据。

        ``bit_depth`` 缺省时使用隐藏时记录的位深（从结构 flags 读取，
        但需先以 1 bit 读头——为简单与健壮，要求调用方显式传入与隐藏时
        一致的位深；若与记录不符将抛 :class:`NoHiddenDataError`）。
        """
        if not password:
            raise ValidationError("提取必须提供口令。")
        bd = bit_depth if bit_depth is not None else self.bit_depth

        img = Image.open(stego_path).convert("RGB")
        buf = bytearray(img.tobytes())
        N = len(buf)

        start = self._start(password, N)
        s = self._step(N)

        # 先读固定头（10 字节：magic4 + ver1 + len4 + flags1）以获知总长与记录位深
        bits = self._extract(buf, start, s, N, count_bytes=10, bit_depth=bd)
        header = self._bits_to_bytes(bits, 10)
        if len(header) < 10 or header[:4] != _MAGIC:
            raise NoHiddenDataError()
        (comp_len,) = struct.unpack("<I", header[5:9])
        rec_bd = header[9]
        if rec_bd != bd:
            raise NoHiddenDataError()
        total_bytes = 10 + comp_len + 4  # header + comp + crc
        if total_bytes * 8 > N * bd:
            raise NoHiddenDataError()

        bits = self._extract(buf, start, s, N, count_bytes=total_bytes, bit_depth=bd)
        blob = self._bits_to_bytes(bits, total_bytes)
        if len(blob) < total_bytes:
            raise NoHiddenDataError()
        struct_, crc_bytes = blob[: total_bytes - 4], blob[total_bytes - 4 : total_bytes]
        (crc,) = struct.unpack("<I", crc_bytes)
        if zlib.crc32(struct_) != crc:
            raise NoHiddenDataError()
        comp_len = struct.unpack("<I", struct_[5:9])[0]
        comp = struct_[10 : 10 + comp_len]
        try:
            enc = zlib.decompress(comp)
        except Exception as exc:
            raise NoHiddenDataError() from exc
        return _decrypt_payload(enc, password)

    # ------------------------------------------------------------ 内部
    @staticmethod
    def _start(password: str, N: int) -> int:
        h = hashlib.sha256(password.encode("utf-8")).digest()[:4]
        return int.from_bytes(h, "big") % max(1, N)

    @staticmethod
    def _step(N: int) -> int:
        # 大素数步长，保证与任意合理 N 互素（N << 2^31-1 恒成立）
        s = 2_147_483_647
        while math.gcd(s, N) != 1:
            s += 2
        return s

    def _embed(self, buf: bytearray, blob: bytes, start: int, s: int, N: int) -> None:
        bit_depth = self.bit_depth
        mask = self._mask
        # 展平为完整比特流：每个载荷字节贡献 8 个比特（与位深无关）
        bits: list[int] = []
        for byte in blob:
            for b in range(8):
                bits.append((byte >> b) & 1)
        # 每个通道位置承载 bit_depth 个连续比特
        npositions = (len(bits) + bit_depth - 1) // bit_depth
        for i in range(npositions):
            pos = (start + i * s) % N
            chunk = 0
            for k in range(bit_depth):
                idx = i * bit_depth + k
                if idx < len(bits):
                    chunk |= (bits[idx] << k)
            buf[pos] = (buf[pos] & ~mask) | chunk

    def _extract(self, buf: bytearray, start: int, s: int, N: int, *, count_bytes: int, bit_depth: int) -> list[int]:
        mask = (1 << bit_depth) - 1
        bits: list[int] = []
        total_bits = count_bytes * 8
        for i in range((total_bits + bit_depth - 1) // bit_depth):
            pos = (start + i * s) % N
            v = buf[pos] & mask
            for k in range(bit_depth):
                bits.append((v >> k) & 1)
            if len(bits) >= total_bits:
                break
        return bits[:total_bits]

    @staticmethod
    def _bits_to_bytes(bits: list[int], nbytes: int) -> bytes:
        out = bytearray()
        for i in range(nbytes):
            byte = 0
            for k in range(8):
                idx = i * 8 + k
                if idx < len(bits):
                    byte |= (bits[idx] << k)
            out.append(byte)
        return bytes(out)

    def capacity(self, carrier_path: str) -> int:
        """返回该载体在当前位深下可容纳的载荷字节数。"""
        img = Image.open(carrier_path).convert("RGB")
        n = len(img.tobytes())
        return lsb_capacity(n, self.bit_depth)
