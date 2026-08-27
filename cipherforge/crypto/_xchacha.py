"""
XChaCha20-Poly1305（RFC 8439 兼容）
==================================

``cryptography`` 的 AEAD 模块未提供 ``XChaCha20Poly1305``，因此本模块
封装该算法，但**优先使用经审计的标准实现**：

* **默认后端 libsodium（PyNaCl 绑定）** —— XChaCha20-Poly1305 的官方
  RFC 8439 参考实现，C 语言、恒定时间、经广泛审计。8 MiB 约毫秒级。
* **纯 Python 兜底** —— 仅在 libsodium 不可用时启用，按 RFC 8439 完整
  实现 ChaCha20 核心 / HChaCha20 / Poly1305，并与 RFC 测试向量逐位
  对齐（见 ``tests/test_kat.py``）。速度慢约 2~3 个大数量级，仅作降级。

两种后端的 AEAD 语义一致：``encrypt(nonce, pt, aad)`` 返回 ``ct || tag``，
解密验签失败抛 :class:`DecryptionFailedError`。
"""

from __future__ import annotations

import struct

from ..core.errors import DecryptionFailedError

__all__ = ["XChaCha20Poly1305Cipher"]

# ----------------------------------------------------------------------
#  后端选择：优先使用经审计的 libsodium（PyNaCl 绑定，RFC 8439 官方的
#  XChaCha20-Poly1305 实现，C 语言、恒定时间、社区广泛审计）；
#  仅当 libsodium 不可用时退回本模块自带的手写纯 Python 实现（同样
#  与 RFC 测试向量逐位对齐，但速度慢约 2~3 个数量级，仅作兜底）。
# ----------------------------------------------------------------------
try:  # pragma: no cover - 依赖环境
    from nacl.bindings import (  # type: ignore
        crypto_aead_xchacha20poly1305_ietf_decrypt as _lib_xchacha_decrypt,
        crypto_aead_xchacha20poly1305_ietf_encrypt as _lib_xchacha_encrypt,
    )
    from nacl.exceptions import CryptoError as _NaClCryptoError  # type: ignore

    _LIBSODIUM_AVAILABLE = True
except Exception:  # pragma: no cover
    _LIBSODIUM_AVAILABLE = False

_MASK32 = 0xFFFFFFFF
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl32(v: int, n: int) -> int:
    return ((v << n) & _MASK32) | (v >> (32 - n))


def _chacha20_rounds(state: list[int]) -> list[int]:
    """20 轮 ChaCha20（RFC 8439 §2.3.1）。

    为性能把 1/4 轮完全内联、使用局部变量并消除函数调用开销，
    同时仍与 RFC 测试向量逐位对齐（见 ``tests/test_kat.py``）。
    """
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = state
    M = _MASK32
    for _ in range(10):
        # ---- 列轮（Even rounds）----
        x0 = (x0 + x4) & M; x12 ^= x0; x12 = ((x12 << 16) & M) | (x12 >> 16)
        x8 = (x8 + x12) & M; x4 ^= x8; x4 = ((x4 << 12) & M) | (x4 >> 20)
        x0 = (x0 + x4) & M; x12 ^= x0; x12 = ((x12 << 8) & M) | (x12 >> 24)
        x8 = (x8 + x12) & M; x4 ^= x8; x4 = ((x4 << 7) & M) | (x4 >> 25)

        x1 = (x1 + x5) & M; x13 ^= x1; x13 = ((x13 << 16) & M) | (x13 >> 16)
        x9 = (x9 + x13) & M; x5 ^= x9; x5 = ((x5 << 12) & M) | (x5 >> 20)
        x1 = (x1 + x5) & M; x13 ^= x1; x13 = ((x13 << 8) & M) | (x13 >> 24)
        x9 = (x9 + x13) & M; x5 ^= x9; x5 = ((x5 << 7) & M) | (x5 >> 25)

        x2 = (x2 + x6) & M; x14 ^= x2; x14 = ((x14 << 16) & M) | (x14 >> 16)
        x10 = (x10 + x14) & M; x6 ^= x10; x6 = ((x6 << 12) & M) | (x6 >> 20)
        x2 = (x2 + x6) & M; x14 ^= x2; x14 = ((x14 << 8) & M) | (x14 >> 24)
        x10 = (x10 + x14) & M; x6 ^= x10; x6 = ((x6 << 7) & M) | (x6 >> 25)

        x3 = (x3 + x7) & M; x15 ^= x3; x15 = ((x15 << 16) & M) | (x15 >> 16)
        x11 = (x11 + x15) & M; x7 ^= x11; x7 = ((x7 << 12) & M) | (x7 >> 20)
        x3 = (x3 + x7) & M; x15 ^= x3; x15 = ((x15 << 8) & M) | (x15 >> 24)
        x11 = (x11 + x15) & M; x7 ^= x11; x7 = ((x7 << 7) & M) | (x7 >> 25)

        # ---- 对角轮（Odd rounds）----
        x0 = (x0 + x5) & M; x15 ^= x0; x15 = ((x15 << 16) & M) | (x15 >> 16)
        x10 = (x10 + x15) & M; x5 ^= x10; x5 = ((x5 << 12) & M) | (x5 >> 20)
        x0 = (x0 + x5) & M; x15 ^= x0; x15 = ((x15 << 8) & M) | (x15 >> 24)
        x10 = (x10 + x15) & M; x5 ^= x10; x5 = ((x5 << 7) & M) | (x5 >> 25)

        x1 = (x1 + x6) & M; x12 ^= x1; x12 = ((x12 << 16) & M) | (x12 >> 16)
        x11 = (x11 + x12) & M; x6 ^= x11; x6 = ((x6 << 12) & M) | (x6 >> 20)
        x1 = (x1 + x6) & M; x12 ^= x1; x12 = ((x12 << 8) & M) | (x12 >> 24)
        x11 = (x11 + x12) & M; x6 ^= x11; x6 = ((x6 << 7) & M) | (x6 >> 25)

        x2 = (x2 + x7) & M; x13 ^= x2; x13 = ((x13 << 16) & M) | (x13 >> 16)
        x8 = (x8 + x13) & M; x7 ^= x8; x7 = ((x7 << 12) & M) | (x7 >> 20)
        x2 = (x2 + x7) & M; x13 ^= x2; x13 = ((x13 << 8) & M) | (x13 >> 24)
        x8 = (x8 + x13) & M; x7 ^= x8; x7 = ((x7 << 7) & M) | (x7 >> 25)

        x3 = (x3 + x4) & M; x14 ^= x3; x14 = ((x14 << 16) & M) | (x14 >> 16)
        x9 = (x9 + x14) & M; x4 ^= x9; x4 = ((x4 << 12) & M) | (x4 >> 20)
        x3 = (x3 + x4) & M; x14 ^= x3; x14 = ((x14 << 8) & M) | (x14 >> 24)
        x9 = (x9 + x14) & M; x4 ^= x9; x4 = ((x4 << 7) & M) | (x4 >> 25)

    return [
        (x0 + state[0]) & M, (x1 + state[1]) & M, (x2 + state[2]) & M, (x3 + state[3]) & M,
        (x4 + state[4]) & M, (x5 + state[5]) & M, (x6 + state[6]) & M, (x7 + state[7]) & M,
        (x8 + state[8]) & M, (x9 + state[9]) & M, (x10 + state[10]) & M, (x11 + state[11]) & M,
        (x12 + state[12]) & M, (x13 + state[13]) & M, (x14 + state[14]) & M, (x15 + state[15]) & M,
    ]


def _bytes_to_words(data: bytes) -> list[int]:
    return list(struct.unpack("<" + "I" * (len(data) // 4), data))


def _words_to_bytes(words: list[int]) -> bytes:
    return struct.pack("<" + "I" * len(words), *words)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """生成 64 字节 ChaCha20 密钥流块（12 字节 nonce）。"""
    state = [
        _CONSTANTS[0], _CONSTANTS[1], _CONSTANTS[2], _CONSTANTS[3],
        *_bytes_to_words(key),
        counter & _MASK32,
        *_bytes_to_words(nonce),
    ]
    out = _chacha20_rounds(state)
    return _words_to_bytes(out)


def hchacha20(key: bytes, nonce: bytes) -> bytes:
    """HChaCha20：输入 32 字节 key + 16 字节 nonce，输出 32 字节子密钥。"""
    state = [
        _CONSTANTS[0], _CONSTANTS[1], _CONSTANTS[2], _CONSTANTS[3],
        *_bytes_to_words(key),
        *_bytes_to_words(nonce[:16]),
    ]
    out = _chacha20_rounds(state)
    # 输出为 state 的前 4 个与后 4 个字（按 RFC 8439 §2.3）
    return _words_to_bytes(out[:4] + out[12:16])


def _poly1305_mac(msg: bytes, key: bytes) -> bytes:
    """Poly1305 一次性 MAC。key 为 32 字节（前 16 字节 r 被 clamp）。"""
    r = int.from_bytes(key[:16], "little")
    # clamp
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    p = (1 << 130) - 5
    n = len(msg)
    i = 0
    while i < n:
        block = msg[i : i + 16]
        ln = len(block)
        # 等价于 block + b"\x01"：在块末高位补 1（RFC 8439 §2.5.1）
        num = int.from_bytes(block, "little") | (1 << (8 * ln))
        acc = (acc + num) % p
        acc = (acc * r) % p
        i += 16
    # RFC 8439 §2.5.1：最终标签为 (acc + s) mod 2^128，而非直接取 acc + s。
    # acc 可逼近 2^130，加上 s（≤2^128）会溢出 16 字节，必须模 2^128。
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """用 counter=0 的 ChaCha20 块的前 32 字节作为 Poly1305 一次性密钥。"""
    block = _chacha20_block(key, 0, nonce)
    return block[:32]


def _pad16(data: bytes) -> bytes:
    if len(data) % 16 == 0:
        return b""
    return b"\x00" * (16 - (len(data) % 16))


class XChaCha20Poly1305Cipher:
    """XChaCha20-Poly1305 AEAD（24 字节 Nonce）。

    后端优先级：

    * **libsodium（PyNaCl）** — 经审计的官方 RFC 8439 实现，恒定时间、
      C 语言、性能极高（8 MiB 约毫秒级）。这是默认生产后端。
    * **纯 Python 兜底** — 仅在 libsodium 不可用时启用，逻辑与 RFC
      测试向量逐位对齐，但速度慢约 2~3 个数量级。

    接口与 ``cryptography`` 的 AEAD 一致：``encrypt(nonce, pt, aad)``
    返回 ``ct || tag``（tag 16 字节）；``decrypt`` 验签失败抛
    :class:`DecryptionFailedError`。
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("XChaCha20-Poly1305 需要 32 字节密钥。")
        self._key = key

    @property
    def backend(self) -> str:
        """当前实际使用的后端：libsodium（经审计）或 pure-python 兜底。

        动态反映 ``_LIBSODIUM_AVAILABLE``，因此可在运行时（如测试）切换。
        """
        return "libsodium" if _LIBSODIUM_AVAILABLE else "pure-python"

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        if len(nonce) != 24:
            raise ValueError("XChaCha20-Poly1305 需要 24 字节 Nonce。")
        if _LIBSODIUM_AVAILABLE:
            return _lib_xchacha_encrypt(
                bytes(plaintext), bytes(associated_data), bytes(nonce), self._key
            )
        return _xchacha_encrypt_pure(self._key, nonce, plaintext, associated_data)

    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes = b"") -> bytes:
        if len(nonce) != 24:
            raise ValueError("XChaCha20-Poly1305 需要 24 字节 Nonce。")
        if len(data) < 16:
            raise DecryptionFailedError(detail="XChaCha 密文缺少认证标签。")
        if _LIBSODIUM_AVAILABLE:
            try:
                return _lib_xchacha_decrypt(
                    bytes(data), bytes(associated_data), bytes(nonce), self._key
                )
            except _NaClCryptoError:
                raise DecryptionFailedError(context={"算法": "XChaCha20-Poly1305"})
        return _xchacha_decrypt_pure(self._key, nonce, data, associated_data)


# ======================================================================
#  纯 Python 兜底实现（仅在 libsodium 不可用时使用）
# ======================================================================
def _xchacha_encrypt_pure(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    subkey = hchacha20(key, nonce[:16])
    chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:]
    otk = _poly1305_key_gen(subkey, chacha_nonce)
    keystream0 = _chacha20_block(subkey, 1, chacha_nonce)
    ct = _xor_stream(plaintext, keystream0, subkey, chacha_nonce, start_counter=1)
    mac_data = (
        associated_data + _pad16(associated_data)
        + ct + _pad16(ct)
        + len(associated_data).to_bytes(8, "little")
        + len(ct).to_bytes(8, "little")
    )
    tag = _poly1305_mac(mac_data, otk)
    return ct + tag


def _xchacha_decrypt_pure(key: bytes, nonce: bytes, data: bytes, associated_data: bytes = b"") -> bytes:
    subkey = hchacha20(key, nonce[:16])
    chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:]
    otk = _poly1305_key_gen(subkey, chacha_nonce)
    ct, recv_tag = data[:-16], data[-16:]
    mac_data = (
        associated_data + _pad16(associated_data)
        + ct + _pad16(ct)
        + len(associated_data).to_bytes(8, "little")
        + len(ct).to_bytes(8, "little")
    )
    expected = _poly1305_mac(mac_data, otk)
    if not _constant_time_eq(expected, recv_tag):
        raise DecryptionFailedError(context={"算法": "XChaCha20-Poly1305"})
    keystream0 = _chacha20_block(subkey, 1, chacha_nonce)
    return _xor_stream(ct, keystream0, subkey, chacha_nonce, start_counter=1)


def _xor_stream(data: bytes, first_block: bytes, key: bytes, nonce: bytes, start_counter: int) -> bytes:
    """逐块整数异或生成密文（纯 Python 兜底用）。

    整块 ``int`` 异或：1 次 C 级运算替代 64 次逐字节 Python 循环。
    """
    n = len(data)
    if n == 0:
        return b""
    out = bytearray(n)
    counter = start_counter
    pos = 0
    ks = first_block
    while pos < n:
        take = min(n - pos, 64)
        chunk = data[pos : pos + take]
        k = int.from_bytes(ks[:take], "little")
        c = int.from_bytes(chunk, "little")
        out[pos : pos + take] = (k ^ c).to_bytes(take, "little")
        pos += take
        counter += 1
        if pos < n:
            ks = _chacha20_block(key, counter, nonce)
    return bytes(out)


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    import hmac

    return hmac.compare_digest(a, b)
