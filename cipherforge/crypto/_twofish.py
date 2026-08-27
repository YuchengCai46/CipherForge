"""
Twofish 纯 Python 实现（ECB 分组密码）
=====================================

纯 Python 的 Twofish(128/192/256 位密钥，128 位分组) 实现，改编自
Dr. Brian Gladman 的公开参考实现（BSD 许可），并随附官方 Known Answer
Test 向量（见模块底部 ``_selftest``）。

之所以自带纯 Python 实现：部分 ``pycryptodome`` 二进制分发包未编译
Serpent/Twofish 扩展，导致无法从 ``Crypto.Cipher`` 导入。本实现保证
CipherForge 在无这些扩展的环境中仍能提供 ``Twofish-GCM``。

接口：``Twofish(key).encrypt_block(block16)`` / ``.decrypt_block(block16)``
返回 16 字节。CTR/HMAC 封装由调用方（``symmetric._CTR_HMAC_AEAD``）完成。

性能：纯 Python 比 C 慢约 20~50 倍，仅建议用于密钥/签名等小数据。
"""

from __future__ import annotations

import struct
import sys

# 改编自 Bjorn Edstrom / Brian Gladman 的纯 Python Twofish 实现。
# 原始版权：Dr B R Gladman，BSD 许可（允许自由派生与使用）。

WORD_BIGENDIAN = 1 if sys.byteorder == "big" else 0


def _rotr32(x: int, n: int) -> int:
    return (x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)


def _rotl32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _byteswap32(x: int) -> int:
    return (((x & 0xFF) << 24) | (((x >> 8) & 0xFF) << 16)
            | (((x >> 16) & 0xFF) << 8) | ((x >> 24) & 0xFF))


class _TWI:
    def __init__(self):
        self.k_len = 0
        self.l_key = [0] * 40
        self.s_key = [0] * 4
        self.qt_gen = 0
        self.q_tab = [[0] * 256, [0] * 256]
        self.mt_gen = 0
        self.m_tab = [[0] * 256, [0] * 256, [0] * 256, [0] * 256]
        self.mk_tab = [[0] * 256, [0] * 256, [0] * 256, [0] * 256]


def _byte(x: int, n: int) -> int:
    return (x >> (8 * n)) & 0xFF


_tab_5b = [0, 90, 180, 238]
_tab_ef = [0, 238, 180, 90]
_ror4 = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
_ashx = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]
_qt0 = [
    [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
    [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5],
]
_qt1 = [
    [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
    [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8],
]
_qt2 = [
    [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
    [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15],
]
_qt3 = [
    [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
    [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10],
]


def _qp(n: int, x: int) -> int:
    a0 = x >> 4
    b0 = x & 15
    a1 = a0 ^ b0
    b1 = _ror4[b0] ^ _ashx[a0]
    a2 = _qt0[n][a1]
    b2 = _qt1[n][b1]
    a3 = a2 ^ b2
    b3 = _ror4[b2] ^ _ashx[a2]
    a4 = _qt2[n][a3]
    b4 = _qt3[n][b3]
    return (b4 << 4) | a4


def _gen_qtab(pkey: _TWI) -> None:
    for i in range(256):
        pkey.q_tab[0][i] = _qp(0, i)
        pkey.q_tab[1][i] = _qp(1, i)


def _gen_mtab(pkey: _TWI) -> None:
    for i in range(256):
        f01 = pkey.q_tab[1][i]
        f5b = (f01 ^ (f01 >> 2) ^ _tab_5b[f01 & 3])
        fef = (f01 ^ (f01 >> 1) ^ (f01 >> 2) ^ _tab_ef[f01 & 3])
        pkey.m_tab[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24)
        pkey.m_tab[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24)

        f01 = pkey.q_tab[0][i]
        f5b = (f01 ^ (f01 >> 2) ^ _tab_5b[f01 & 3])
        fef = (f01 ^ (f01 >> 1) ^ (f01 >> 2) ^ _tab_ef[f01 & 3])
        pkey.m_tab[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24)
        pkey.m_tab[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24)


def _gen_mk_tab(pkey: _TWI, key) -> None:
    if pkey.k_len == 2:
        for i in range(256):
            by = i % 0x100
            pkey.mk_tab[0][i] = pkey.m_tab[0][pkey.q_tab[0][pkey.q_tab[0][by] ^ _byte(key[1], 0)] ^ _byte(key[0], 0)]
            pkey.mk_tab[1][i] = pkey.m_tab[1][pkey.q_tab[0][pkey.q_tab[1][by] ^ _byte(key[1], 1)] ^ _byte(key[0], 1)]
            pkey.mk_tab[2][i] = pkey.m_tab[2][pkey.q_tab[1][pkey.q_tab[0][by] ^ _byte(key[1], 2)] ^ _byte(key[0], 2)]
            pkey.mk_tab[3][i] = pkey.m_tab[3][pkey.q_tab[1][pkey.q_tab[1][by] ^ _byte(key[1], 3)] ^ _byte(key[0], 3)]
    elif pkey.k_len == 3:
        for i in range(256):
            by = i % 0x100
            pkey.mk_tab[0][i] = pkey.m_tab[0][pkey.q_tab[0][pkey.q_tab[0][pkey.q_tab[1][by] ^ _byte(key[2], 0)] ^ _byte(key[1], 0)] ^ _byte(key[0], 0)]
            pkey.mk_tab[1][i] = pkey.m_tab[1][pkey.q_tab[0][pkey.q_tab[1][pkey.q_tab[1][by] ^ _byte(key[2], 1)] ^ _byte(key[1], 1)] ^ _byte(key[0], 1)]
            pkey.mk_tab[2][i] = pkey.m_tab[2][pkey.q_tab[1][pkey.q_tab[0][pkey.q_tab[0][by] ^ _byte(key[2], 2)] ^ _byte(key[1], 2)] ^ _byte(key[0], 2)]
            pkey.mk_tab[3][i] = pkey.m_tab[3][pkey.q_tab[1][pkey.q_tab[1][pkey.q_tab[0][by] ^ _byte(key[2], 3)] ^ _byte(key[1], 3)] ^ _byte(key[0], 3)]
    else:  # k_len == 4
        for i in range(256):
            by = i % 0x100
            pkey.mk_tab[0][i] = pkey.m_tab[0][pkey.q_tab[0][pkey.q_tab[0][pkey.q_tab[1][pkey.q_tab[1][by] ^ _byte(key[3], 0)] ^ _byte(key[2], 0)] ^ _byte(key[1], 0)] ^ _byte(key[0], 0)]
            pkey.mk_tab[1][i] = pkey.m_tab[1][pkey.q_tab[0][pkey.q_tab[1][pkey.q_tab[1][pkey.q_tab[0][by] ^ _byte(key[3], 1)] ^ _byte(key[2], 1)] ^ _byte(key[1], 1)] ^ _byte(key[0], 1)]
            pkey.mk_tab[2][i] = pkey.m_tab[2][pkey.q_tab[1][pkey.q_tab[0][pkey.q_tab[0][pkey.q_tab[0][by] ^ _byte(key[3], 2)] ^ _byte(key[2], 2)] ^ _byte(key[1], 2)] ^ _byte(key[0], 2)]
            pkey.mk_tab[3][i] = pkey.m_tab[3][pkey.q_tab[1][pkey.q_tab[1][pkey.q_tab[0][pkey.q_tab[1][by] ^ _byte(key[3], 3)] ^ _byte(key[2], 3)] ^ _byte(key[1], 3)] ^ _byte(key[0], 3)]


def _h_fun(pkey: _TWI, x: int, key) -> int:
    b0 = _byte(x, 0)
    b1 = _byte(x, 1)
    b2 = _byte(x, 2)
    b3 = _byte(x, 3)
    if pkey.k_len >= 4:
        b0 = pkey.q_tab[1][b0] ^ _byte(key[3], 0)
        b1 = pkey.q_tab[0][b1] ^ _byte(key[3], 1)
        b2 = pkey.q_tab[0][b2] ^ _byte(key[3], 2)
        b3 = pkey.q_tab[1][b3] ^ _byte(key[3], 3)
    if pkey.k_len >= 3:
        b0 = pkey.q_tab[1][b0] ^ _byte(key[2], 0)
        b1 = pkey.q_tab[1][b1] ^ _byte(key[2], 1)
        b2 = pkey.q_tab[0][b2] ^ _byte(key[2], 2)
        b3 = pkey.q_tab[0][b3] ^ _byte(key[2], 3)
    if pkey.k_len >= 2:
        b0 = pkey.q_tab[0][pkey.q_tab[0][b0] ^ _byte(key[1], 0)] ^ _byte(key[0], 0)
        b1 = pkey.q_tab[0][pkey.q_tab[1][b1] ^ _byte(key[1], 1)] ^ _byte(key[0], 1)
        b2 = pkey.q_tab[1][pkey.q_tab[0][b2] ^ _byte(key[1], 2)] ^ _byte(key[0], 2)
        b3 = pkey.q_tab[1][pkey.q_tab[1][b3] ^ _byte(key[1], 3)] ^ _byte(key[0], 3)
    return (pkey.m_tab[0][b0] ^ pkey.m_tab[1][b1] ^ pkey.m_tab[2][b2] ^ pkey.m_tab[3][b3]) & 0xFFFFFFFF


def _mds_rem(p0: int, p1: int) -> int:
    p0 &= 0xFFFFFFFF
    p1 &= 0xFFFFFFFF
    for _ in range(8):
        t = p1 >> 24
        p1 = ((p1 << 8) & 0xFFFFFFFF) | (p0 >> 24)
        p0 = (p0 << 8) & 0xFFFFFFFF
        u = (t << 1) & 0xFFFFFFFF
        if t & 0x80:
            u ^= 0x0000014D
        p1 ^= t ^ ((u << 16) & 0xFFFFFFFF)
        u ^= (t >> 1)
        if t & 0x01:
            u ^= 0x0000014D >> 1
        p1 ^= ((u << 24) & 0xFFFFFFFF) | ((u << 8) & 0xFFFFFFFF)
    return p1 & 0xFFFFFFFF


def _set_key(pkey: _TWI, in_key, key_len: int) -> None:
    if not pkey.qt_gen:
        _gen_qtab(pkey)
        pkey.qt_gen = 1
    if not pkey.mt_gen:
        _gen_mtab(pkey)
        pkey.mt_gen = 1
    pkey.k_len = (key_len * 8) // 64

    me_key = [0, 0, 0, 0]
    mo_key = [0, 0, 0, 0]
    for i in range(pkey.k_len):
        a = in_key[i + i]
        me_key[i] = a
        b = in_key[i + i + 1]
        mo_key[i] = b
        pkey.s_key[pkey.k_len - i - 1] = _mds_rem(a, b)

    for i in range(0, 40, 2):
        a = (0x01010101 * i) % 0x100000000
        b = (a + 0x01010101) % 0x100000000
        a = _h_fun(pkey, a, me_key)
        b = _rotl32(_h_fun(pkey, b, mo_key), 8)
        pkey.l_key[i] = (a + b) % 0x100000000
        pkey.l_key[i + 1] = _rotl32((a + 2 * b) % 0x100000000, 9)
    _gen_mk_tab(pkey, pkey.s_key)


def _encrypt(pkey: _TWI, in_blk) -> None:
    blk = [0, 0, 0, 0]
    blk[0] = in_blk[0] ^ pkey.l_key[0]
    blk[1] = in_blk[1] ^ pkey.l_key[1]
    blk[2] = in_blk[2] ^ pkey.l_key[2]
    blk[3] = in_blk[3] ^ pkey.l_key[3]

    for i in range(8):
        t1 = (pkey.mk_tab[0][_byte(blk[1], 3)] ^ pkey.mk_tab[1][_byte(blk[1], 0)] ^
              pkey.mk_tab[2][_byte(blk[1], 1)] ^ pkey.mk_tab[3][_byte(blk[1], 2)])
        t0 = (pkey.mk_tab[0][_byte(blk[0], 0)] ^ pkey.mk_tab[1][_byte(blk[0], 1)] ^
              pkey.mk_tab[2][_byte(blk[0], 2)] ^ pkey.mk_tab[3][_byte(blk[0], 3)])

        blk[2] = _rotr32(blk[2] ^ ((t0 + t1 + pkey.l_key[4 * i + 8]) % 0x100000000), 1)
        blk[3] = _rotl32(blk[3], 1) ^ ((t0 + 2 * t1 + pkey.l_key[4 * i + 9]) % 0x100000000)

        t1 = (pkey.mk_tab[0][_byte(blk[3], 3)] ^ pkey.mk_tab[1][_byte(blk[3], 0)] ^
              pkey.mk_tab[2][_byte(blk[3], 1)] ^ pkey.mk_tab[3][_byte(blk[3], 2)])
        t0 = (pkey.mk_tab[0][_byte(blk[2], 0)] ^ pkey.mk_tab[1][_byte(blk[2], 1)] ^
              pkey.mk_tab[2][_byte(blk[2], 2)] ^ pkey.mk_tab[3][_byte(blk[2], 3)])

        blk[0] = _rotr32(blk[0] ^ ((t0 + t1 + pkey.l_key[4 * i + 10]) % 0x100000000), 1)
        blk[1] = _rotl32(blk[1], 1) ^ ((t0 + 2 * t1 + pkey.l_key[4 * i + 11]) % 0x100000000)

    in_blk[0] = blk[2] ^ pkey.l_key[4]
    in_blk[1] = blk[3] ^ pkey.l_key[5]
    in_blk[2] = blk[0] ^ pkey.l_key[6]
    in_blk[3] = blk[1] ^ pkey.l_key[7]


def _decrypt(pkey: _TWI, in_blk) -> None:
    blk = [0, 0, 0, 0]
    blk[0] = in_blk[0] ^ pkey.l_key[4]
    blk[1] = in_blk[1] ^ pkey.l_key[5]
    blk[2] = in_blk[2] ^ pkey.l_key[6]
    blk[3] = in_blk[3] ^ pkey.l_key[7]

    for i in range(7, -1, -1):
        t1 = (pkey.mk_tab[0][_byte(blk[1], 3)] ^ pkey.mk_tab[1][_byte(blk[1], 0)] ^
              pkey.mk_tab[2][_byte(blk[1], 1)] ^ pkey.mk_tab[3][_byte(blk[1], 2)])
        t0 = (pkey.mk_tab[0][_byte(blk[0], 0)] ^ pkey.mk_tab[1][_byte(blk[0], 1)] ^
              pkey.mk_tab[2][_byte(blk[0], 2)] ^ pkey.mk_tab[3][_byte(blk[0], 3)])

        blk[2] = _rotl32(blk[2], 1) ^ ((t0 + t1 + pkey.l_key[4 * i + 10]) % 0x100000000)
        blk[3] = _rotr32(blk[3] ^ ((t0 + 2 * t1 + pkey.l_key[4 * i + 11]) % 0x100000000), 1)

        t1 = (pkey.mk_tab[0][_byte(blk[3], 3)] ^ pkey.mk_tab[1][_byte(blk[3], 0)] ^
              pkey.mk_tab[2][_byte(blk[3], 1)] ^ pkey.mk_tab[3][_byte(blk[3], 2)])
        t0 = (pkey.mk_tab[0][_byte(blk[2], 0)] ^ pkey.mk_tab[1][_byte(blk[2], 1)] ^
              pkey.mk_tab[2][_byte(blk[2], 2)] ^ pkey.mk_tab[3][_byte(blk[2], 3)])

        blk[0] = _rotl32(blk[0], 1) ^ ((t0 + t1 + pkey.l_key[4 * i + 8]) % 0x100000000)
        blk[1] = _rotr32(blk[1] ^ ((t0 + 2 * t1 + pkey.l_key[4 * i + 9]) % 0x100000000), 1)

    in_blk[0] = blk[2] ^ pkey.l_key[0]
    in_blk[1] = blk[3] ^ pkey.l_key[1]
    in_blk[2] = blk[0] ^ pkey.l_key[2]
    in_blk[3] = blk[1] ^ pkey.l_key[3]


class Twofish:
    """Twofish 分组密码（128 位分组，密钥 16/24/32 字节）。

    提供 ECB 风格的 ``encrypt_block`` / ``decrypt_block``（各 16 字节）。
    CTR + HMAC 的 AEAD 封装由上层完成。
    """

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish 密钥长度必须是 16/24/32 字节。")
        self._ctx = _TWI()
        words = list(struct.unpack("<%dL" % (len(key) // 4), key))
        _set_key(self._ctx, words, len(key))

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Twofish 分组必须为 16 字节。")
        blk = list(struct.unpack("<4L", block))
        _encrypt(self._ctx, blk)
        return struct.pack("<4L", *blk)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Twofish 分组必须为 16 字节。")
        blk = list(struct.unpack("<4L", block))
        _decrypt(self._ctx, blk)
        return struct.pack("<4L", *blk)


def _selftest() -> bool:
    key = bytes.fromhex("D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F")
    pt = bytes.fromhex("90AFE91BB288544F2C32DC239B2635E6")
    ct = bytes.fromhex("6CB4561C40BF0A9705931CB6D408E7FA")
    c = Twofish(key)
    enc = c.encrypt_block(pt)
    dec = c.decrypt_block(ct)
    assert enc == ct, f"Twofish KAT 失败: 得到 {enc.hex()}"
    assert dec == pt, "Twofish 解密 KAT 失败"
    return True
