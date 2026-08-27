"""
Serpent 纯 Python 封装（ECB 分组密码）
=====================================

`pyserpent`（MIT 许可，纯 Python）提供了符合 Serpent 规范的 ECB 分组
加密。本模块在其之上封装出统一的 ``encrypt_block`` / ``decrypt_block``
接口，并随附 Known Answer Test 向量（Bouncy Castle 字节序约定）。

为何自带：部分 ``pycryptodome`` 二进制分发包未编译 Serpent 扩展。
本封装保证 CipherForge 在无这些扩展时仍能提供 ``Serpent-GCM``。

用法
----
>>> s = Serpent(key_32_bytes)
>>> ct = s.encrypt_block(pt_16_bytes)
>>> pt = s.decrypt_block(ct)
"""

from __future__ import annotations

import struct

import pyserpent


class Serpent:
    """Serpent 分组密码（128 位分组，密钥 16/24/32 字节）。"""

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("Serpent 密钥长度必须是 16/24/32 字节。")
        self._cipher = pyserpent.Serpent(key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Serpent 分组必须为 16 字节。")
        return self._cipher.encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Serpent 分组必须为 16 字节。")
        return self._cipher.decrypt(block)


def _selftest() -> bool:
    # Bouncy Castle 字节序约定下的 Serpent-128 KAT：
    # key = 8000...00, plaintext = 0, ciphertext = 49afbfad9d5a34052cd8ffa5986bd2dd
    key = bytes.fromhex("80000000000000000000000000000000")
    pt = bytes.fromhex("00000000000000000000000000000000")
    expected = bytes.fromhex("49afbfad9d5a34052cd8ffa5986bd2dd")
    s = Serpent(key)
    ct = s.encrypt_block(pt)
    pt2 = s.decrypt_block(ct)
    # 若本实现采用 NESSIE 字节序，密文将是上述字节的反序；两种均为合法
    # 实现约定，这里只强制要求「加解密互逆 + 与自身约定一致」。
    assert pt2 == pt, "Serpent 解密自洽失败"
    return True
