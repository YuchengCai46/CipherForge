"""
高级哈希引擎
============

统一封装主流**经审计**的哈希原语（均来自 Python 标准库 :mod:`hashlib`，
底层由 OpenSSL / 平台实现背书）：

* **SHA-2**：``SHA-224 / 256 / 384 / 512``
* **SHA-3**：``SHA3-224 / 256 / 384 / 512``（Keccak，FIPS 202）
* **BLAKE2**：``BLAKE2b / BLAKE2s``（高度抗碰撞，快于 SHA-2）
* **SHAKE**：``SHAKE128 / SHAKE256``（可扩展输出，XOF，需指定输出长度）

特性
----

* **Pepper（胡椒）**：一段由安全 RNG 生成的随机秘密，参与哈希输入但
  **绝不写入磁盘**——用户需自行保管。它把"仅知道数据"与"能验证哈希"
  二者解耦，类似服务端 pepper 的抗泄露思路。
* **一键惰性校验**：``verify`` 在需要时才计算并比较，且用
  :func:`hmac.compare_digest` 做恒定时间比较，避免时序侧信道。
* 所有算法名、输出长度、是否 XOF 均有自描述元数据，便于 GUI 展示。

所有随机数（Pepper）仅来自 :mod:`os.urandom` / :mod:`secrets`，
不引入任何手写密码学。
"""

from __future__ import annotations

import hashlib
import hmac

from ..core.errors import UnsupportedAlgorithmError, ValidationError
from ..core.rng import random_bytes

__all__ = ["HashEngine", "SUPPORTED_HASHES", "HashInfo", "generate_pepper"]

# 算法元数据：name -> (hashlib 构造名, 是否 XOF, 默认输出字节, 是否支持自定义长度)
_HASH_META: dict[str, tuple[str, bool, int | None]] = {
    "SHA-224": ("sha224", False, 28),
    "SHA-256": ("sha256", False, 32),
    "SHA-384": ("sha384", False, 48),
    "SHA-512": ("sha512", False, 64),
    "SHA3-224": ("sha3_224", False, 28),
    "SHA3-256": ("sha3_256", False, 32),
    "SHA3-384": ("sha3_384", False, 48),
    "SHA3-512": ("sha3_512", False, 64),
    "BLAKE2b": ("blake2b", False, 64),
    "BLAKE2s": ("blake2s", False, 32),
    "SHAKE128": ("shake_128", True, 64),
    "SHAKE256": ("shake_256", True, 64),
}

SUPPORTED_HASHES = tuple(_HASH_META.keys())


class HashInfo:
    """单个哈希算法的自描述信息。"""

    def __init__(self, name: str, lib_name: str, xof: bool, default_len: int | None) -> None:
        self.name = name
        self.lib_name = lib_name
        self.xof = xof
        self.default_len = default_len

    def __repr__(self) -> str:
        kind = "XOF(可扩展)" if self.xof else "定长"
        return f"<Hash {self.name} {kind} default={self.default_len}B>"


def _resolve(algo: str) -> tuple[str, bool, int | None]:
    meta = _HASH_META.get(algo)
    if meta is None:
        raise UnsupportedAlgorithmError(algo, SUPPORTED_HASHES)
    return meta


def generate_pepper(size: int = 32) -> bytes:
    """生成一段 Pepper（安全随机字节）。

    ⚠ 调用方负责保管；本函数与哈希引擎都**不会**把它写入磁盘。
    """
    if size <= 0:
        raise ValidationError("Pepper 长度必须为正数。")
    return random_bytes(size)


class HashEngine:
    """高级哈希引擎门面。

    典型用法::

        he = HashEngine()
        pepper = generate_pepper()            # 自行保管，不落盘
        digest = he.hash(data, "SHA-256", pepper=pepper)
        # 之后验证：
        assert he.verify(data, digest, "SHA-256", pepper=pepper)
    """

    def supported(self) -> list[str]:
        """返回所有支持的算法名。"""
        return list(SUPPORTED_HASHES)

    def info(self, algo: str) -> HashInfo:
        """返回算法的自描述元数据。"""
        lib_name, xof, default_len = _resolve(algo)
        return HashInfo(algo, lib_name, xof, default_len)

    # ------------------------------------------------------------ 核心
    def _build(self, algo: str, shake_len: int | None):
        """构造哈希对象。返回 ``(hash_obj, is_xof, xof_len | None)``。

        ⚠ 注意：Python 3.13 的 :func:`hashlib.new` 已不再接受
        ``digest_size`` 关键字（XOF 长度需通过 ``hash_obj.digest(len)``
        在最终输出时传入），故此处只回传 ``xof_len`` 供调用方使用。
        """
        lib_name, xof, default_len = _resolve(algo)
        if xof:
            if shake_len is None:
                shake_len = default_len or 64
            if shake_len <= 0:
                raise ValidationError("SHAKE 需要正数输出长度（字节）。")
            return hashlib.new(lib_name), True, shake_len
        return hashlib.new(lib_name), False, None

    def hash_raw(
        self,
        data: bytes,
        algo: str,
        *,
        pepper: bytes | None = None,
        shake_len: int | None = None,
    ) -> bytes:
        """计算原始字节摘要。``pepper`` 若存在则前缀到输入。"""
        h, xof, slen = self._build(algo, shake_len)
        if pepper:
            h.update(pepper)
        h.update(data)
        return h.digest(slen) if xof else h.digest()

    def hash(
        self,
        data: bytes,
        algo: str,
        *,
        pepper: bytes | None = None,
        shake_len: int | None = None,
    ) -> str:
        """计算十六进制摘要（默认输出）。"""
        return self.hash_raw(data, algo, pepper=pepper, shake_len=shake_len).hex()

    def verify(
        self,
        data: bytes,
        expected_hex: str,
        algo: str,
        *,
        pepper: bytes | None = None,
        shake_len: int | None = None,
    ) -> bool:
        """惰性校验：仅在调用时计算并用恒定时间比较。

        返回 ``True`` 表示数据 + Pepper 与预期摘要一致。
        """
        try:
            actual = self.hash_raw(data, algo, pepper=pepper, shake_len=shake_len)
        except Exception:
            return False
        try:
            expected = bytes.fromhex(expected_hex)
        except ValueError:
            return False
        return hmac.compare_digest(actual, expected)

    # ------------------------------------------------------------ 便捷
    def file_hash(
        self,
        path: str,
        algo: str,
        *,
        chunk_size: int = 1 << 20,
        pepper: bytes | None = None,
        shake_len: int | None = None,
    ) -> str:
        """对大文件做流式哈希（避免整文件载入内存）。"""
        h, xof, slen = self._build(algo, shake_len)
        if pepper:
            h.update(pepper)
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest(slen) if xof else h.hexdigest()
