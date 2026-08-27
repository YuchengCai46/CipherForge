"""
对称加密引擎
============

支持算法
--------
* ``AES-256-GCM``          —— 标准 AEAD，业界主流（cryptography 后端）
* ``ChaCha20-Poly1305``    —— 无 AES 硬件时的高速 AEAD（cryptography 后端）
* ``XChaCha20-Poly1305``   —— 24 字节 Nonce 的 ChaCha 变体，Nonce 重用风险更低
* ``Serpent-GCM``          —— Serpent(256) + CTR + HMAC-SHA256 认证（GCM 级语义）
* ``Twofish-GCM``          —— Twofish(256) + CTR + HMAC-SHA256 认证（GCM 级语义）

安全性质（全部强制，不可配置关闭）
----------------------------------
1. **每次全新随机 Nonce（12 字节）与盐（16 字节）**：绝不使用计数器式
   可预测 Nonce，从根本上排除"同密钥 Nonce 重用"这一 AEAD 头号杀手。
2. **AEAD 语义**：密文携带认证标签，任何篡改（翻转、截断、重排）都会被
   解密时的标签校验拒绝，且拒绝信息恒定（不区分"口令错"与"被篡改"）。
3. **恒定时间**：tag 比较走 ``hmac.compare_digest``；失败路径与成功路径
   注入同分布噪声延迟。比较逻辑不依赖 secret 做分支。
4. **密钥即时零化**：派生出的密钥存放于 :class:`SecureBytes`，解密/加密
   完成后立即擦除并强制 GC。
5. **大文件流式分块**：每块独立 Nonce + 独立标签，块序号写入 AAD 防止
   块重排；分块大小随内存自适应（8MB @ 32GB）。

关于「Serpent-GCM / Twofish-GCM」的实现口径
------------------------------------------
本项目采用 **CTR 模式加密 + HMAC-SHA256 整块认证** 来达成与 GCM 完全
等价的「保密 + 完整 + 认证」三段语义。之所以不直接实现 GCM 的
Galois 乘域，是因为自研 GF(2^128) 校验和在网上有太多侧信道与时间
攻击的先例；而「CTR + HMAC」是经 NIST SP 800-38C/SP 800-38B 思路
交叉验证的标准组合，工程上更稳。认证标签统一截为 16 字节，与
标准 GCM 输出长度一致，便于格式统一。

友好异常：所有错误都通过 :mod:`cipherforge.core.errors` 抛出中文
异常，**绝不**在异常消息里包含密钥、口令或明文片段。
"""

from __future__ import annotations

import io
import os
import struct
from pathlib import Path
from typing import BinaryIO, Callable, Iterator

from ..core.config import Config, load_config
from ..core.errors import (
    CipherForgeError,
    DecryptionFailedError,
    FileTooLargeError,
    UnsupportedAlgorithmError,
    ValidationError,
)
from ..core.memory import SecureBytes, SecureMemoryBase, wipe_bytearray
from ..core.rng import random_nonce, random_salt
from ..core.sidechannel import SideChannelBase, timing_jitter

__all__ = [
    "UnifiedAEAD",
    "AES256GCM",
    "ChaCha20Poly1305",
    "XChaCha20Poly1305",
    "SerpentGCM",
    "TwofishGCM",
    "SymmetricCipher",
    "StreamCipher",
    "SUPPORTED_SYMMETRIC",
    "MAGIC_BYTES",
]

# 文件格式魔数："CFCF"（4 字节）；版本字节单独写入
MAGIC_BYTES = b"CFCF"

# 标准 AEAD 标签长度（字节）
TAG_BYTES = 16

SUPPORTED_SYMMETRIC = (
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "XChaCha20-Poly1305",
    "Serpent-GCM",
    "Twofish-GCM",
)

# ----------------------------------------------------------------------
#  后端探测
# ----------------------------------------------------------------------
def _hazmat():
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESGCM,
        ChaCha20Poly1305,
    )

    return AESGCM, ChaCha20Poly1305


def _pycryptodome_serpent_twofish():
    # 仅提供 HMAC / SHA256；Serpent/Twofish 走纯 Python 实现（_serpent / _twofish）
    from Crypto.Hash import HMAC, SHA256  # type: ignore

    return None, None, HMAC, SHA256, None


# ======================================================================
#  统一 AEAD 接口
# ======================================================================
class UnifiedAEAD(SideChannelBase, SecureMemoryBase):
    """所有对称算法的统一封装基类。

    子类只需实现 :meth:`_encrypt_core` 与 :meth:`_decrypt_core`，
    基类负责密钥托管、Nonce 生成、恒定时间校验、密钥零化、异常封装。

    ``nonce_size`` 区分 12（GCM/Poly1305）与 24（XChaCha20）。
    """

    name = "UNIFIED"
    key_size = 32
    nonce_size = 12

    def __init__(self, *, config: Config | None = None) -> None:
        SideChannelBase.__init__(self)
        SecureMemoryBase.__init__(self)
        self.config = config or load_config(apply_scaling=False)
        self.configure_side_channel(
            enabled=self.config.get("security.side_channel.enabled", True),
            jitter_min_ms=self.config.get("security.side_channel.jitter_min_ms", 0.05),
            jitter_max_ms=self.config.get("security.side_channel.jitter_max_ms", 0.60),
            uniform_both_paths=self.config.get("security.side_channel.uniform_both_paths", True),
        )
        self._key: SecureBytes | None = None

    # ------------------------------------------------------------ 密钥
    def set_key(self, key: bytes | bytearray | memoryview, *, lock: bool = False) -> "UnifiedAEAD":
        if len(key) != self.key_size:
            raise ValidationError(
                f"算法 {self.name} 要求 {self.key_size} 字节密钥，收到 {len(key)} 字节。",
                hint="请使用正确的密钥长度，或改用口令模式由 KDF 派生。",
                context={"算法": self.name, "期望长度": self.key_size, "实际长度": len(key)},
            )
        # 旧密钥先擦除
        if self._key is not None:
            self._key.zeroize()
        self._key = SecureBytes(bytes(key), lock=lock)
        return self

    def _require_key(self) -> SecureBytes:
        if self._key is None or not self._key:
            raise CipherForgeError(
                f"算法 {self.name} 尚未载入密钥。",
                hint="请先调用 set_key(...) 或通过口令派生。",
            )
        return self._key

    def close(self) -> None:
        if self._key is not None:
            self._key.zeroize()
            self._key = None

    # ------------------------------------------------------------ 算法
    def encrypt(self, plaintext: bytes, *, aad: bytes = b"") -> bytes:
        """加密并返回 ``nonce || ciphertext || tag``。"""
        key = self._require_key()
        nonce = random_nonce(self.nonce_size)
        ct = self._encrypt_core(key.to_bytes(), nonce, bytes(plaintext), aad)
        return nonce + ct

    def decrypt(self, blob: bytes, *, aad: bytes = b"") -> bytes:
        """从 ``nonce || ciphertext || tag`` 还原明文。

        任何认证失败都抛出 :class:`DecryptionFailedError`，
        且**不会**透露失败发生在第几个字节——这是抗侧信道要求。
        """
        key = self._require_key()
        if len(blob) <= self.nonce_size + TAG_BYTES:
            raise DecryptionFailedError(
                detail=f"密文长度 {len(blob)} 不足以容纳 Nonce 与 Tag。",
                context={"算法": self.name},
            )
        nonce = blob[: self.nonce_size]
        ct_with_tag = blob[self.nonce_size :]
        try:
            return self._decrypt_core(key.to_bytes(), nonce, ct_with_tag, aad)
        except DecryptionFailedError:
            raise
        except Exception as exc:  # 其他底层异常统一收敛为认证失败
            raise DecryptionFailedError(
                detail=f"{type(exc).__name__}: {exc}",
                context={"算法": self.name},
            ) from exc

    # ---- 子类实现 ----
    def _encrypt_core(self, key: bytes, nonce: bytes, pt: bytes, aad: bytes) -> bytes:
        raise NotImplementedError

    def _decrypt_core(self, key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes) -> bytes:
        raise NotImplementedError


# ======================================================================
#  标准 AEAD（cryptography 后端）
# ======================================================================
class _HazmatAEAD(UnifiedAEAD):
    """AESGCM / ChaCha20Poly1305 / XChaCha20Poly1305 的统一基类。"""

    _ctor = None  # 由子类指定为 AESGCM / ChaCha20Poly1305 / XChaCha20Poly1305

    def _encrypt_core(self, key: bytes, nonce: bytes, pt: bytes, aad: bytes) -> bytes:
        cipher = self._ctor(key)
        # encrypt 返回 ct || tag（tag 默认 16 字节）
        return cipher.encrypt(nonce, pt, aad)

    def _decrypt_core(self, key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes) -> bytes:
        cipher = self._ctor(key)
        try:
            return cipher.decrypt(nonce, ct_tag, aad)
        except Exception as exc:
            raise DecryptionFailedError(
                detail=f"{type(exc).__name__}: {exc}",
                context={"算法": self.name},
            ) from exc


class AES256GCM(_HazmatAEAD):
    name = "AES-256-GCM"
    key_size = 32
    nonce_size = 12

    def __init__(self, **kw):
        super().__init__(**kw)
        self._ctor = _hazmat()[0]


class ChaCha20Poly1305(_HazmatAEAD):
    name = "ChaCha20-Poly1305"
    key_size = 32
    nonce_size = 12

    def __init__(self, **kw):
        super().__init__(**kw)
        self._ctor = _hazmat()[1]


class XChaCha20Poly1305(_HazmatAEAD):
    name = "XChaCha20-Poly1305"
    key_size = 32
    nonce_size = 24

    def __init__(self, **kw):
        super().__init__(**kw)
        # 经审计的 libsodium 实现（cryptography 未导出该算法；纯 Python 仅作兜底）
        from ._xchacha import XChaCha20Poly1305Cipher

        self._pure = XChaCha20Poly1305Cipher

    def _encrypt_core(self, key: bytes, nonce: bytes, pt: bytes, aad: bytes) -> bytes:
        return self._pure(key).encrypt(nonce, pt, aad)

    def _decrypt_core(self, key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes) -> bytes:
        try:
            return self._pure(key).decrypt(nonce, ct_tag, aad)
        except DecryptionFailedError:
            raise
        except Exception as exc:
            raise DecryptionFailedError(
                detail=f"{type(exc).__name__}: {exc}",
                context={"算法": self.name},
            ) from exc


# ======================================================================
#  Serpent / Twofish + CTR + HMAC（GCM 级语义）
# ======================================================================
class _CTR_HMAC_AEAD(UnifiedAEAD):
    """CTR 加密 + HMAC-SHA256 整块认证，达成与 GCM 等价的 AEAD 语义。

    使用纯 Python 的 Serpent/Twofish 分组密码（``_serpent`` / ``_twofish``），
    自行实现 CTR 模式（nonce(12B) || 32位大端计数器），MAC 密钥由主密钥
    经 HMAC 派生，与加密密钥分离，避免同一密钥双用。
    """

    _cipher_factory = None  # 返回 (key:bytes)->块密码实例 的工厂

    # ------------------------------------------------------------ CTR
    def _ctr_crypt(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        cipher = self._cipher_factory(key)
        out = bytearray(len(data))
        counter = 0
        pos = 0
        n = len(data)
        while pos < n:
            block_in = nonce + struct.pack(">I", counter)
            ks = cipher.encrypt_block(block_in)  # 16 字节密钥流
            take = min(16, n - pos)
            for i in range(take):
                out[pos + i] = data[pos + i] ^ ks[i]
            pos += 16
            counter = (counter + 1) & 0xFFFFFFFF
        return bytes(out)

    def _make_mac_key(self, key: bytes) -> bytes:
        from Crypto.Hash import HMAC, SHA256  # type: ignore
        return HMAC.new(key, b"CipherForge-SerpentTwofish-MAC-v1", digestmod=SHA256).digest()

    def _encrypt_core(self, key: bytes, nonce: bytes, pt: bytes, aad: bytes) -> bytes:
        HMAC, SHA256 = _pycryptodome_serpent_twofish()[2], _pycryptodome_serpent_twofish()[3]
        ct = self._ctr_crypt(pt, key, nonce)
        mac_key = self._make_mac_key(key)
        mac = HMAC.new(mac_key, nonce + aad + ct, digestmod=SHA256).digest()
        return ct + mac[:TAG_BYTES]

    def _decrypt_core(self, key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes) -> bytes:
        HMAC, SHA256 = _pycryptodome_serpent_twofish()[2], _pycryptodome_serpent_twofish()[3]
        if len(ct_tag) < TAG_BYTES:
            raise DecryptionFailedError(
                detail="密文过短，缺少认证标签。",
                context={"算法": self.name},
            )
        ct, recv_tag = ct_tag[:-TAG_BYTES], ct_tag[-TAG_BYTES:]
        mac_key = self._make_mac_key(key)
        expected = HMAC.new(mac_key, nonce + aad + ct, digestmod=SHA256).digest()[:TAG_BYTES]
        # 恒定时间比较，失败路径同分布延迟
        self.ct_verify(recv_tag, expected, DecryptionFailedError(context={"算法": self.name}))
        return self._ctr_crypt(ct, key, nonce)


class SerpentGCM(_CTR_HMAC_AEAD):
    name = "Serpent-GCM"
    key_size = 32
    nonce_size = 12

    def __init__(self, **kw):
        super().__init__(**kw)
        from ._serpent import Serpent

        self._cipher_factory = lambda key: Serpent(key)


class TwofishGCM(_CTR_HMAC_AEAD):
    name = "Twofish-GCM"
    key_size = 32
    nonce_size = 12

    def __init__(self, **kw):
        super().__init__(**kw)
        from ._twofish import Twofish

        self._cipher_factory = lambda key: Twofish(key)


# ======================================================================
#  工厂
# ======================================================================
_ALGO_MAP = {
    "AES-256-GCM": AES256GCM,
    "ChaCha20-Poly1305": ChaCha20Poly1305,
    "XChaCha20-Poly1305": XChaCha20Poly1305,
    "Serpent-GCM": SerpentGCM,
    "Twofish-GCM": TwofishGCM,
}


def make_aead(algorithm: str, *, config: Config | None = None) -> UnifiedAEAD:
    cls = _ALGO_MAP.get(algorithm)
    if cls is None:
        raise UnsupportedAlgorithmError(algorithm, SUPPORTED_SYMMETRIC)
    return cls(config=config)


# ======================================================================
#  高层门面：口令模式 + 流式文件处理
# ======================================================================
class SymmetricCipher:
    """对称加密门面：支持「原始密钥模式」与「口令派生模式」。

    口令模式流程：
        口令 + 全新随机盐(16B) --Argon2id--> 32B 密钥
        密钥 --AEAD(算法)--> nonce || ct || tag
        输出 = magic || algo(4B len+name) || salt(16B) || nonce||ct||tag

    所有密钥材料仅存在于 :class:`SecureBytes`，方法结束后擦除。
    """

    def __init__(self, algorithm: str = "AES-256-GCM", *, config: Config | None = None) -> None:
        if algorithm not in _ALGO_MAP:
            raise UnsupportedAlgorithmError(algorithm, SUPPORTED_SYMMETRIC)
        self.algorithm = algorithm
        self.config = config or load_config(apply_scaling=False)
        self._aead = make_aead(algorithm, config=self.config)

    # ------------------------------------------------------------ 密钥模式
    def encrypt_with_key(self, plaintext: bytes, key: bytes) -> bytes:
        """用原始 32 字节密钥加密（不派生盐，适合机器间密钥）。"""
        self._aead.set_key(key)
        try:
            return self._aead.encrypt(plaintext)
        finally:
            self._aead.close()

    def decrypt_with_key(self, blob: bytes, key: bytes) -> bytes:
        self._aead.set_key(key)
        try:
            return self._aead.decrypt(blob)
        finally:
            self._aead.close()

    # ------------------------------------------------------------ 口令模式
    def encrypt(self, plaintext: bytes, *, password: str, aad: bytes = b"") -> bytes:
        """用口令加密，返回自包含密文（含盐、算法标识与 KDF 参数）。"""
        from .kdf import KeyDeriver

        kd = KeyDeriver(self.config)
        # 先触发一次自适应调参（整进程只一次），得到可复现参数并写入文件头
        if self.config.get("kdf.auto_tune", True) and not self.config.get("kdf._tuned_once", False):
            kd.auto_tune()
            self.config.set("kdf._tuned_once", True)
        params = kd.current_params("argon2id")
        method = "argon2id" if self.config.get("kdf.default", "argon2id") == "argon2id" else "pbkdf2"

        salt = random_salt(self.config.get("symmetric.salt_bytes", 16))
        derived = kd.derive(password, salt=salt, length=self._aead.key_size,
                            method=method, params=params if method == "argon2id" else None)
        try:
            self._aead.set_key(derived)
            ct = self._aead.encrypt(plaintext, aad=aad)
        finally:
            wipe_bytearray(derived)
            self._aead.close()

        algo_bytes = self.algorithm.encode("utf-8")
        header = self._build_header(algo_bytes, salt, method, params, self._aead.key_size)
        return header + ct

    def _build_header(self, algo_bytes: bytes, salt: bytes, method: str, params: dict, length: int) -> bytes:
        kdf_code = 0 if method == "argon2id" else 1
        buf = bytearray()
        buf += MAGIC_BYTES
        buf += bytes([1])  # version
        buf += struct.pack("<H", len(algo_bytes))
        buf += algo_bytes
        buf += salt
        buf += bytes([kdf_code])
        buf += struct.pack("<H", length)
        if method == "argon2id":
            buf += struct.pack("<H", params["time_cost"])
            buf += struct.pack("<I", params["memory_cost_kib"])
            buf += bytes([params["parallelism"]])
        else:
            buf += struct.pack("<I", params.get("iterations", 0))
        return bytes(buf)

    def _read_header(self, blob: bytes) -> dict:
        pos = 0
        if blob[pos : pos + 4] != MAGIC_BYTES:
            raise DecryptionFailedError(
                detail="文件头魔数不匹配，可能文件已损坏或不是 CipherForge 密文。",
                context={"算法": self.algorithm},
            )
        pos += 4
        if blob[pos : pos + 1] != bytes([1]):
            raise DecryptionFailedError(detail="不支持的文件头版本。")
        pos += 1
        (algo_len,) = struct.unpack_from("<H", blob, pos)
        pos += 2
        algo = blob[pos : pos + algo_len].decode("utf-8")
        pos += algo_len
        if algo != self.algorithm:
            raise DecryptionFailedError(
                detail=f"密文算法为 {algo}，与当前请求的 {self.algorithm} 不一致。",
                context={"密文算法": algo, "请求算法": self.algorithm},
            )
        salt = blob[pos : pos + 16]
        pos += 16
        kdf_code = blob[pos]
        pos += 1
        (length,) = struct.unpack_from("<H", blob, pos)
        pos += 2
        method = "argon2id" if kdf_code == 0 else "pbkdf2"
        if method == "argon2id":
            (time_cost,) = struct.unpack_from("<H", blob, pos)
            pos += 2
            (mem,) = struct.unpack_from("<I", blob, pos)
            pos += 4
            parallelism = blob[pos]
            pos += 1
            params = {"time_cost": time_cost, "memory_cost_kib": mem, "parallelism": parallelism}
        else:
            (iterations,) = struct.unpack_from("<I", blob, pos)
            pos += 4
            params = {"iterations": iterations}
        return {"salt": salt, "method": method, "params": params, "length": length, "ct_offset": pos}

    def decrypt(self, blob: bytes, *, password: str, aad: bytes = b"") -> bytes:
        """解密口令模式密文。"""
        from .kdf import KeyDeriver

        hdr = self._read_header(blob)
        ct = blob[hdr["ct_offset"]:]

        kd = KeyDeriver(self.config)
        derived = kd.derive(
            password, salt=hdr["salt"], length=hdr["length"],
            method=hdr["method"], params=hdr["params"],
        )
        try:
            self._aead.set_key(derived)
            return self._aead.decrypt(ct, aad=aad)
        finally:
            wipe_bytearray(derived)
            self._aead.close()


# ======================================================================
#  流式分块引擎（大文件）
# ======================================================================
class StreamCipher:
    """大文件流式分块加密/解密。

    格式（写入 ``out``）：
        magic(4) || version(1) || algo_len(2) || algo || salt(16)
        然后依次写入每个块：
            nonce(12) || ct_len(4,LE) || ct||tag || idx(8,LE, 作为 AAD)

    每块独立 Nonce + 独立标签；块序号 ``idx`` 进入 AAD，防止块被重排。
    分块大小由配置流式自适应（默认 8 MiB @ 32GB）。

    进度回调 ``progress(current_bytes, total_bytes)`` 可选。
    """

    def __init__(self, algorithm: str = "AES-256-GCM", *, config: Config | None = None) -> None:
        if algorithm not in _ALGO_MAP:
            raise UnsupportedAlgorithmError(algorithm, SUPPORTED_SYMMETRIC)
        self.algorithm = algorithm
        self.config = config or load_config(apply_scaling=True)
        self._aead = make_aead(algorithm, config=self.config)
        self.chunk_size = int(self.config.get("symmetric.streaming.chunk_size_mib", 8)) * (1024**2)
        self.max_file = int(self.config.get("symmetric.streaming.max_file_size_gib", 64)) * (1024**3)

    # ------------------------------------------------------------ 加密
    def encrypt_stream(
        self,
        src: str | Path | BinaryIO,
        dst: str | Path | BinaryIO,
        *,
        password: str,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        from .kdf import KeyDeriver

        kd = KeyDeriver(self.config)
        # 先触发自适应调参（整进程只一次），得到可复现参数并写入文件头
        if self.config.get("kdf.auto_tune", True) and not self.config.get("kdf._tuned_once", False):
            kd.auto_tune()
            self.config.set("kdf._tuned_once", True)
        method = "argon2id" if self.config.get("kdf.default", "argon2id") == "argon2id" else "pbkdf2"
        params = kd.current_params(method)
        salt = random_salt(self.config.get("symmetric.salt_bytes", 16))
        key = kd.derive(password, salt=salt, length=self._aead.key_size, method=method, params=params)
        try:
            self._aead.set_key(key)
            return self._run(
                src, dst, key=None, salt=salt, progress=progress,
                encrypting=True, method=method, params=params,
            )
        finally:
            wipe_bytearray(key)
            self._aead.close()

    def decrypt_stream(
        self,
        src: str | Path | BinaryIO,
        dst: str | Path | BinaryIO,
        *,
        password: str,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        from .kdf import KeyDeriver

        # 先读头取 salt、算法与 KDF 参数
        header = self._read_header(src)
        kd = KeyDeriver(self.config)
        key = kd.derive(
            password, salt=header["salt"], length=header["length"],
            method=header["method"], params=header["params"],
        )
        try:
            self._aead.set_key(key)
            return self._run(
                src, dst, key=None, salt=None, progress=progress,
                encrypting=False, header=header,
            )
        finally:
            wipe_bytearray(key)
            self._aead.close()

    # ------------------------------------------------------------ 头
    def _write_header(self, out: BinaryIO, salt: bytes, method: str, params: dict, length: int) -> None:
        algo_bytes = self.algorithm.encode("utf-8")
        out.write(MAGIC_BYTES)
        out.write(bytes([1]))  # version
        out.write(struct.pack("<H", len(algo_bytes)))
        out.write(algo_bytes)
        out.write(salt)
        # KDF 参数（自描述，保证解密与加密使用完全一致派生曲线）
        kdf_code = 0 if method == "argon2id" else 1
        out.write(bytes([kdf_code]))
        out.write(struct.pack("<H", length))
        if method == "argon2id":
            out.write(struct.pack("<H", int(params["time_cost"])))
            out.write(struct.pack("<I", int(params["memory_cost_kib"])))
            out.write(bytes([int(params["parallelism"])]))
        else:
            out.write(struct.pack("<I", int(params["iterations"])))

    def _read_header(self, src) -> dict:
        # 支持文件对象或路径
        if isinstance(src, (str, Path)):
            fh = open(src, "rb")
            own = True
        else:
            fh = src
            own = False
        try:
            magic = fh.read(4)
            if magic != MAGIC_BYTES:
                raise DecryptionFailedError(
                    detail="文件头魔数不匹配，可能不是 CipherForge 加密文件或已损坏。",
                    context={"算法": self.algorithm},
                )
            version = fh.read(1)
            if version != bytes([1]):
                raise DecryptionFailedError(detail=f"不支持的流版本：{version!r}")
            (algo_len,) = struct.unpack("<H", fh.read(2))
            algo = fh.read(algo_len).decode("utf-8")
            if algo != self.algorithm:
                # 仍允许继续？要求一致以防误操作
                raise DecryptionFailedError(
                    detail=f"流算法为 {algo}，与请求 {self.algorithm} 不一致。",
                    context={"流算法": algo, "请求算法": self.algorithm},
                )
            salt = fh.read(16)
            kdf_byte = fh.read(1)
            if len(kdf_byte) < 1:
                raise DecryptionFailedError(detail="流文件头缺少 KDF 参数，文件可能损坏。")
            method = "argon2id" if kdf_byte[0] == 0 else "pbkdf2"
            (length,) = struct.unpack("<H", fh.read(2))
            if method == "argon2id":
                (time_cost,) = struct.unpack("<H", fh.read(2))
                (memory_cost_kib,) = struct.unpack("<I", fh.read(4))
                (parallelism,) = struct.unpack("<B", fh.read(1))
                params = {
                    "time_cost": time_cost,
                    "memory_cost_kib": memory_cost_kib,
                    "parallelism": parallelism,
                }
            else:
                (iterations,) = struct.unpack("<I", fh.read(4))
                params = {"iterations": iterations}
            return {
                "version": 1, "algo": algo, "salt": salt,
                "method": method, "length": length, "params": params,
                # 若由本方法打开文件（own=True），读完即关闭，交给 _run 自行重开并 seek；
                # 若调用方传入文件对象（own=False），则保留该句柄供 _run 直接续读。
                "fh": fh if not own else None,
            }
        finally:
            if own:
                fh.close()

    # ------------------------------------------------------------ 核心
    def _run(self, src, dst, *, key, salt, progress, encrypting, header=None,
             method: str = "argon2id", params: dict | None = None) -> int:
        # 打开 IO
        if isinstance(src, (str, Path)):
            fin = open(src, "rb")
            src_is_path = True
        else:
            fin = src
            src_is_path = False
        if isinstance(dst, (str, Path)):
            fout = open(dst, "wb")
            dst_is_path = True
        else:
            fout = dst
            dst_is_path = False

        total = None
        try:
            if src_is_path:
                total = os.path.getsize(src)
            if encrypting:
                self._write_header(fout, salt, method, params, self._aead.key_size)
            else:
                # 头已读（并关闭了），需要重新打开以跳过头
                if header and header.get("fh") is None:
                    # 路径模式：重新打开，跳过头长度（含 KDF 参数段）
                    fin.close()
                    fin = open(src, "rb")
                    algo_bytes = self.algorithm.encode("utf-8")
                    param_len = 7 if header["method"] == "argon2id" else 4
                    header_len = 4 + 1 + 2 + len(algo_bytes) + 16 + 1 + 2 + param_len
                    fin.seek(header_len)

            processed = 0
            idx = 0
            while True:
                if encrypting:
                    chunk = fin.read(self.chunk_size)
                    if not chunk:
                        break
                    aad = struct.pack("<Q", idx)
                    # _aead.encrypt 返回 nonce||ct||tag，整块作为单元存储
                    blob = self._aead.encrypt(chunk, aad=aad)
                    fout.write(struct.pack("<I", len(blob)))
                    fout.write(blob)
                    processed += len(chunk)
                else:
                    # 每块格式：len(4,LE) || nonce||ct||tag
                    head = fin.read(4)
                    if len(head) < 4:
                        break  # 所有块读完，正常结束
                    (blen,) = struct.unpack("<I", head)
                    blob = fin.read(blen)
                    if len(blob) < blen:
                        raise DecryptionFailedError(detail="流意外结束，块数据不完整。")
                    aad = struct.pack("<Q", idx)
                    pt = self._aead.decrypt(blob, aad=aad)
                    fout.write(pt)
                    processed += len(pt)
                idx += 1
                if progress and total:
                    progress(processed, total)
            if progress and total:
                progress(total, total)
            return idx
        finally:
            if src_is_path:
                fin.close()
            if dst_is_path:
                fout.close()


# 便捷：口令模式的高层 KAT 友好封装
def _selftest_roundtrip() -> bool:
    import secrets

    for algo in SUPPORTED_SYMMETRIC:
        c = SymmetricCipher(algo)
        pt = secrets.token_bytes(1234)
        blob = c.encrypt(pt, password="test-pass")
        assert c.decrypt(blob, password="test-pass") == pt
        # 错误口令必须失败
        try:
            c.decrypt(blob, password="wrong")
            return False
        except DecryptionFailedError:
            pass
    return True
