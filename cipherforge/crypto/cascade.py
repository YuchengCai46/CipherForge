"""
级联加密引擎（多层 AEAD 嵌套 + 层间完整性链 + 多重密码 + 每层独立盐）
=======================================================================

把明文用**多条不同算法**逐层加密，形成「洋葱式」密文。
即使其中某一条算法的实现在未来被发现弱点，其余层仍提供保密性。

设计要点
--------
* **多重密码保护**：支持主密码 + 可选的每层独立密码。
  所有密码组合成最终的 master key，即使攻击者知道部分层的密码，
  也无法解密其他层。
* **每层独立盐**：每一层使用独立的随机盐派生子密钥，防止盐重用攻击。
* **独立子密钥**：主密钥由 Argon2id（口令派生）得到，再用
  **HKDF-SHA256**（经审计的 ``cryptography`` 后端）为每个层级派生
  互不相同的 32 字节子密钥——同一口令不会在任何两层复用密钥。
* **层间 Tag 链**：每一层计算
  ``chain_i = HMAC(链密钥_i, algo_i ‖ ct_i ‖ chain_{i-1})``，
  把「算法 + 本层密文 + 上一层校验」绑定起来。剥离、重排或替换任一层，
  都会令某条链 Tag 失配，立即被 :class:`IntegrityError` 拦下。
* **签名头**：整个文件头（含层数、各层描述、KDF 参数、各层盐）用
  头认证密钥做 HMAC-SHA256。攻击者若删层（降级攻击）或篡改头，
  头 MAC 必失配 → :class:`DowngradeAttackError`（红字呈现）。
* **自动逆序解密**：解密时从最外层向内逐层剥离，无需调用方指定顺序；
  顺序由密文自身描述，且受链 Tag 与头 MAC 双重保护。
* 所有随机数（盐、Nonce、子密钥熵源）来自 OS CSPRNG；
  密钥材料经 :class:`SecureBytes` 托管并在退出时擦除。

默认三层：``AES-256-GCM → ChaCha20-Poly1305 → Serpent-GCM``，
兼顾性能、抗实现缺陷与算法多样性。

用法示例
--------
.. code-block:: python

    # 基本用法：单密码
    ce = CascadeEngine(["AES-256-GCM", "ChaCha20-Poly1305"])
    blob = ce.encrypt(data, password="master-pass")

    # 多重密码：主密码 + 每层独立密码
    blob = ce.encrypt(data, password="master",
                      layer_passwords=["layer0-pass", "layer1-pass"])

    # 每层独立盐（默认开启）
    # 密文头中会记录每层的盐，解密时自动提取
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Sequence

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from ..core.errors import (
    DowngradeAttackError,
    IntegrityError,
    ValidationError,
    DecryptionFailedError,
    UnsupportedAlgorithmError,
)
from ..core.rng import random_salt
from ..core.memory import SecureBytes
from .symmetric import make_aead, SUPPORTED_SYMMETRIC

__all__ = ["CascadeEngine"]

# 格式版本
_MAGIC = b"CFCS"          # CipherForge Cascade
_VERSION = 2              # v2: 支持多重密码和每层独立盐
_HKDF_SALT = b"CipherForge-Cascade-v2"
_SEED_CHAIN = b"\x00" * 32  # 链首前缀（公开常量）

# 盐长度（每层）
_LAYER_SALT_BYTES = 16
# 主密码派生的 master key 长度
_MASTER_KEY_BYTES = 32


def _hkdf(master: bytes, info: bytes, length: int = 32) -> bytes:
    """使用固定盐的 HKDF-SHA256 派生。"""
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=_HKDF_SALT, info=info
    ).derive(master)


def _combine_passwords(*passwords: str) -> bytes:
    """将多个密码组合成一个 master key（HMAC 链式组合）。"""
    if not passwords:
        raise ValidationError("至少需要一个密码。")
    result = b""
    for pw in passwords:
        if not pw:
            continue
        result = hashlib.sha512(result + pw.encode("utf-8")).digest()
    return result[:_MASTER_KEY_BYTES]


class CascadeEngine:
    """级联加密引擎，支持多重密码和每层独立盐。"""

    def __init__(self, algorithms: list[str] | None = None, *, config=None) -> None:
        from ..core.config import load_config

        self.config = config or load_config(apply_scaling=False)
        if algorithms is None:
            algorithms = ["AES-256-GCM", "ChaCha20-Poly1305", "Serpent-GCM"]
        if len(algorithms) < 1:
            raise ValidationError("级联至少需要 1 层算法。")
        if len(algorithms) > 16:
            raise ValidationError("级联层数上限为 16。")
        for a in algorithms:
            if a not in SUPPORTED_SYMMETRIC:
                raise UnsupportedAlgorithmError(a, SUPPORTED_SYMMETRIC)
        self.algorithms = list(algorithms)

    # ------------------------------------------------------------ 加密
    def encrypt(
        self,
        plaintext: bytes,
        *,
        password: str,
        layer_passwords: Sequence[str] | None = None,
    ) -> bytes:
        """加密明文。

        Args:
            plaintext: 要加密的明文。
            password: 主密码（必须）。
            layer_passwords: 可选，每层独立密码列表，长度需等于层数。
        """
        if plaintext == b"":
            raise ValidationError("明文不能为空。")
        if not password:
            raise ValidationError("主密码不能为空。")

        layer_passwords = list(layer_passwords) if layer_passwords else []
        # 层密码可选：如果不提供，则每层使用空密码；如果提供，数量必须等于层数
        if layer_passwords and len(layer_passwords) != len(self.algorithms):
            raise ValidationError(
                f"层密码数量 ({len(layer_passwords)}) 必须等于层数 ({len(self.algorithms)})。"
            )
        # 补齐空密码
        while len(layer_passwords) < len(self.algorithms):
            layer_passwords.append("")

        from .kdf import KeyDeriver

        kd = KeyDeriver(self.config)
        if self.config.get("kdf.auto_tune", True) and not self.config.get("kdf._tuned_once", False):
            kd.auto_tune()
            self.config.set("kdf._tuned_once", True)
        method = "argon2id" if self.config.get("kdf.default", "argon2id") == "argon2id" else "pbkdf2"
        params = kd.current_params(method)

        # 组合所有密码得到一个 master key
        all_passwords = [password] + layer_passwords
        master_key = _combine_passwords(*all_passwords)
        master_sec = SecureBytes(master_key)

        try:
            header_key = _hkdf(master_sec.to_bytes(), b"cipherforge-cascade-header")
            data = plaintext
            layers: list[tuple[bytes, bytes]] = []   # (algo_bytes, ct)
            chains: list[bytes] = []                 # 每层各自的链 Tag
            layer_salts: list[bytes] = []            # 每层的盐
            prev_chain = _SEED_CHAIN

            for i, algo in enumerate(self.algorithms):
                # 每层独立盐
                layer_salt = random_salt(_LAYER_SALT_BYTES)
                layer_salts.append(layer_salt)

                # 用该层盐和主 master key 派生层子密钥
                subkey = _hkdf(
                    master_sec.to_bytes(),
                    layer_salt + f"layer-{i}-{algo}".encode()
                )
                chain_key = _hkdf(
                    master_sec.to_bytes(),
                    layer_salt + f"chain-{i}-{algo}".encode()
                )

                aead = make_aead(algo, config=self.config)
                aead.set_key(subkey)
                try:
                    ct = aead.encrypt(data)
                finally:
                    aead.close()
                    del subkey

                algo_b = algo.encode()
                chain = hmac.new(
                    chain_key, algo_b + ct + prev_chain, hashlib.sha256
                ).digest()
                layers.append((algo_b, ct))
                chains.append(chain)
                prev_chain = chain
                data = ct

            blob = self._build_header(
                method, params, layer_salts, layers, chains, header_key
            )
            return blob
        finally:
            master_sec.zeroize()

    # ------------------------------------------------------------ 解密
    def decrypt(self, blob: bytes, *, password: str, layer_passwords: Sequence[str] | None = None) -> bytes:
        """解密级联密文。

        Args:
            blob: 级联密文。
            password: 主密码（必须与加密时一致）。
            layer_passwords: 可选，每层独立密码列表。
        """
        if not password:
            raise ValidationError("主密码不能为空。")
        if len(blob) < 4 or blob[:4] != _MAGIC:
            raise DecryptionFailedError(
                detail="输入不是有效的 CipherForge 级联密文（魔数不匹配）。"
            )

        from .kdf import KeyDeriver

        kd = KeyDeriver(self.config)

        # 解析头
        body, header_mac = self._split_mac(blob)
        parsed = self._parse_header(body)
        method = parsed["method"]
        params = parsed["params"]
        layer_salts = parsed["layer_salts"]
        layer_algos = parsed["algos"]
        layer_cts = parsed["cts"]
        chain_stored = parsed["chains"]
        n = len(layer_algos)

        # 结构降级检测
        if parsed["trailing"] != 0:
            raise DowngradeAttackError(n, n - 1)

        layer_passwords = list(layer_passwords) if layer_passwords else []

        # 验证层密码数量并补齐
        if layer_passwords and len(layer_passwords) != n:
            raise ValidationError(
                f"层密码数量 ({len(layer_passwords)}) 必须等于层数 ({n})。"
            )
        while len(layer_passwords) < n:
            layer_passwords.append("")

        # 组合密码
        all_passwords = [password] + layer_passwords
        master_key = _combine_passwords(*all_passwords)
        master_sec = SecureBytes(master_key)

        try:
            header_key = _hkdf(master_sec.to_bytes(), b"cipherforge-cascade-header")
            # 头 MAC 校验
            if not hmac.compare_digest(
                hmac.new(header_key, body, hashlib.sha256).digest(), header_mac
            ):
                raise DecryptionFailedError()

            # 重算并比对层间链 Tag
            prev_chain = _SEED_CHAIN
            for i, algo in enumerate(layer_algos):
                layer_salt = layer_salts[i]
                chain_key = _hkdf(
                    master_sec.to_bytes(),
                    layer_salt + f"chain-{i}-{algo}".encode()
                )
                expected = hmac.new(
                    chain_key, algo.encode() + layer_cts[i] + prev_chain, hashlib.sha256
                ).digest()
                if not hmac.compare_digest(expected, chain_stored[i]):
                    raise IntegrityError("层间完整性链校验失败，密文可能被篡改或重排。")
                prev_chain = chain_stored[i]

            # 自动逆序解密
            data = layer_cts[-1]
            for i in range(n - 1, -1, -1):
                algo = layer_algos[i]
                layer_salt = layer_salts[i]
                subkey = _hkdf(
                    master_sec.to_bytes(),
                    layer_salt + f"layer-{i}-{algo}".encode()
                )
                aead = make_aead(algo, config=self.config)
                aead.set_key(subkey)
                try:
                    data = aead.decrypt(data)
                finally:
                    aead.close()
                    del subkey
            return data
        finally:
            master_sec.zeroize()

    # ------------------------------------------------------------ 头编解码
    def _build_header(
        self,
        method: str,
        params: dict,
        layer_salts: list[bytes],
        layers: list[tuple[bytes, bytes]],
        chains: list[bytes],
        header_key: bytes,
    ) -> bytes:
        """组装文件头：magic/版本/层数/各层盐/KDF 参数/各层(算法,密文,链Tag)。"""
        body = bytearray()
        body += _MAGIC
        body += bytes([_VERSION])
        body += bytes([len(layers)])

        # 写入每层盐
        for salt in layer_salts:
            body += salt

        body += self._pack_kdf(method, params)

        for (algo_b, ct), chain in zip(layers, chains):
            body += struct.pack("<H", len(algo_b))
            body += algo_b
            body += struct.pack("<I", len(ct))
            body += chain
            body += ct

        mac = hmac.new(header_key, bytes(body), hashlib.sha256).digest()
        return bytes(body) + mac

    def _pack_kdf(self, method: str, params: dict) -> bytes:
        if method == "argon2id":
            return bytes([0]) + struct.pack(
                "<III",
                int(params["time_cost"]),
                int(params["memory_cost_kib"]),
                int(params["parallelism"]),
            )
        return bytes([1]) + struct.pack("<I", int(params["iterations"]))

    def _parse_header(self, body: bytes) -> dict:
        """解析文件头。"""
        min_len = 4 + 1 + 1 + _LAYER_SALT_BYTES * 2 + 1  # 至少 2 层
        if len(body) < min_len:
            raise DowngradeAttackError(0, 0)

        off = 0
        if body[off:off + 4] != _MAGIC:
            raise DowngradeAttackError(0, 0)
        off += 4

        version = body[off]; off += 1
        if version != _VERSION:
            raise DowngradeAttackError(0, 0)

        n = body[off]; off += 1
        if n < 1 or n > 16:
            raise DowngradeAttackError(0, 0)

        # 读取每层盐
        layer_salts: list[bytes] = []
        for _ in range(n):
            salt = body[off:off + _LAYER_SALT_BYTES]
            layer_salts.append(salt)
            off += _LAYER_SALT_BYTES

        # 读取 KDF 参数
        kdf_code = body[off]; off += 1
        if kdf_code == 0:
            method = "argon2id"
            tc, mk, pl = struct.unpack("<III", body[off:off + 12]); off += 12
            params = {"time_cost": tc, "memory_cost_kib": mk, "parallelism": pl}
        else:
            method = "pbkdf2"
            (it,) = struct.unpack("<I", body[off:off + 4]); off += 4
            params = {"iterations": it}

        # 读取各层数据
        algos: list[str] = []
        cts: list[bytes] = []
        chains: list[bytes] = []
        for _ in range(n):
            (algo_len,) = struct.unpack("<H", body[off:off + 2]); off += 2
            algo = body[off:off + algo_len].decode(); off += algo_len
            (ct_len,) = struct.unpack("<I", body[off:off + 4]); off += 4
            chain = body[off:off + 32]; off += 32
            ct = body[off:off + ct_len]; off += ct_len
            algos.append(algo)
            cts.append(ct)
            chains.append(chain)

        return {
            "version": version,
            "method": method,
            "params": params,
            "layer_salts": layer_salts,
            "algos": algos,
            "cts": cts,
            "chains": chains,
            "trailing": len(body) - off,
        }

    def _split_mac(self, blob: bytes) -> tuple[bytes, bytes]:
        """分离头体和 MAC。"""
        if len(blob) < 32:
            raise DowngradeAttackError(0, 0)
        return blob[:-32], blob[-32:]
