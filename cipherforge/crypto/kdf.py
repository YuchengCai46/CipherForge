"""
密钥派生（KDF）
==============

* **默认 Argon2id** —— 抗 GPU/ASIC 的"内存硬" KDF，被 OWASP、NIST、
  PASSPHRASE 等主流指南推荐用于口令加密。
* **备选 PBKDF2-HMAC-SHA512** —— 兼容性强、零额外依赖，作为降级选项。

自适应调参（启动基准测试）
--------------------------
程序启动（或首次派生前）会跑一轮基准测试，目标是让单次派生耗时
≈ ``target_ms``（默认 400ms），且**整个基准测试本身不超过
``benchmark_budget_ms``（默认 500ms）**——这是硬性预算，任何情况下
都不会突破，因为过长的启动等待会损害可用性。

调参思路：

* Argon2id：固定并行度＝CPU 核心数（上限 8），通过二分/倍增调整
  ``memory_cost``，让耗时收敛到目标值。内存是 Argon2 抗并行攻击的
  主战场，因此优先吃满内存预算。
* PBKDF2：线性缩放 ``iterations``（OWASP 2023 下限 210,000），
  按实测耗时与目标的比值放大迭代次数。

所有调参结果都会回写配置对象，供同一进程复用；``auto_tune=False``
时直接采用配置文件中的静态参数。

友好异常 & 内存卫生：派生出的密钥只存在于 :class:`SecureBytes`，
调用方负责擦除；盐每次全新随机。
"""

from __future__ import annotations

import hashlib
import time

from ..core.config import Config, load_config
from ..core.errors import ValidationError
from ..core.memory import SecureBytes
from ..core.rng import random_salt
from ..core.sidechannel import SideChannelBase

__all__ = ["KeyDeriver", "derive_argon2id", "derive_pbkdf2"]


def _argon2():
    from argon2.low_level import Type, hash_secret_raw

    return Type, hash_secret_raw


def derive_argon2id(
    password: str | bytes,
    *,
    salt: bytes,
    time_cost: int = 3,
    memory_cost_kib: int = 262144,
    parallelism: int = 4,
    length: int = 32,
) -> bytes:
    """Argon2id 派生，返回 ``length`` 字节原始密钥。"""
    if isinstance(password, str):
        pw = password.encode("utf-8")
    else:
        pw = password
    Type, hash_secret_raw = _argon2()
    return hash_secret_raw(
        secret=pw,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost_kib,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )


def derive_pbkdf2(
    password: str | bytes,
    *,
    salt: bytes,
    iterations: int = 600000,
    hash_name: str = "sha512",
    length: int = 32,
) -> bytes:
    """PBKDF2-HMAC 派生，返回 ``length`` 字节原始密钥。"""
    if isinstance(password, str):
        pw = password.encode("utf-8")
    else:
        pw = password
    return hashlib.pbkdf2_hmac(hash_name, pw, salt, iterations, dklen=length)


class KeyDeriver(SideChannelBase):
    """统一的密钥派生门面，含启动自适应调参。"""

    def __init__(self, config: Config | None = None) -> None:
        SideChannelBase.__init__(self)
        self.config = config or load_config(apply_scaling=True)
        self._tuned = False
        self.last_tuning: dict = {}

    # ------------------------------------------------------------ 调参
    def auto_tune(self) -> dict:
        """运行基准测试，自适应选定参数。结果回写 ``self.config``。

        严格遵守 ``benchmark_budget_ms`` 总预算：一旦累计耗时逼近预算，
        立即采用当前可行参数，绝不超限。

        :return: 诊断字典（算法、最终参数、各次测量耗时）
        """
        method = self.config.get("kdf.default", "argon2id")
        if method == "argon2id":
            result = self._tune_argon2id()
        else:
            result = self._tune_pbkdf2()
        self._tuned = True
        self.last_tuning = result
        return result

    def _tune_argon2id(self) -> dict:
        salt = random_salt(self.config.get("symmetric.salt_bytes", 16))
        pw = b"benchmark-only-input"
        target_ms = float(self.config.get("kdf.target_ms", 400))
        budget_ms = float(self.config.get("kdf.benchmark_budget_ms", 500))
        lo = int(self.config.get("kdf.argon2id.min_memory_cost_kib", 65536))
        hi = int(self.config.get("kdf.argon2id.max_memory_cost_kib", 262144))
        parallelism = int(self.config.get("kdf.argon2id.parallelism", 4))
        length = int(self.config.get("kdf.argon2id.length", 32)) if self.config.get("kdf.argon2id.length") else int(self.config.get("kdf.output_length", 32))

        measurements: list[dict] = []
        start_all = time.perf_counter()

        def _measure(mem: int, tc: int = 3) -> float:
            t0 = time.perf_counter()
            derive_argon2id(pw, salt=salt, time_cost=tc, memory_cost_kib=mem,
                            parallelism=parallelism, length=length)
            return (time.perf_counter() - t0) * 1000.0

        # 第一次测量：下限内存，建立耗时基准（linear: time ∝ memory_cost）
        dt0 = _measure(lo)
        measurements.append({"memory_kib": lo, "time_cost": 3, "ms": round(dt0, 2)})
        if dt0 <= 0:
            dt0 = 0.1

        # 外推到目标耗时对应的内存成本，并用内存硬上限夹紧（防 OOM）
        est_mem = int(lo * (target_ms / dt0))
        chosen = max(lo, min(hi, est_mem))

        time_cost = 3
        # 若内存被上限夹住、单轮（tc=3）耗时仍低于目标，则用 time_cost 补偿：
        # 保持内存上界不变，靠轮数逼近目标耗时，避免无节制吃内存。
        if chosen >= hi and est_mem > hi:
            elapsed = (time.perf_counter() - start_all) * 1000.0
            if elapsed < budget_ms * 0.6:
                dt_c = _measure(chosen, 3)
                measurements.append({"memory_kib": chosen, "time_cost": 3, "ms": round(dt_c, 2)})
                if dt_c > 0:
                    tc = int(round(3 * target_ms / dt_c))
                    time_cost = max(3, min(20, tc))

        elapsed = (time.perf_counter() - start_all) * 1000.0
        self.config.set("kdf.argon2id.memory_cost_kib", chosen)
        self.config.set("kdf.argon2id.time_cost", time_cost)
        self.config.set("kdf.argon2id.parallelism", parallelism)

        return {
            "method": "argon2id",
            "target_ms": target_ms,
            "budget_ms": budget_ms,
            "total_benchmark_ms": round(elapsed, 2),
            "final_memory_kib": chosen,
            "final_memory_mib": round(chosen / 1024, 1),
            "final_time_cost": time_cost,
            "parallelism": parallelism,
            "measurements": measurements,
            "within_budget": elapsed <= budget_ms,
        }

    def _tune_pbkdf2(self) -> dict:
        salt = random_salt(self.config.get("symmetric.salt_bytes", 16))
        pw = b"benchmark-only-input"
        target_ms = float(self.config.get("kdf.target_ms", 400))
        budget_ms = float(self.config.get("kdf.benchmark_budget_ms", 500))
        hash_name = self.config.get("kdf.pbkdf2.hash", "sha512")
        min_iter = int(self.config.get("kdf.pbkdf2.min_iterations", 210000))
        length = int(self.config.get("kdf.output_length", 32))

        # 先测一个基准迭代量，再按耗时线性外推
        base_iter = min_iter
        t0 = time.perf_counter()
        derive_pbkdf2(pw, salt=salt, iterations=base_iter, hash_name=hash_name, length=length)
        dt = (time.perf_counter() - t0) * 1000.0
        if dt <= 0:
            dt = 0.1
        scale = target_ms / dt
        chosen_iter = max(min_iter, int(base_iter * scale))
        # 不超预算：若外推耗时 > 预算，则夹回预算对应值
        est_ms = chosen_iter / base_iter * dt
        if est_ms > budget_ms:
            chosen_iter = max(min_iter, int(base_iter * budget_ms / dt))
        self.config.set("kdf.pbkdf2.iterations", chosen_iter)

        return {
            "method": "pbkdf2",
            "target_ms": target_ms,
            "budget_ms": budget_ms,
            "final_iterations": chosen_iter,
            "base_ms": round(dt, 2),
            "within_budget": chosen_iter / base_iter * dt <= budget_ms,
        }

    # ------------------------------------------------------------ 公开派生
    def derive(
        self,
        password: str | bytes,
        *,
        salt: bytes | None = None,
        length: int | None = None,
        method: str | None = None,
        force_salt: bool = False,
        params: dict | None = None,
    ) -> bytes:
        """派生密钥（普通 ``bytes``，调用方负责擦除）。

        :param salt: 复用给定盐；省略则生成全新随机盐。
        :param length: 输出字节数，默认取配置 ``kdf.output_length``。
        :param method: 覆盖默认 KDF（``argon2id`` / ``pbkdf2``）。
        :param force_salt: 为 ``True`` 时若未提供盐则抛出异常
                           （防止意外生成盐破坏可复现性）。
        :param params: 显式 KDF 参数（来自文件头）。传入后**不再**自动调参，
                       保证加密/解密使用完全一致的派生曲线，避免计时噪声
                       导致的参数漂移使双方密钥不一致。
        """
        if salt is None:
            if force_salt:
                raise ValidationError(
                    "derive 要求显式提供盐，但未传入。",
                    hint="请传入 salt 参数，或允许自动生成盐。",
                )
            salt = random_salt(self.config.get("symmetric.salt_bytes", 16))
        if length is None:
            length = int(self.config.get("kdf.output_length", 32))

        method = method or self.config.get("kdf.default", "argon2id")

        # 显式参数优先：直接派生，跳过所有自适应逻辑（可复现、零计时依赖）
        if params is not None:
            if method == "argon2id":
                return derive_argon2id(
                    password, salt=salt,
                    time_cost=int(params["time_cost"]),
                    memory_cost_kib=int(params["memory_cost_kib"]),
                    parallelism=int(params["parallelism"]),
                    length=length,
                )
            if method == "pbkdf2":
                return derive_pbkdf2(
                    password, salt=salt,
                    iterations=int(params["iterations"]),
                    hash_name=self.config.get("kdf.pbkdf2.hash", "sha512"),
                    length=length,
                )
            raise ValidationError(f"不支持的 KDF：{method}", context={"请求KDF": method})

        # 否则走自适应：整进程（同一 config 对象）只调参一次，
        # 避免每次派生都做一次 ~GiB 级内存基准测试导致内存峰值累积。
        if self.config.get("kdf.auto_tune", True) and not self._tuned \
                and not self.config.get("kdf._tuned_once", False) \
                and not self.config.get("kdf._tuning_in_progress", False):
            self.config.set("kdf._tuning_in_progress", True)
            try:
                self.auto_tune()
                self.config.set("kdf._tuned_once", True)
            finally:
                self.config.set("kdf._tuning_in_progress", False)

        if method == "argon2id":
            return derive_argon2id(
                password,
                salt=salt,
                time_cost=int(self.config.get("kdf.argon2id.time_cost", 3)),
                memory_cost_kib=int(self.config.get("kdf.argon2id.memory_cost_kib", 262144)),
                parallelism=int(self.config.get("kdf.argon2id.parallelism", 4)),
                length=length,
            )
        if method == "pbkdf2":
            return derive_pbkdf2(
                password,
                salt=salt,
                iterations=int(self.config.get("kdf.pbkdf2.iterations", 600000)),
                hash_name=self.config.get("kdf.pbkdf2.hash", "sha512"),
                length=length,
            )
        raise ValidationError(
            f"不支持的 KDF：{method}",
            hint="可选：argon2id 或 pbkdf2。",
            context={"请求KDF": method},
        )

    def current_params(self, method: str | None = None) -> dict:
        """返回当前生效的 KDF 参数（供写入文件头，保证可复现）。"""
        method = method or self.config.get("kdf.default", "argon2id")
        if method == "argon2id":
            return {
                "time_cost": int(self.config.get("kdf.argon2id.time_cost", 3)),
                "memory_cost_kib": int(self.config.get("kdf.argon2id.memory_cost_kib", 262144)),
                "parallelism": int(self.config.get("kdf.argon2id.parallelism", 4)),
            }
        return {
            "iterations": int(self.config.get("kdf.pbkdf2.iterations", 600000)),
        }

    def derive_secure(self, password: str | bytes, **kw) -> SecureBytes:
        """派生密钥并返回 :class:`SecureBytes`（可擦除）。"""
        raw = self.derive(password, **kw)
        return SecureBytes(raw)
