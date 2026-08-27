"""
安全随机数源
============

CipherForge 中**所有**密钥、盐、Nonce、Pepper、分片 x 坐标、
隐写置换种子都必须来自本模块。

设计原则
--------
* 唯一熵源是操作系统 CSPRNG：``os.urandom`` / :mod:`secrets`
  （Windows 上为 ``BCryptGenRandom``，Linux 上为 ``getrandom(2)``）。
* **绝不**使用 :mod:`random`。它是 Mersenne Twister，
  观测 624 个连续输出即可完整还原内部状态并预测后续全部输出。
* 不实现"自研混合熵池"。自制 RNG 是密码学工程中最经典的翻车点，
  操作系统的实现经过了远超本项目的审计强度。
* 提供无模偏的区间随机数：:func:`randbelow` 走 ``secrets``，
  内部使用拒绝采样，不引入 ``% n`` 的模偏。

模块内所有函数都是无状态的纯函数，天然线程安全。
"""

from __future__ import annotations

import os
import secrets

from .errors import ValidationError

__all__ = [
    "random_bytes",
    "random_nonce",
    "random_salt",
    "randbelow",
    "random_int_range",
    "random_permutation",
    "random_token_hex",
    "random_choice",
    "entropy_selftest",
]

#: 标准 AEAD Nonce 长度（GCM / Poly1305）
NONCE_BYTES = 12
#: XChaCha20 扩展 Nonce 长度
XNONCE_BYTES = 24
#: 默认盐长度
SALT_BYTES = 16


def random_bytes(size: int) -> bytes:
    """生成 ``size`` 字节密码学安全随机数据。"""
    if not isinstance(size, int) or size <= 0:
        raise ValidationError(
            f"随机字节长度必须是正整数，收到：{size!r}",
            hint="请传入大于 0 的整数。",
        )
    if size > 1 << 30:  # 1 GiB 上限，防御异常参数导致内存耗尽
        raise ValidationError(
            "单次请求的随机数据超过 1 GiB 上限。",
            hint="请分批生成。",
            context={"请求字节数": size},
        )
    return os.urandom(size)


def random_nonce(size: int = NONCE_BYTES) -> bytes:
    """生成全新随机 Nonce。

    ⚠ 同一密钥下 Nonce 重用会**彻底摧毁** GCM/Poly1305 的安全性
    （可恢复认证密钥并伪造任意消息）。因此本项目在每次加密时
    都生成全新随机 Nonce，从不使用计数器模式的可预测 Nonce。

    96 位随机 Nonce 在生日界下的碰撞概率：加密 2^32 条消息时
    约为 2^-33，对桌面工具的使用规模而言绰绰有余。
    """
    return random_bytes(size)


def random_salt(size: int = SALT_BYTES) -> bytes:
    """生成全新随机盐（用于 KDF）。

    盐无需保密，但必须**每次全新且唯一**——复用盐会让预计算
    彩虹表攻击重新变得可行。
    """
    return random_bytes(size)


def randbelow(upper: int) -> int:
    """返回 ``[0, upper)`` 上的均匀随机整数，无模偏。"""
    if not isinstance(upper, int) or upper <= 0:
        raise ValidationError(
            f"上界必须是正整数，收到：{upper!r}",
            hint="请传入大于 0 的整数。",
        )
    return secrets.randbelow(upper)


def random_int_range(low: int, high: int) -> int:
    """返回闭区间 ``[low, high]`` 上的均匀随机整数。"""
    if low > high:
        raise ValidationError(
            f"区间下界 {low} 大于上界 {high}。",
            hint="请检查参数顺序。",
        )
    return low + randbelow(high - low + 1)


def random_permutation(n: int) -> list[int]:
    """返回 ``0..n-1`` 的均匀随机排列（Fisher–Yates 洗牌）。

    用于隐写模块打乱像素嵌入顺序。使用**逆向** Fisher–Yates
    并配合无模偏的 :func:`randbelow`，保证每种排列等概率出现。
    """
    if n < 0:
        raise ValidationError("排列长度不能为负。")
    arr = list(range(n))
    for i in range(n - 1, 0, -1):
        j = randbelow(i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    return arr


def random_token_hex(nbytes: int = 16) -> str:
    """生成十六进制随机令牌（用于文件名、会话 ID 等非秘密场景）。"""
    return secrets.token_hex(nbytes)


def random_choice(sequence):
    """从非空序列中均匀随机选取一个元素。"""
    if not sequence:
        raise ValidationError("不能从空序列中随机选取。")
    return sequence[randbelow(len(sequence))]


# ----------------------------------------------------------------------
#  自检
# ----------------------------------------------------------------------
def entropy_selftest(sample_bytes: int = 4096) -> dict[str, float | bool]:
    """对随机源做一次轻量健康检查。

    这**不是**统计随机性检验（那需要 NIST SP 800-22 全套测试），
    只是一道"活性哨兵"：捕捉随机源被错误替换成常量、
    全零或严重偏斜等灾难性故障。

    检查项：
    * 字节均值应接近 127.5
    * 不同字节值的覆盖率应足够高
    * 不应出现长串重复

    :return: 诊断指标字典，``passed`` 为总体结论
    """
    data = random_bytes(sample_bytes)

    mean = sum(data) / len(data)
    distinct = len(set(data))

    # 最长连续相同字节
    longest_run = 1
    current_run = 1
    for i in range(1, len(data)):
        if data[i] == data[i - 1]:
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            current_run = 1

    # 位级 1 的占比
    ones = sum(bin(b).count("1") for b in data)
    ones_ratio = ones / (len(data) * 8)

    mean_ok = 110.0 <= mean <= 145.0
    distinct_ok = distinct >= min(256, sample_bytes // 32)
    run_ok = longest_run <= 8
    bits_ok = 0.45 <= ones_ratio <= 0.55

    return {
        "均值": mean,
        "不同字节数": float(distinct),
        "最长重复串": float(longest_run),
        "比特1占比": ones_ratio,
        "均值检查": mean_ok,
        "覆盖率检查": distinct_ok,
        "重复串检查": run_ok,
        "比特平衡检查": bits_ok,
        "passed": bool(mean_ok and distinct_ok and run_ok and bits_ok),
    }
