"""
抗侧信道基类
============

侧信道攻击不攻破数学，而是观测实现的**物理表现**：耗时、缓存命中、
分支预测、功耗。本模块提供三层防御：

1. **恒定时间比较**：一切秘密比较走 :func:`hmac.compare_digest`
   （C 实现，无短路），杜绝"逐字节比较提前返回"这类经典漏洞。
2. **无秘密分支**：提供 :func:`select`、:func:`conditional_copy` 等
   位运算原语，用掩码代替 ``if``，让两条路径执行完全相同的指令序列。
3. **随机噪声延迟**：在敏感操作出入口注入随机时长的延迟，
   把真实耗时淹没在噪声中，抬高统计攻击所需的采样量。

关于噪声延迟的诚实说明
----------------------
随机延迟**不能**消除时序泄露，只能提高攻击成本——攻击者用
足够多的样本做平均即可滤掉零均值噪声。它是**纵深防御的一层**，
真正的防线始终是恒定时间算法本身。因此本模块的所有比较函数
都保证恒定时间，噪声只是额外保险。

同时，我们对成功与失败两条路径施加**同分布**的延迟
（``uniform_both_paths``）。若只在失败时延迟，反而制造了
更明显的时序区分信号，这是一个常见的实现错误。
"""

from __future__ import annotations

import hmac
import os
import secrets
import time
from functools import wraps
from typing import Any, Callable, TypeVar

__all__ = [
    "SideChannelBase",
    "constant_time_compare",
    "constant_time_compare_int",
    "select",
    "conditional_copy",
    "random_delay",
    "timing_jitter",
    "TimingProfile",
]

F = TypeVar("F", bound=Callable[..., Any])


# ======================================================================
#  恒定时间原语
# ======================================================================
def constant_time_compare(a: bytes | bytearray | memoryview, b: bytes | bytearray | memoryview) -> bool:
    """恒定时间比较两段字节串。

    直接委托给 :func:`hmac.compare_digest`——它在 CPython 中是 C 实现，
    对等长输入不会短路返回。

    ⚠ 注意：长度本身仍会泄露（不等长输入会立刻返回 ``False``）。
    这是可接受的，因为密码学场景中标签/摘要长度是公开参数。
    """
    return hmac.compare_digest(bytes(a), bytes(b))


def constant_time_compare_int(a: int, b: int, *, bit_length: int = 64) -> bool:
    """恒定时间比较两个非负整数。

    将整数转为固定宽度字节串后比较，避免 ``a == b`` 在大整数上
    可能出现的提前返回。
    """
    nbytes = (bit_length + 7) // 8
    try:
        ba = a.to_bytes(nbytes, "big")
        bb = b.to_bytes(nbytes, "big")
    except OverflowError:
        return False
    return hmac.compare_digest(ba, bb)


def select(condition: int, a: int, b: int) -> int:
    """无分支三元选择：``condition ? a : b``。

    ``condition`` 必须是 0 或 1。实现使用掩码而非 ``if``，
    因此不产生依赖秘密的分支，也不会污染分支预测器。

    >>> select(1, 0xAA, 0xBB)
    170
    >>> select(0, 0xAA, 0xBB)
    187
    """
    # 把 0/1 扩展成全 0 或全 1 掩码
    mask = -(condition & 1)
    return (a & mask) | (b & ~mask)


def conditional_copy(
    condition: int,
    dst: bytearray,
    src: bytes | bytearray,
) -> None:
    """当 ``condition`` 为 1 时把 ``src`` 写入 ``dst``，否则保持不变。

    两种情况下执行的指令序列完全一致——都会遍历全部字节并做
    掩码运算，只是写回的值不同。因此外部无法通过耗时判断
    拷贝是否真的发生。
    """
    if len(dst) != len(src):
        raise ValueError("无分支条件拷贝要求源与目标等长。")
    mask = -(condition & 1) & 0xFF
    inv = (~mask) & 0xFF
    for i in range(len(dst)):
        dst[i] = (src[i] & mask) | (dst[i] & inv)


# ======================================================================
#  时间噪声
# ======================================================================
def random_delay(min_ms: float = 0.05, max_ms: float = 0.60) -> float:
    """注入一段随机时长的忙等延迟。

    使用 :func:`time.perf_counter` 做忙等而非 ``time.sleep``，
    原因是 ``sleep`` 在多数平台上的精度只有毫秒级（Windows 更差），
    无法产生细粒度噪声；忙等虽然消耗 CPU，但延迟范围在亚毫秒级，
    整体开销可以忽略。

    随机源使用 :mod:`secrets`（CSPRNG），避免攻击者预测噪声序列后
    将其从测量结果中减去。

    :return: 实际延迟的毫秒数（便于测试与诊断）
    """
    if max_ms <= 0:
        return 0.0
    lo, hi = (min_ms, max_ms) if min_ms <= max_ms else (max_ms, min_ms)
    span_us = max(1, int((hi - lo) * 1000.0))
    delay_ms = lo + secrets.randbelow(span_us) / 1000.0

    deadline = time.perf_counter() + delay_ms / 1000.0
    while time.perf_counter() < deadline:
        pass
    return delay_ms


def timing_jitter(
    min_ms: float = 0.05,
    max_ms: float = 0.60,
    *,
    enabled: bool = True,
) -> Callable[[F], F]:
    """装饰器：在被装饰函数**返回前**注入随机延迟。

    延迟放在返回前而非调用前，是为了让"提前抛出异常"的快速失败路径
    也同样被延迟覆盖——否则异常路径会明显更快，形成时序预言机。

    >>> @timing_jitter(0.1, 0.5)
    ... def verify(tag, expected):
    ...     return constant_time_compare(tag, expected)
    """

    def decorator(func: F) -> F:
        if not enabled:
            return func

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                result = func(*args, **kwargs)
            except BaseException:
                # 失败路径同样延迟，保持与成功路径同分布
                random_delay(min_ms, max_ms)
                raise
            random_delay(min_ms, max_ms)
            return result

        return wrapper  # type: ignore[return-value]

    return decorator


# ======================================================================
#  基类
# ======================================================================
class SideChannelBase:
    """抗侧信道基类：所有处理秘密的密码学类都应继承它。

    提供的能力：

    * :meth:`ct_compare` —— 恒定时间比较
    * :meth:`ct_verify`  —— 恒定时间校验，失败抛出指定异常
    * :meth:`jitter`     —— 手动注入噪声延迟
    * :meth:`guarded`    —— 把任意可调用对象包进"同分布延迟"保护

    子类实现约定（**违反即视为安全缺陷**）：

    1. 不以秘密值作为 ``if`` / ``while`` 的判断条件
    2. 不以秘密值作为数组下标（会泄露到缓存行）
    3. 不用 ``==`` 比较秘密，一律走 :meth:`ct_compare`
    4. 不在异常消息中包含秘密内容或其派生值
    """

    #: 是否启用噪声延迟
    side_channel_enabled: bool = True
    #: 噪声延迟下界（毫秒）
    jitter_min_ms: float = 0.05
    #: 噪声延迟上界（毫秒）
    jitter_max_ms: float = 0.60
    #: 成功与失败路径施加同分布延迟
    uniform_both_paths: bool = True

    # ------------------------------------------------------------ 配置
    def configure_side_channel(
        self,
        *,
        enabled: bool | None = None,
        jitter_min_ms: float | None = None,
        jitter_max_ms: float | None = None,
        uniform_both_paths: bool | None = None,
    ) -> None:
        """从配置对象注入侧信道防护参数。"""
        if enabled is not None:
            self.side_channel_enabled = bool(enabled)
        if jitter_min_ms is not None:
            self.jitter_min_ms = max(0.0, float(jitter_min_ms))
        if jitter_max_ms is not None:
            self.jitter_max_ms = max(0.0, float(jitter_max_ms))
        if uniform_both_paths is not None:
            self.uniform_both_paths = bool(uniform_both_paths)

    # ------------------------------------------------------------ 比较
    @staticmethod
    def ct_compare(
        a: bytes | bytearray | memoryview,
        b: bytes | bytearray | memoryview,
    ) -> bool:
        """恒定时间比较（静态方法，无实例状态依赖）。"""
        return constant_time_compare(a, b)

    def ct_verify(
        self,
        actual: bytes | bytearray | memoryview,
        expected: bytes | bytearray | memoryview,
        exc: BaseException,
    ) -> None:
        """恒定时间校验；不匹配则抛出 ``exc``。

        无论成功还是失败都注入同分布延迟（当 ``uniform_both_paths``
        为真），确保攻击者无法通过耗时区分两种结果。
        """
        ok = constant_time_compare(actual, expected)
        if self.side_channel_enabled:
            # 关键：延迟在分支**之前**统一施加，不因结果不同而不同
            self.jitter()
        if not ok:
            raise exc

    # ------------------------------------------------------------ 噪声
    def jitter(self) -> float:
        """按当前配置注入一次噪声延迟。"""
        if not self.side_channel_enabled:
            return 0.0
        return random_delay(self.jitter_min_ms, self.jitter_max_ms)

    def guarded(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """在噪声保护下执行 ``func``，成功与失败路径耗时同分布。"""
        if not self.side_channel_enabled:
            return func(*args, **kwargs)
        try:
            result = func(*args, **kwargs)
        except BaseException:
            if self.uniform_both_paths:
                self.jitter()
            raise
        self.jitter()
        return result


# ======================================================================
#  时序自测工具（供测试套件使用）
# ======================================================================
class TimingProfile:
    """采集函数耗时样本并计算统计量，用于验证"恒定时间"性质。

    测试套件用它断言：不同输入下的耗时标准差占均值比例 < 5%。
    这不是形式化证明，但能有效捕捉"提前返回"这类明显缺陷。

    >>> prof = TimingProfile()
    >>> prof.measure(lambda: constant_time_compare(b"a"*32, b"a"*32), rounds=200)
    >>> prof.relative_stdev() < 0.05
    True
    """

    def __init__(self) -> None:
        self.samples: list[float] = []

    def measure(self, func: Callable[[], Any], *, rounds: int = 100, warmup: int = 10) -> None:
        """采集 ``rounds`` 轮耗时（秒）。前 ``warmup`` 轮丢弃以预热缓存/JIT。"""
        for _ in range(max(0, warmup)):
            try:
                func()
            except Exception:
                pass
        self.samples.clear()
        for _ in range(max(1, rounds)):
            start = time.perf_counter()
            try:
                func()
            except Exception:
                pass
            self.samples.append(time.perf_counter() - start)

    # ------------------------------------------------------------ 统计
    def mean(self) -> float:
        return sum(self.samples) / len(self.samples) if self.samples else 0.0

    def stdev(self) -> float:
        n = len(self.samples)
        if n < 2:
            return 0.0
        mu = self.mean()
        var = sum((x - mu) ** 2 for x in self.samples) / (n - 1)
        return var**0.5

    def median(self) -> float:
        if not self.samples:
            return 0.0
        ordered = sorted(self.samples)
        mid = len(ordered) // 2
        if len(ordered) % 2:
            return ordered[mid]
        return (ordered[mid - 1] + ordered[mid]) / 2

    def relative_stdev(self) -> float:
        """标准差 / 均值。越小说明耗时越稳定。"""
        mu = self.mean()
        return self.stdev() / mu if mu > 0 else 0.0

    def trimmed_relative_stdev(self, trim_ratio: float = 0.10) -> float:
        """剔除首尾极端值后的相对标准差。

        操作系统调度、GC、CPU 频率调节会产生离群点，
        这些噪声与算法实现无关。裁剪后的指标更能反映真实性质。
        """
        if len(self.samples) < 10:
            return self.relative_stdev()
        ordered = sorted(self.samples)
        k = int(len(ordered) * trim_ratio)
        core = ordered[k : len(ordered) - k] or ordered
        mu = sum(core) / len(core)
        if mu <= 0:
            return 0.0
        var = sum((x - mu) ** 2 for x in core) / max(1, len(core) - 1)
        return (var**0.5) / mu

    def summary(self) -> dict[str, float]:
        return {
            "样本数": float(len(self.samples)),
            "均值_ms": self.mean() * 1000,
            "中位数_ms": self.median() * 1000,
            "标准差_ms": self.stdev() * 1000,
            "相对标准差": self.relative_stdev(),
            "裁剪相对标准差": self.trimmed_relative_stdev(),
        }


def _self_check() -> bool:
    """模块自检：确认 os.urandom 与 secrets 可用。"""
    try:
        return len(os.urandom(16)) == 16 and secrets.randbelow(10) < 10
    except Exception:  # pragma: no cover
        return False
