"""抗侧信道补充测试：装饰器、延迟边界、时序画像统计与配置分支。"""

import pytest

from cipherforge.core.sidechannel import (
    SideChannelBase,
    random_delay,
    timing_jitter,
    TimingProfile,
    _self_check,
)


def test_random_delay_zero_when_max_nonpositive():
    assert random_delay(0.1, 0) == 0.0
    assert random_delay(0.1, -5) == 0.0


def test_random_delay_swaps_min_max():
    # min > max 时内部交换（lo, hi），不应报错
    d = random_delay(0.0002, 0.0001)
    assert d >= 0  # 极小范围，几乎为 0


def test_timing_jitter_decorator_enabled():
    @timing_jitter(0.0001, 0.0001)
    def add(x):
        return x + 1

    assert add(41) == 42


def test_timing_jitter_decorator_exception_delayed():
    @timing_jitter(0.0001, 0.0001)
    def boom():
        raise ValueError("boom")

    with pytest.raises(ValueError):
        boom()


def test_timing_jitter_decorator_disabled_passthrough():
    @timing_jitter(0.1, 0.5, enabled=False)
    def nine():
        return 9

    assert nine() == 9


def test_configure_side_channel_skip_none():
    base = SideChannelBase()
    # 全部传 None -> 各自的 "is not None" 分支走 False（跳过）
    base.configure_side_channel(
        enabled=None, jitter_min_ms=None, jitter_max_ms=None,
        uniform_both_paths=None,
    )
    # 值保持不变（默认）
    assert base.side_channel_enabled is True


def test_guarded_exception_with_delay():
    base = SideChannelBase()  # 默认启用且 uniform_both_paths=True
    base.jitter_min_ms = 0.0
    base.jitter_max_ms = 0.0

    def boom():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        base.guarded(boom)


def test_timing_profile_warmup_and_round_exceptions():
    prof = TimingProfile()
    calls = {"n": 0}

    def bad():
        calls["n"] += 1
        raise RuntimeError("x")

    prof.measure(bad, rounds=5, warmup=3)
    # 全部在预热/正式轮中抛异常，被静默吞掉（异常不向外传播）
    # 预热轮不计入样本、正式 5 轮各记录一次（异常路径的耗时也被采集）
    assert calls["n"] == 8  # 3 预热 + 5 正式
    assert len(prof.samples) == 5


def test_timing_profile_median_edges():
    prof = TimingProfile()
    # 空样本
    assert prof.median() == 0.0
    assert prof.mean() == 0.0
    # 偶数个样本
    prof.samples = [1.0, 2.0, 3.0, 4.0]
    assert prof.median() == 2.5
    # 奇数个样本
    prof.samples = [1.0, 2.0, 3.0]
    assert prof.median() == 2.0


def test_self_check():
    assert _self_check() is True
