import pytest

from cipherforge.core.sidechannel import (
    SideChannelBase,
    conditional_copy,
    constant_time_compare,
    constant_time_compare_int,
    select,
    TimingProfile,
)


def test_constant_time_compare():
    assert constant_time_compare(b"abc", b"abc")
    assert not constant_time_compare(b"abc", b"abd")
    assert not constant_time_compare(b"abc", b"abcd")


def test_constant_time_compare_int():
    assert constant_time_compare_int(123, 123)
    assert not constant_time_compare_int(123, 124)
    # 溢出（超过指定比特宽）应判不等
    assert not constant_time_compare_int(300, 300, bit_length=8)


def test_select_mask():
    assert select(1, 0xAA, 0xBB) == 0xAA
    assert select(0, 0xAA, 0xBB) == 0xBB
    # condition 必须为 0/1：非 1 会被 &1 归一
    assert select(3, 0xAA, 0xBB) == 0xAA


def test_conditional_copy():
    dst = bytearray(b"AAAAAAAA")
    src = bytearray(b"BBBBBBBB")
    conditional_copy(1, dst, src)
    assert dst == src
    dst2 = bytearray(b"AAAAAAAA")
    conditional_copy(0, dst2, src)
    assert dst2 == b"AAAAAAAA"


def test_conditional_copy_length_mismatch():
    dst = bytearray(b"AAAA")
    src = bytearray(b"BBBBBBBB")
    with pytest.raises(ValueError):
        conditional_copy(1, dst, src)


def test_timing_jitter_decorator():
    base = SideChannelBase()

    def work():
        return 42

    # guarded 是"带噪声保护的调用器"，直接运行被保护函数。
    assert base.guarded(work) == 42


def test_timing_jitter_disabled_passthrough():
    base = SideChannelBase()
    base.side_channel_enabled = False

    def work():
        return 7

    assert base.guarded(work) == 7


def test_timing_profile_basic():
    prof = TimingProfile()
    prof.measure(
        lambda: constant_time_compare(b"a" * 32, b"a" * 32), rounds=50, warmup=5
    )
    assert prof.mean() >= 0
    assert prof.relative_stdev() >= 0


def test_timing_profile_stats():
    prof = TimingProfile()
    prof.samples = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0]
    assert prof.mean() == 6.5
    assert prof.median() == 6.5
    assert prof.stdev() > 0
    assert prof.relative_stdev() == pytest.approx(prof.stdev() / 6.5)
    assert prof.trimmed_relative_stdev() >= 0
    summary = prof.summary()
    assert summary["样本数"] == 12


def test_timing_profile_empty():
    prof = TimingProfile()
    assert prof.mean() == 0.0
    assert prof.stdev() == 0.0
    assert prof.relative_stdev() == 0.0


def test_timing_profile_too_few_for_trim():
    prof = TimingProfile()
    prof.samples = [1.0, 2.0, 3.0]
    # 样本不足 10 时退回未裁剪指标
    assert prof.trimmed_relative_stdev() == prof.relative_stdev()


def test_random_delay_bounded():
    base = SideChannelBase()
    base.side_channel_enabled = True
    d = base.jitter()
    assert d >= 0


def test_random_delay_disabled_is_zero():
    base = SideChannelBase()
    base.side_channel_enabled = False
    assert base.jitter() == 0.0


def test_ct_verify_success():
    base = SideChannelBase()

    class E(Exception):
        pass

    # 成功路径不应抛
    base.ct_verify(b"x" * 16, b"x" * 16, E())


def test_ct_verify_failure_raises():
    base = SideChannelBase()

    class E(Exception):
        pass

    with pytest.raises(E):
        base.ct_verify(b"x" * 16, b"y" * 16, E())


def test_ct_verify_disabled_no_delay():
    base = SideChannelBase()
    base.side_channel_enabled = False

    class E(Exception):
        pass

    base.ct_verify(b"x" * 16, b"x" * 16, E())  # 不抛
    with pytest.raises(E):
        base.ct_verify(b"x" * 16, b"y" * 16, E())


def test_configure_side_channel():
    base = SideChannelBase()
    base.configure_side_channel(
        enabled=False,
        jitter_min_ms=0.01,
        jitter_max_ms=0.02,
        uniform_both_paths=False,
    )
    assert base.side_channel_enabled is False
    assert base.jitter_min_ms == 0.01
    assert base.jitter_max_ms == 0.02
    assert base.uniform_both_paths is False


def test_guarded_exception_still_delayed_or_raises():
    base = SideChannelBase()
    base.side_channel_enabled = False

    def boom():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        base.guarded(boom)
