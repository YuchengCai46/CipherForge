"""运行时加固测试：反调试、混淆自校验、日志脱敏、时间抖动、Observable。"""

import importlib
import logging
import os

import pytest

import cipherforge
from cipherforge.core import hardening
from cipherforge.core.errors import SecurityViolationError
from cipherforge.core.hardening import (
    check_debugger,
    anti_debug_guard,
    SensitiveFilter,
    build_logger,
    safe_sleep,
    Observable,
    register_obfuscation_sentinel,
    obfuscation_self_check,
)


def test_check_debugger_clean():
    assert check_debugger() is False


def test_check_debugger_env_signal(monkeypatch):
    monkeypatch.setenv("VSCODE_PID", "4242")
    assert check_debugger() is True
    monkeypatch.delenv("VSCODE_PID", raising=False)
    assert check_debugger() is False


def test_anti_debug_guard_disabled_ok():
    anti_debug_guard(enabled=False)  # 不抛


def test_anti_debug_guard_enabled_no_debugger():
    anti_debug_guard(enabled=True)  # 当前无调试器，不抛


def test_anti_debug_guard_enabled_with_debugger(monkeypatch):
    monkeypatch.setenv("PYTHONBREAKPOINT", "1")
    with pytest.raises(SecurityViolationError):
        anti_debug_guard(enabled=True)
    monkeypatch.delenv("PYTHONBREAKPOINT", raising=False)


def test_obfuscation_self_check_no_sentinel():
    # 确保没有已注册哨兵
    import cipherforge.core.hardening as hm

    hm._OBFS_SENTINEL = None
    assert obfuscation_self_check() is True


def test_obfuscation_self_check_with_sentinel(monkeypatch):
    sentinel = "secret-marker-123"
    register_obfuscation_sentinel(sentinel)
    try:
        # 无 __obf_marker__ -> 校验失败
        assert obfuscation_self_check() is False
        # 匹配 marker -> 通过
        monkeypatch.setattr(cipherforge, "__obf_marker__", sentinel, raising=False)
        assert obfuscation_self_check() is True
    finally:
        import cipherforge.core.hardening as hm

        hm._OBFS_SENTINEL = None
        monkeypatch.delattr(cipherforge, "__obf_marker__", raising=False)


def test_sensitive_filter_masks():
    f = SensitiveFilter()
    rec = logging.LogRecord(
        "t", logging.INFO, "p", 1, "user password=secret123", None, None
    )
    assert f.filter(rec) is True
    assert "secret123" not in rec.getMessage()
    assert "已脱敏" in rec.getMessage()


def test_sensitive_filter_passthrough():
    f = SensitiveFilter()
    rec = logging.LogRecord("t", logging.INFO, "p", 1, "normal log line", None, None)
    f.filter(rec)
    assert rec.getMessage() == "normal log line"


def test_build_logger_default(tmp_path):
    logger = build_logger(
        "TestLogger", level="DEBUG", to_file=True, log_dir=str(tmp_path)
    )
    assert logger.level == logging.DEBUG
    # 脱敏过滤器已挂载
    assert any(isinstance(f, SensitiveFilter) for f in logger.filters)
    # 至少一个 StreamHandler
    assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
    # 写入日志（含敏感词会被过滤）
    logger.info("access password=topsecret")
    # 文件日志生成
    log_file = tmp_path / "TestLogger.log"
    assert log_file.exists()


def test_build_logger_no_sensitive(tmp_path):
    logger = build_logger(
        "NoSens", forbid_sensitive=False, to_file=False
    )
    assert not any(isinstance(f, SensitiveFilter) for f in logger.filters)


def test_build_logger_idempotent_handlers():
    # 重复构建同名 logger 不应无限叠加 StreamHandler
    l1 = build_logger("DupLog", to_file=False)
    n1 = len([h for h in l1.handlers if isinstance(h, logging.StreamHandler)])
    l2 = build_logger("DupLog", to_file=False)
    n2 = len([h for h in l2.handlers if isinstance(h, logging.StreamHandler)])
    assert n1 == n2 == 1


def test_safe_sleep_zero():
    assert safe_sleep(0) is None
    assert safe_sleep(-1) is None


def test_safe_sleep_positive_with_rng():
    class FakeRng:
        def randbelow(self, n):
            return 0  # 最小延迟

    # 用极小值避免真实等待
    safe_sleep(0.0001, jitter_ratio=0.0, rng=FakeRng())
    # 抖动路径
    safe_sleep(0.0001, jitter_ratio=0.5, rng=FakeRng())


def test_observable_throttled():
    obs = Observable()
    obs.base_delay_s = 0.0  # 避免真实延迟
    obs.max_delay_s = 0.0

    def action(x):
        return x * 2

    # 无失败 -> 不延迟
    obs._failures = 0
    assert obs.throttled(action, 21) == 42
    # 有失败 -> 施加退避（delay 为 0，瞬时）
    obs._failures = 3
    assert obs.throttled(action, 21) == 42
