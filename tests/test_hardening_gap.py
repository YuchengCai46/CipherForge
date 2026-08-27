"""加固模块补充覆盖：Linux 调试器探针对 `/proc` 的读取、日志文件不可写降级。"""

import logging
import os
import sys

import pytest

from cipherforge.core.hardening import build_logger, check_debugger


def _fake_proc_file(tracer_pid: str):
    class FakeFile:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def __iter__(self):
            text = f"Name: test\nTracerPid:\t{tracer_pid}\nState: S\n"
            return iter(text.splitlines(keepends=True))

    return FakeFile()


def test_check_debugger_linux_tracer_present(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("builtins.open", lambda *a, **k: _fake_proc_file("1234"))
    assert check_debugger() is True


def test_check_debugger_linux_no_tracer(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("builtins.open", lambda *a, **k: _fake_proc_file("0"))
    assert check_debugger() is False


def test_build_logger_file_write_oserror(monkeypatch):
    def boom(*a, **k):
        raise OSError("log dir not writable")

    monkeypatch.setattr(os, "makedirs", boom)
    logger = build_logger("GapTestLogger", to_file=True, log_dir="bad/path")
    assert logger is not None
    # 降级：没有挂 FileHandler，但 StreamHandler 仍然存在
    assert any(
        isinstance(h, logging.StreamHandler)
        for h in logger.handlers
        if not isinstance(h, logging.FileHandler)
    )
