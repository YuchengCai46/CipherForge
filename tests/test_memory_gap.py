"""内存安全模块补充覆盖：POSIX 锁定分支、分配/擦除边界与兜底路径。"""

import types

import pytest

from cipherforge.core import memory
from cipherforge.core.memory import (
    SecureMemoryBase,
    lock_memory,
    unlock_memory,
    wipe_bytearray,
)


def test_allocate_with_lock():
    b = SecureMemoryBase()
    buf = b._allocate(16, lock=True)
    assert len(buf) == 16
    assert buf in b._secure_buffers


def test_zeroize_force_gc_false():
    b = SecureMemoryBase()
    b.force_gc = False
    b._allocate(16)
    b.zeroize()
    assert b._zeroized is True


def test_zeroize_unlock_raises_is_swallowed(monkeypatch):
    b = SecureMemoryBase()
    buf = b._allocate(16)

    def boom(_buf):
        raise RuntimeError("unlock failed")

    monkeypatch.setattr(memory, "unlock_memory", boom)
    b.zeroize()  # 不应因 unlock 异常而传播
    assert b._zeroized is True


def test_posix_lock_unlock(monkeypatch):
    # 在非 Windows 分支下演练 mlock/munlock 调用（用伪 libc 避免真实系统调用）
    fake_lib = types.SimpleNamespace(
        mlock=lambda *a, **k: 0, munlock=lambda *a, **k: 0
    )

    def fake_cdll(*a, **k):
        return fake_lib

    monkeypatch.setattr(memory, "_IS_WINDOWS", False)
    monkeypatch.setattr("ctypes.CDLL", fake_cdll)
    buf = bytearray(16)
    assert lock_memory(buf) is True
    assert unlock_memory(buf) is True


def test_wipe_bytearray_fallback_when_no_address(monkeypatch):
    # _get_buffer_address 抛错时退化为纯 Python 清零
    def raise_oserror(_buf):
        raise OSError("no buffer address")

    monkeypatch.setattr(memory, "_get_buffer_address", raise_oserror)
    buf = bytearray(b"secret-bytes")
    wipe_bytearray(buf)
    assert buf == bytearray(len(buf))
