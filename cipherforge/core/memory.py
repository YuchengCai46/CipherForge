"""
内存安全基类
============

Python 无法真正保证秘密材料从物理内存中消失——GC、字符串驻留、
写时复制、内存换页都会留下副本。本模块把风险压到语言允许的最低限度：

* 秘密**只存放在 ``bytearray``** 中（可变缓冲区，可原地覆写）。
  绝不使用 ``bytes`` 或 ``str`` 保存长期秘密：不可变对象无法擦除。
* 销毁时先用 CSPRNG 随机数据多轮覆写，再整体清零，最后截断长度。
  多轮覆写可降低残留磁化/单元电荷被恢复的可能性。
* 使用 ``ctypes.memset`` 直接操作缓冲区地址，绕过解释器层面的优化，
  避免"死存储消除"把清零动作优化掉。
* 可选调用 ``VirtualLock`` / ``mlock`` 把页面锁定在物理内存，
  防止秘密被换出到磁盘交换文件。
* 支持上下文管理器语法，异常路径同样保证擦除。

用法
----
>>> with SecureBytes(b"my-secret-key") as key:
...     do_something(key.view())
... # 退出作用域时缓冲区已被覆写清零

安全提醒
--------
``SecureBytes.__repr__`` **永不**输出内容，只输出长度与状态，
以防秘密意外进入日志、异常回溯或调试器输出。
"""

from __future__ import annotations

import ctypes
import gc
import os
import sys
from typing import Iterator

__all__ = [
    "SecureBytes",
    "SecureMemoryBase",
    "wipe_bytearray",
    "constant_time_copy",
    "lock_memory",
    "unlock_memory",
]

# ----------------------------------------------------------------------
#  平台相关的内存锁定
# ----------------------------------------------------------------------
_IS_WINDOWS = sys.platform.startswith("win")


def _get_buffer_address(buf: bytearray) -> int:
    """取得 bytearray 底层数据区的真实地址。"""
    return ctypes.addressof(ctypes.c_char.from_buffer(buf))


def lock_memory(buf: bytearray) -> bool:
    """尝试把缓冲区锁定在物理内存，阻止换出到交换分区。

    :return: 成功返回 ``True``；权限不足或平台不支持返回 ``False``（仅告警）。
    """
    if not buf:
        return False
    try:
        addr = _get_buffer_address(buf)
        size = len(buf)
        if _IS_WINDOWS:
            # BOOL VirtualLock(LPVOID lpAddress, SIZE_T dwSize)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            return bool(kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(size)))
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        return libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size)) == 0
    except Exception:
        # 内存锁定属于"尽力而为"的加固，失败不应中断业务流程
        return False


def unlock_memory(buf: bytearray) -> bool:
    """解除 :func:`lock_memory` 的锁定。"""
    if not buf:
        return False
    try:
        addr = _get_buffer_address(buf)
        size = len(buf)
        if _IS_WINDOWS:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            return bool(kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(size)))
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        return libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size)) == 0
    except Exception:
        return False


# ----------------------------------------------------------------------
#  擦除原语
# ----------------------------------------------------------------------
def wipe_bytearray(
    buf: bytearray,
    *,
    passes: int = 3,
    overwrite_random: bool = True,
) -> None:
    """原地擦除 ``bytearray``：多轮随机覆写 + 最终清零。

    实现要点：

    * 通过 ``ctypes.memset`` 写入，编译器/解释器无法将其优化掉。
    * 随机覆写使用 ``os.urandom``（操作系统 CSPRNG）。
    * 最后一轮必定是全零，保证残留内容确定且无信息量。
    * 本函数**不抛异常**：擦除失败时退化为纯 Python 切片赋值，
      因为在清理路径上抛错只会让情况更糟。

    :param buf: 待擦除缓冲区（原地修改）
    :param passes: 随机覆写轮数，取值被夹在 1~7
    :param overwrite_random: 关闭时只做清零（更快，安全性略降）
    """
    if not isinstance(buf, bytearray) or len(buf) == 0:
        return

    size = len(buf)
    passes = max(1, min(7, int(passes)))

    try:
        addr = _get_buffer_address(buf)

        if overwrite_random:
            for _ in range(passes):
                noise = os.urandom(size)
                ctypes.memmove(addr, noise, size)
                # 立刻销毁噪声副本的引用（bytes 不可变，只能等 GC）
                del noise

        # 终局清零
        ctypes.memset(addr, 0, size)
    except Exception:
        # 兜底：纯 Python 覆写。虽可能被优化，但总比什么都不做好。
        try:
            for i in range(size):
                buf[i] = 0
        except Exception:
            pass


def constant_time_copy(dst: bytearray, src: bytes | bytearray, offset: int = 0) -> None:
    """把 ``src`` 拷入 ``dst``，耗时只与长度相关，不依赖内容。"""
    length = len(src)
    if offset < 0 or offset + length > len(dst):
        raise ValueError("目标缓冲区容量不足，无法完成拷贝。")
    dst[offset : offset + length] = src


# ----------------------------------------------------------------------
#  基类
# ----------------------------------------------------------------------
class SecureMemoryBase:
    """内存安全基类：任何持有秘密材料的类都应继承它。

    子类需把秘密登记到 ``self._secure_buffers``，
    基类的 :meth:`zeroize` 会统一擦除。

    子类还应避免：

    * 把秘密放进 ``__repr__`` / ``__str__``
    * 把秘密写入日志或异常消息
    * 用 ``str`` / ``bytes`` 长期保存秘密
    """

    #: 覆写轮数，可由配置覆盖
    wipe_passes: int = 3
    #: 是否在清零前先随机覆写
    overwrite_before_zero: bool = True
    #: 擦除后是否强制 GC
    force_gc: bool = True

    def __init__(self) -> None:
        self._secure_buffers: list[bytearray] = []
        self._zeroized: bool = False

    # ------------------------------------------------------------ 登记
    def _register(self, buf: bytearray) -> bytearray:
        """登记一块需要在销毁时擦除的缓冲区。"""
        if not isinstance(buf, bytearray):
            raise TypeError("只能登记 bytearray；不可变对象无法安全擦除。")
        self._secure_buffers.append(buf)
        return buf

    def _allocate(self, size: int, *, lock: bool = False) -> bytearray:
        """分配一块已登记的零初始化安全缓冲区。"""
        buf = bytearray(size)
        if lock:
            lock_memory(buf)
        return self._register(buf)

    # ------------------------------------------------------------ 擦除
    def zeroize(self) -> None:
        """立即擦除全部登记的秘密材料。可重复调用（幂等）。"""
        if self._zeroized:
            return
        for buf in self._secure_buffers:
            try:
                unlock_memory(buf)
            except Exception:
                pass
            wipe_bytearray(
                buf,
                passes=self.wipe_passes,
                overwrite_random=self.overwrite_before_zero,
            )
            # 截断长度，让缓冲区连"曾有多长"都不再暴露
            try:
                del buf[:]
            except Exception:
                pass
        self._secure_buffers.clear()
        self._zeroized = True
        if self.force_gc:
            gc.collect()

    # ------------------------------------------------------------ 生命周期
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        # 无论正常退出还是异常退出，都保证擦除
        self.zeroize()
        return False  # 不吞掉异常

    def __del__(self) -> None:  # pragma: no cover - 依赖 GC 时机
        try:
            self.zeroize()
        except Exception:
            pass

    # ------------------------------------------------------------ 表示
    def __repr__(self) -> str:
        state = "已擦除" if self._zeroized else f"{len(self._secure_buffers)} 块活动缓冲区"
        return f"<{type(self).__name__} {state}>"


class SecureBytes(SecureMemoryBase):
    """可擦除的字节容器，用于承载密钥、口令、Pepper 等秘密材料。

    与 ``bytes`` 的关键差异：

    * 内容存于 ``bytearray``，可原地覆写
    * :meth:`zeroize` 后长度归零，内容不可恢复
    * ``__repr__`` 只暴露长度，绝不暴露内容
    * 支持 ``len()``、切片读取、缓冲区协议（可直接传给密码学 API）

    >>> sb = SecureBytes(b"secret")
    >>> len(sb)
    6
    >>> sb.zeroize()
    >>> len(sb)
    0
    """

    __slots__ = ("_buf", "_secure_buffers", "_zeroized", "_locked")

    def __init__(
        self,
        data: bytes | bytearray | memoryview | str = b"",
        *,
        encoding: str = "utf-8",
        lock: bool = False,
    ) -> None:
        super().__init__()
        if isinstance(data, str):
            # str 是不可变且可能被驻留的，转换后原字符串无法擦除。
            # 这里接受该风险以便利，但在文档中明确告知调用方。
            raw = data.encode(encoding)
        else:
            raw = bytes(data)
        self._buf: bytearray = bytearray(raw)
        self._locked = lock_memory(self._buf) if lock else False
        self._register(self._buf)

    # ------------------------------------------------------------ 构造
    @classmethod
    def random(cls, size: int, *, lock: bool = False) -> "SecureBytes":
        """用操作系统 CSPRNG 生成 ``size`` 字节随机秘密。"""
        if size <= 0:
            raise ValueError("随机秘密长度必须为正数。")
        return cls(os.urandom(size), lock=lock)

    @classmethod
    def zeros(cls, size: int, *, lock: bool = False) -> "SecureBytes":
        """分配 ``size`` 字节的零初始化安全缓冲区。"""
        return cls(bytes(size), lock=lock)

    # ------------------------------------------------------------ 读取
    def view(self) -> memoryview:
        """返回底层缓冲区的 ``memoryview``（零拷贝）。

        ⚠ 调用方不得在 :meth:`zeroize` 之后继续使用返回的视图。
        """
        self._ensure_alive()
        return memoryview(self._buf)

    def to_bytes(self) -> bytes:
        """导出为不可变 ``bytes``。

        ⚠ 返回值**无法被擦除**。仅在必须传给只接受 ``bytes`` 的
        第三方 API 时使用，且应尽快让其失去引用。
        """
        self._ensure_alive()
        return bytes(self._buf)

    def hex(self) -> str:
        """导出十六进制字符串（同样无法擦除，谨慎使用）。"""
        self._ensure_alive()
        return self._buf.hex()

    def _ensure_alive(self) -> None:
        if self._zeroized:
            raise ValueError("该 SecureBytes 已被擦除，不能再读取其内容。")

    # ------------------------------------------------------------ 协议
    def __len__(self) -> int:
        return len(self._buf)

    def __bool__(self) -> bool:
        return len(self._buf) > 0

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __buffer__(self, flags: int) -> memoryview:  # Python 3.12+ 缓冲区协议
        self._ensure_alive()
        return memoryview(self._buf)

    def __getitem__(self, item) -> int | bytes:
        self._ensure_alive()
        result = self._buf[item]
        return bytes(result) if isinstance(item, slice) else result

    def __iter__(self) -> Iterator[int]:
        self._ensure_alive()
        return iter(self._buf)

    def __eq__(self, other: object) -> bool:
        """恒定时间相等比较，避免通过耗时泄露秘密内容。"""
        import hmac

        if isinstance(other, SecureBytes):
            if other._zeroized or self._zeroized:
                return self._zeroized and other._zeroized
            return hmac.compare_digest(bytes(self._buf), bytes(other._buf))
        if isinstance(other, (bytes, bytearray, memoryview)):
            if self._zeroized:
                return False
            return hmac.compare_digest(bytes(self._buf), bytes(other))
        return NotImplemented

    def __hash__(self):
        # 秘密不应作为字典键：哈希值本身就是内容的泄露渠道
        raise TypeError("SecureBytes 不可哈希，以避免秘密内容通过哈希值泄露。")

    def __repr__(self) -> str:
        if self._zeroized:
            return "<SecureBytes 已擦除>"
        lock_tag = " 已锁页" if self._locked else ""
        return f"<SecureBytes {len(self._buf)} 字节{lock_tag}>"

    __str__ = __repr__

    # ------------------------------------------------------------ 变换
    def append(self, data: bytes | bytearray) -> None:
        """追加数据（用于增量拼装秘密）。"""
        self._ensure_alive()
        self._buf.extend(data)

    def split_at(self, index: int) -> tuple["SecureBytes", "SecureBytes"]:
        """在 ``index`` 处切成两个新的 :class:`SecureBytes`。

        常用于把一次 KDF 输出拆成"加密密钥 + MAC 密钥"。
        """
        self._ensure_alive()
        if not 0 <= index <= len(self._buf):
            raise ValueError("切分位置越界。")
        return SecureBytes(self._buf[:index]), SecureBytes(self._buf[index:])
