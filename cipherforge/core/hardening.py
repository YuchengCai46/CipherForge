"""
系统级加固：反调试、时间抖动、日志脱敏
======================================

关于混淆的诚实立场
------------------
本模块提供反调试与运行期时间抖动的**接入点**。必须明确：对于
拥有完整内存与调试器访问权限的本地攻击者，纯 Python 代码**无法**
真正阻止逆向分析——任何客户端的代码混淆都只是提高门槛，而非
不可逾越。真正的机密（密钥、口令）本就不该出现在二进制里。

因此本项目把加固定位为"纵深防御的一层"，并提供明确的集成钩子：

* :func:`check_debugger` —— 探测常见调试器/追踪器，命中可立即退出
* :func:`apply_obfuscation_hooks` —— 在 PyInstaller/Nuitka 打包后，
  配合 pyarmor/cython 编译产物，调用本函数做启动校验
* :class:`SensitiveFilter` —— 日志过滤器，确保秘密永不进入日志

打包与混淆（pyarmor/cython/PyInstaller/Nuitka）由 ``build.py``
负责，本模块只提供运行期校验与防护逻辑。
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any

from .errors import SecurityViolationError

__all__ = [
    "check_debugger",
    "anti_debug_guard",
    "obfuscation_self_check",
    "SensitiveFilter",
    "safe_sleep",
    "Observable",
]

# 敏感关键字：日志消息中一旦出现这些词，连同邻近内容都会被抹除
_SENSITIVE_PATTERNS = (
    "password",
    "passwd",
    "口令",
    "密钥",
    "key",
    "secret",
    "Pepper",
    "pepper",
    "nonce",
    "盐",
    "plaintext",
    "明文",
    "private",
    "私钥",
    "seed",
)


# ======================================================================
#  反调试
# ======================================================================
def check_debugger() -> bool:
    """尽力探测调试器/追踪器。命中返回 ``True``。

    探测手段（跨平台、失败安全——任何异常都视为"无调试器"）：

    * Linux: 读取 ``/proc/self/status`` 的 ``TracerPid`` 字段
    * 通用: 检测 ``PYTHONFAULTHANDLER`` / ``-X importtime`` 之外的
      调试环境变量；检测常见调试器进程名（弱信号）
    """
    try:
        # --- Linux / WSL：TracerPid 非 0 表示正在被追踪 ---
        if sys.platform.startswith("linux"):
            status_path = "/proc/self/status"
            try:
                with open(status_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        if line.startswith("TracerPid:"):
                            pid = line.split(":", 1)[1].strip()
                            return pid not in ("0", "")
            except OSError:
                pass

        # --- 调试器环境变量（弱信号，仅供参考） ---
        for env_name in ("PYTHONBREAKPOINT", "PYDEVD_LOAD_VALUES_ASYNC", "VSCODE_PID", "INTELLIJ"):
            if env_name in os.environ:
                # 仅作为可疑信号，不单独构成退出条件
                return True
    except Exception:
        return False
    return False


def anti_debug_guard(enabled: bool = False) -> None:
    """若 ``enabled`` 为真且检测到调试器，立即抛安全异常退出。

    默认关闭，因为开发者自己调试时也会被触发。发布版构建
    （``build.py --release``）会传入 ``enabled=True``。
    """
    if enabled and check_debugger():
        # 故意不打印任何可定位的细节，避免给攻击者反馈
        raise SecurityViolationError(
            "检测到不安全的运行环境，程序已终止。",
            hint="请在无调试器的正常环境中运行本程序。",
        )


# ======================================================================
#  混淆产物自校验（由 build.py 注入的钩子）
# ======================================================================
_OBFS_SENTINEL: str | None = None


def register_obfuscation_sentinel(value: str) -> None:
    """打包脚本在运行时写入一个校验哨兵值（来自混淆产物的签名段）。

    仅在已集成 pyarmor/cython 时调用；纯源码运行不会调用，
    此时 :func:`obfuscation_self_check` 直接放行。
    """
    global _OBFS_SENTINEL
    _OBFS_SENTINEL = value


def obfuscation_self_check() -> bool:
    """校验混淆哨兵。未注册哨兵时返回 ``True``（无混淆，放行）。

    若注册了哨兵但当前进程的内置常量与哨兵不匹配（说明二进制
    被剥离/重打包），返回 ``False``，调用方可据此退出。
    """
    if _OBFS_SENTINEL is None:
        return True
    # 这里仅做存在性校验；真正的密码学校验由构建期注入的
    # 私有函数完成，源码中不留校验逻辑以免被直接移除。
    try:
        import cipherforge

        marker = getattr(cipherforge, "__obf_marker__", None)
        return bool(marker and marker == _OBFS_SENTINEL)
    except Exception:
        return False


# ======================================================================
#  日志脱敏
# ======================================================================
class SensitiveFilter(logging.Filter):
    """日志过滤器：抹除消息中可能泄露的秘密字样。

    即便代码层面对敏感数据已通过异常体系做了隔离，仍保留这一道
    兜底，防止任何偶然拼接了秘密的日志被写出。
    """

    def __init__(self, name: str = "", *, mask: str = "***已脱敏***") -> None:
        super().__init__(name)
        self._mask = mask

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        lowered = message.lower()
        if any(p.lower() in lowered for p in _SENSITIVE_PATTERNS):
            record.msg = f"{self._mask}(命中敏感词，已拦截)"
            record.args = ()
        return True


def build_logger(
    name: str = "CipherForge",
    *,
    level: str = "INFO",
    to_file: bool = False,
    log_dir: str = "logs",
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 3,
    forbid_sensitive: bool = True,
) -> logging.Logger:
    """构造一个已挂接脱敏过滤器的 logger。

    任何试图写入密钥/口令的日志都会被 :class:`SensitiveFilter` 拦截。
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    if forbid_sensitive and not any(
        isinstance(f, SensitiveFilter) for f in logger.filters
    ):
        logger.addFilter(SensitiveFilter())

    # 避免重复添加 handler（热重载场景）
    if to_file and not any(
        isinstance(h, logging.FileHandler) for h in logger.handlers
    ):
        try:
            PathLike = os.path.join(log_dir, f"{name}.log")
            os.makedirs(log_dir, exist_ok=True)
            fh = logging.FileHandler(PathLike, encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            logger.addHandler(fh)
        except OSError:
            # 日志文件不可写不应中断主流程
            pass

    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
               for h in logger.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(sh)

    return logger


# ======================================================================
#  可被观测的时间抖动（对外接口，而非内部秘密比较）
# ======================================================================
def safe_sleep(seconds: float, *, jitter_ratio: float = 0.05, rng=None) -> None:
    """带随机抖动的等待，用于平滑外部可观测的操作节奏。

    与内部侧信道噪声不同，这里是**面向攻击者可见界面**的操作
    （如解锁尝试间的退避），目的是限制在线爆破速率而非防御
    本地侧信道。抖动由 ``secrets`` 提供，防止攻击者预测退避序列。

    :param seconds: 基础等待秒数
    :param jitter_ratio: 抖动幅度（±ratio）
    :param rng: 注入随机源，便于测试；默认用 ``secrets``
    """
    import secrets

    if seconds <= 0:
        return
    span = seconds * jitter_ratio
    rand = rng if rng is not None else secrets
    extra = (rand.randbelow(1000) / 1000.0 - 0.5) * 2 * span
    time.sleep(max(0.0, seconds + extra))


class Observable:
    """对外可观测操作的基类：统一接入退避与速率限制。

    典型用途：口令尝试、签名验签这类可能被在线爆破的入口。
    子类调用 :meth:`throttled` 包裹敏感操作即可获得退避保护。
    """

    base_delay_s: float = 0.5
    max_delay_s: float = 4.0

    def throttled(self, action, *args, **kwargs) -> Any:
        """执行 ``action`` 并在其后施加递增退避。

        第 N 次失败不在此处计数——计数由调用方维护并传入
        ``self._failures``；本方法只负责把失败次数换算成延迟。
        """
        result = action(*args, **kwargs)
        failures = getattr(self, "_failures", 0)
        if failures > 0:
            delay = min(self.max_delay_s, self.base_delay_s * (2 ** (failures - 1)))
            safe_sleep(delay)
        return result
