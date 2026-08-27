"""
配置加载与环境自适应
====================

职责
----
1. 读取 ``config.yaml``，缺失字段回退到内置默认值（永不因缺字段崩溃）。
2. 校验取值范围，越界时**夹取到合法区间并告警**，而不是直接抛错——
   桌面工具的可用性优先，但绝不接受会削弱安全性的取值。
3. 探测物理内存与 CPU 核心数，把参数按 8GB~128GB 区间自适应缩放。

内存探测策略
------------
优先使用平台原生 API（Windows ``GlobalMemoryStatusEx`` /
Linux ``sysconf`` / macOS ``sysctl``），避免为了读一个数字
而强制依赖 ``psutil``。探测失败时回退到配置中的
``reference_ram_gb``（默认 32GB），保证流程继续。
"""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError

__all__ = ["Config", "load_config", "detect_total_ram_gb", "detect_cpu_count", "SystemProfile"]


# ======================================================================
#  内置默认配置
# ======================================================================
DEFAULT_CONFIG: dict[str, Any] = {
    "meta": {"app_name": "CipherForge", "version": "1.0.0", "config_schema": 1},
    "environment": {
        "reference_ram_gb": 32,
        "min_ram_gb": 8,
        "max_ram_gb": 128,
        "kdf_memory_budget_ratio": 0.06,
        "max_workers": None,
    },
    "security": {
        "side_channel": {
            "enabled": True,
            "jitter_min_ms": 0.05,
            "jitter_max_ms": 0.60,
            "uniform_both_paths": True,
        },
        "memory": {
            "overwrite_before_zero": True,
            "overwrite_passes": 3,
            "force_gc": True,
            "try_mlock": True,
        },
        "hardening": {
            "anti_debug": False,
            "timing_jitter": True,
            "forbid_sensitive_logging": True,
        },
    },
    "symmetric": {
        "default_algorithm": "AES-256-GCM",
        "nonce_bytes": 12,
        "xnonce_bytes": 24,
        "salt_bytes": 16,
        "tag_bytes": 16,
        "streaming": {
            "chunk_size_mib": 4,
            "auto_scale_chunk": True,
            "max_chunk_size_mib": 64,
            "max_file_size_gib": 64,
        },
    },
    "kdf": {
        "default": "argon2id",
        "auto_tune": True,
        "target_ms": 400,
        "benchmark_budget_ms": 500,
        "output_length": 32,
        "argon2id": {
            "time_cost": 3,
            "memory_cost_kib": 262144,
            "parallelism": 4,
            "min_memory_cost_kib": 65536,
            "max_memory_cost_kib": 4194304,
        },
        "pbkdf2": {"hash": "sha512", "iterations": 600000, "min_iterations": 210000},
    },
    "hashing": {
        "default_algorithm": "SHA3-256",
        "shake_output_bytes": 64,
        "pepper_enabled": True,
        "smart_verify": True,
    },
    "pq_signature": {
        "default_algorithm": "ML-DSA-87",
        "default_validity_hours": 720,
        "clock_skew_tolerance_s": 300,
        "timestamp_in_signature": True,
    },
    "shamir": {
        "default_shares": 5,
        "default_threshold": 3,
        "max_shares": 256,
        "emit_text": True,
        "emit_qrcode": True,
        "qrcode_box_size": 6,
        "qrcode_border": 2,
        "share_checksum": True,
    },
    "steganography": {
        "default_bit_depth": 1,
        "max_bit_depth": 4,
        "compress": True,
        "compress_level": 9,
        "randomized_embedding": True,
        "force_lossless_output": True,
        "supported_carriers": [".png", ".bmp", ".jpg", ".jpeg"],
    },
    "cascade": {
        "default_layers": ["AES-256-GCM", "ChaCha20-Poly1305", "XChaCha20-Poly1305"],
        "max_layers": 8,
        "per_layer_hkdf": True,
        "hkdf_hash": "sha512",
        "tag_chaining": True,
        "header_signature": True,
        "auto_reverse": True,
    },
    "password_generator": {
        "default_length": 24,
        "min_length": 8,
        "max_length": 512,
        "charsets": {"lowercase": True, "uppercase": True, "digits": True, "symbols": True},
        "exclude_ambiguous": False,
        "require_each_class": True,
        "passphrase": {
            "default_words": 6,
            "separator": "-",
            "capitalize": True,
            "inject_digit": True,
        },
    },
    "gui": {
        "mode": "workshop",
        "theme": "cyber-neon",
        "window_width": 1280,
        "window_height": 820,
        "min_width": 1024,
        "min_height": 700,
        "font_family_zh": "Microsoft YaHei UI",
        "font_size": 10,
        "enable_drag_drop": True,
        "enable_system_notification": True,
        "autoclear_secret_seconds": 0,
    },
    "logging": {
        "level": "INFO",
        "to_file": True,
        "directory": "logs",
        "max_bytes": 5242880,
        "backup_count": 3,
        "diagnostics_directory": "diagnostics",
    },
    "paths": {
        "output_directory": "output",
        "temp_directory": ".cfg_tmp",
        "wipe_temp_on_failure": True,
    },
}


# ======================================================================
#  环境探测
# ======================================================================
def detect_total_ram_gb(fallback_gb: float = 32.0) -> float:
    """探测物理内存总量（GB）。探测失败返回 ``fallback_gb``。"""
    try:
        if sys.platform.startswith("win"):

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):  # type: ignore[attr-defined]
                return stat.ullTotalPhys / (1024**3)

        elif sys.platform == "darwin":
            import subprocess

            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], timeout=3)
            return int(out.strip()) / (1024**3)

        else:  # Linux / BSD
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            if pages > 0 and page_size > 0:
                return (pages * page_size) / (1024**3)
    except Exception:
        pass

    # 最后再试一次 psutil（若恰好装了）
    try:
        import psutil  # type: ignore

        return psutil.virtual_memory().total / (1024**3)
    except Exception:
        return fallback_gb


def detect_cpu_count() -> int:
    """探测可用逻辑 CPU 核心数，至少返回 1。"""
    try:
        # 优先使用受 cgroup / affinity 限制的真实可用核心数
        if hasattr(os, "sched_getaffinity"):
            return max(1, len(os.sched_getaffinity(0)))  # type: ignore[attr-defined]
    except Exception:
        pass
    return max(1, os.cpu_count() or 1)


@dataclass(frozen=True)
class SystemProfile:
    """探测得到的运行环境画像。"""

    ram_gb: float
    cpu_count: int
    platform: str
    python_version: str

    #: 按 8~128GB 归一化后的内存档位（0.0 = 8GB, 1.0 = 128GB）
    @property
    def ram_scale(self) -> float:
        lo, hi = 8.0, 128.0
        clamped = max(lo, min(hi, self.ram_gb))
        return (clamped - lo) / (hi - lo)

    @property
    def tier(self) -> str:
        """内存档位描述，用于界面展示。"""
        if self.ram_gb < 12:
            return "轻量 (8GB 级)"
        if self.ram_gb < 24:
            return "标准 (16GB 级)"
        if self.ram_gb < 48:
            return "推荐 (32GB 级)"
        if self.ram_gb < 96:
            return "高性能 (64GB 级)"
        return "工作站 (128GB 级)"

    def describe(self) -> str:
        return (
            f"{self.platform} | Python {self.python_version} | "
            f"{self.cpu_count} 核 | {self.ram_gb:.1f} GB 内存 | 档位：{self.tier}"
        )

    @classmethod
    def detect(cls, fallback_ram_gb: float = 32.0) -> "SystemProfile":
        return cls(
            ram_gb=detect_total_ram_gb(fallback_ram_gb),
            cpu_count=detect_cpu_count(),
            platform=sys.platform,
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )


# ======================================================================
#  配置对象
# ======================================================================
def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """递归合并：``override`` 中存在的键覆盖 ``base``，其余保留默认。"""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _clamp(value: Any, lo: float, hi: float, default: float, warnings: list[str], label: str) -> float:
    """把数值夹取到 ``[lo, hi]``；类型非法则回退默认值并记录告警。"""
    try:
        num = float(value)
    except (TypeError, ValueError):
        warnings.append(f"{label} 取值 {value!r} 非数值，已回退为 {default}。")
        return default
    if num < lo:
        warnings.append(f"{label} 取值 {num} 低于下限 {lo}，已提升至 {lo}。")
        return lo
    if num > hi:
        warnings.append(f"{label} 取值 {num} 高于上限 {hi}，已下调至 {hi}。")
        return hi
    return num


@dataclass
class Config:
    """已校验、已自适应的配置容器。

    通过点分路径读取，永不抛 ``KeyError``：

    >>> cfg = load_config()
    >>> cfg.get("symmetric.default_algorithm")
    'AES-256-GCM'
    >>> cfg.get("不存在.的.键", "默认值")
    '默认值'
    """

    data: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_CONFIG))
    system: SystemProfile = field(default_factory=SystemProfile.detect)
    warnings: list[str] = field(default_factory=list)
    source_path: Path | None = None

    # ------------------------------------------------------------ 读取
    def get(self, dotted_key: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, name: str) -> dict[str, Any]:
        value = self.get(name, {})
        return value if isinstance(value, dict) else {}

    def set(self, dotted_key: str, value: Any) -> None:
        """运行期覆盖配置项（仅影响内存，不写回文件）。"""
        parts = dotted_key.split(".")
        node = self.data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):  # pragma: no cover
                raise ConfigError(f"配置路径 {dotted_key} 与现有结构冲突。")
        node[parts[-1]] = value

    # ------------------------------------------------------------ 校验
    def validate(self) -> list[str]:
        """校验并夹取关键取值，返回告警列表。"""
        w = self.warnings

        self.set(
            "environment.kdf_memory_budget_ratio",
            _clamp(self.get("environment.kdf_memory_budget_ratio", 0.06), 0.01, 0.50, 0.06, w, "KDF 内存预算比例"),
        )
        self.set(
            "security.memory.overwrite_passes",
            int(_clamp(self.get("security.memory.overwrite_passes", 3), 1, 7, 3, w, "内存覆写轮数")),
        )
        self.set(
            "security.side_channel.jitter_min_ms",
            _clamp(self.get("security.side_channel.jitter_min_ms", 0.05), 0.0, 50.0, 0.05, w, "噪声延迟下界"),
        )
        self.set(
            "security.side_channel.jitter_max_ms",
            _clamp(self.get("security.side_channel.jitter_max_ms", 0.60), 0.0, 100.0, 0.60, w, "噪声延迟上界"),
        )
        # Nonce/盐/Tag 长度是安全关键参数，不允许削弱
        if int(self.get("symmetric.nonce_bytes", 12)) != 12:
            w.append("symmetric.nonce_bytes 必须为 12（AEAD 标准），已强制修正。")
            self.set("symmetric.nonce_bytes", 12)
        if int(self.get("symmetric.salt_bytes", 16)) < 16:
            w.append("symmetric.salt_bytes 不得小于 16，已强制修正为 16。")
            self.set("symmetric.salt_bytes", 16)
        if int(self.get("symmetric.tag_bytes", 16)) != 16:
            w.append("symmetric.tag_bytes 必须为 16，已强制修正。")
            self.set("symmetric.tag_bytes", 16)

        # KDF 下限：低于 OWASP 建议值会显著降低离线爆破成本
        pbkdf2_iter = int(self.get("kdf.pbkdf2.iterations", 600000))
        pbkdf2_min = int(self.get("kdf.pbkdf2.min_iterations", 210000))
        if pbkdf2_iter < pbkdf2_min:
            w.append(f"PBKDF2 迭代次数 {pbkdf2_iter} 低于安全下限 {pbkdf2_min}，已提升。")
            self.set("kdf.pbkdf2.iterations", pbkdf2_min)

        argon_mem = int(self.get("kdf.argon2id.memory_cost_kib", 262144))
        argon_min = int(self.get("kdf.argon2id.min_memory_cost_kib", 65536))
        if argon_mem < argon_min:
            w.append(f"Argon2id 内存成本 {argon_mem} KiB 低于下限 {argon_min} KiB，已提升。")
            self.set("kdf.argon2id.memory_cost_kib", argon_min)

        # Shamir 阈值关系
        shares = int(self.get("shamir.default_shares", 5))
        threshold = int(self.get("shamir.default_threshold", 3))
        shares = int(_clamp(shares, 2, 256, 5, w, "Shamir 分片数 N"))
        if threshold > shares:
            w.append(f"Shamir 阈值 M={threshold} 超过分片数 N={shares}，已下调为 N。")
            threshold = shares
        threshold = int(_clamp(threshold, 2, shares, min(3, shares), w, "Shamir 阈值 M"))
        self.set("shamir.default_shares", shares)
        self.set("shamir.default_threshold", threshold)

        # 隐写位深
        self.set(
            "steganography.default_bit_depth",
            int(_clamp(self.get("steganography.default_bit_depth", 1), 1, 4, 1, w, "隐写位深")),
        )

        # 级联层数
        self.set(
            "cascade.max_layers",
            int(_clamp(self.get("cascade.max_layers", 8), 1, 16, 8, w, "级联最大层数")),
        )

        # 密码长度
        min_len = int(_clamp(self.get("password_generator.min_length", 8), 4, 128, 8, w, "密码最小长度"))
        max_len = int(_clamp(self.get("password_generator.max_length", 512), min_len, 4096, 512, w, "密码最大长度"))
        self.set("password_generator.min_length", min_len)
        self.set("password_generator.max_length", max_len)

        # GUI 模式
        mode = str(self.get("gui.mode", "workshop")).lower()
        if mode not in ("minimal", "workshop"):
            w.append(f"gui.mode 取值 {mode!r} 非法，已回退为 workshop。")
            self.set("gui.mode", "workshop")

        return w

    # ------------------------------------------------------------ 自适应
    def apply_environment_scaling(self) -> None:
        """依据实测内存/CPU 调整性能相关参数。

        缩放策略：

        * **分块大小**：8GB→2MiB，32GB→8MiB，128GB→32MiB。
          分块越大 I/O 效率越高，但峰值内存占用也越大。
        * **Argon2id 内存成本**：取物理内存的 ``kdf_memory_budget_ratio``
          （默认 6%），并夹取到配置的上下限。32GB 环境约 1.9GiB，
          但基准测试会进一步下调到满足 ``target_ms`` 的水平。
        * **并行度**：Argon2 parallelism 取 CPU 核心数（上限 8），
          工作线程数取核心数 - 1。
        """
        prof = self.system
        ram = max(8.0, min(128.0, prof.ram_gb))

        # ---- 分块大小：随内存对数级增长 ----
        if self.get("symmetric.streaming.auto_scale_chunk", True):
            # 查表比连续函数更可控：8GB→2, 16GB→4, 32GB→8, 64GB→16, 128GB→32 (MiB)
            for threshold, size in ((96, 32), (48, 16), (24, 8), (12, 4)):
                if ram >= threshold:
                    chunk_mib = size
                    break
            else:
                chunk_mib = 2
            cap = int(self.get("symmetric.streaming.max_chunk_size_mib", 64))
            self.set("symmetric.streaming.chunk_size_mib", min(chunk_mib, cap))

        # ---- Argon2id 内存成本 ----
        ratio = float(self.get("environment.kdf_memory_budget_ratio", 0.06))
        budget_kib = int(ram * (1024**2) * ratio)  # GB → KiB
        lo = int(self.get("kdf.argon2id.min_memory_cost_kib", 65536))
        hi = int(self.get("kdf.argon2id.max_memory_cost_kib", 4194304))
        self.set("kdf.argon2id.memory_cost_kib", max(lo, min(hi, budget_kib)))

        # ---- 并行度 ----
        self.set("kdf.argon2id.parallelism", max(1, min(8, prof.cpu_count)))
        if self.get("environment.max_workers") is None:
            self.set("environment.max_workers", max(1, prof.cpu_count - 1))

    # ------------------------------------------------------------ 导出
    def summary(self) -> str:
        """生成可读的配置摘要，用于诊断报告与启动日志。"""
        lines = [
            "── CipherForge 运行配置 ──",
            f"环境        : {self.system.describe()}",
            f"配置来源    : {self.source_path or '内置默认'}",
            f"默认对称算法: {self.get('symmetric.default_algorithm')}",
            f"流式分块    : {self.get('symmetric.streaming.chunk_size_mib')} MiB",
            f"默认 KDF    : {self.get('kdf.default')}"
            f"（自适应调参：{'开' if self.get('kdf.auto_tune') else '关'}）",
            f"Argon2 内存 : {self.get('kdf.argon2id.memory_cost_kib') / 1024:.0f} MiB"
            f" / 并行度 {self.get('kdf.argon2id.parallelism')}",
            f"默认哈希    : {self.get('hashing.default_algorithm')}",
            f"抗量子签名  : {self.get('pq_signature.default_algorithm')}",
            f"级联默认层  : {' → '.join(self.get('cascade.default_layers', []))}",
            f"侧信道防护  : {'开' if self.get('security.side_channel.enabled') else '关'}",
            f"界面模式    : {self.get('gui.mode')} / 主题 {self.get('gui.theme')}",
        ]
        if self.warnings:
            lines.append(f"配置告警    : {len(self.warnings)} 条")
            lines.extend(f"  ⚠ {msg}" for msg in self.warnings)
        return "\n".join(lines)


# ======================================================================
#  加载入口
# ======================================================================
def load_config(path: str | Path | None = None, *, apply_scaling: bool = True) -> Config:
    """加载配置。

    :param path: ``config.yaml`` 路径；``None`` 时按以下顺序查找
                 当前工作目录 → 包的上一级目录 → 纯内置默认
    :param apply_scaling: 是否执行环境自适应缩放
    :raises ConfigError: 仅当 YAML 语法错误时抛出（缺字段不抛）
    """
    candidates: list[Path] = []
    if path is not None:
        candidates.append(Path(path))
    else:
        candidates.append(Path.cwd() / "config.yaml")
        candidates.append(Path(__file__).resolve().parents[2] / "config.yaml")

    user_data: dict[str, Any] = {}
    used_path: Path | None = None
    warnings: list[str] = []

    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            import yaml
        except ImportError:
            warnings.append("未安装 PyYAML，已使用内置默认配置。")
            break
        try:
            with candidate.open("r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh)
            if loaded is None:
                loaded = {}
            if not isinstance(loaded, dict):
                raise ConfigError(
                    f"配置文件 {candidate.name} 的顶层结构必须是键值映射。",
                    hint="请确认文件未被截断，且缩进正确。",
                )
            user_data = loaded
            used_path = candidate
            break
        except ConfigError:
            raise
        except Exception as exc:
            raise ConfigError(
                f"配置文件 {candidate.name} 解析失败。",
                hint="请检查 YAML 缩进与引号是否配对；也可删除该文件以使用默认配置。",
                detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    merged = _deep_merge(DEFAULT_CONFIG, user_data)

    fallback_ram = float(merged.get("environment", {}).get("reference_ram_gb", 32) or 32)
    cfg = Config(
        data=merged,
        system=SystemProfile.detect(fallback_ram),
        warnings=warnings,
        source_path=used_path,
    )

    # 顺序很重要：先按环境缩放，再校验夹取，保证最终值一定合法
    if apply_scaling:
        cfg.apply_environment_scaling()
    cfg.validate()
    return cfg
