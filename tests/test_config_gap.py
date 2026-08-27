"""配置模块补充覆盖：平台相关探测分支与 load_config 的边界路径。"""

import os
import subprocess
import sys

import pytest

from cipherforge.core.config import (
    detect_cpu_count,
    detect_total_ram_gb,
    load_config,
)


def test_detect_ram_darwin(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        subprocess, "check_output", lambda *a, **k: b"17179869184"
    )  # 16 GiB
    assert detect_total_ram_gb() == pytest.approx(16.0)


def test_detect_cpu_sched_getaffinity(monkeypatch):
    monkeypatch.setattr(os, "sched_getaffinity", lambda _pid: {0, 1, 2, 3}, raising=False)
    assert detect_cpu_count() == 4


def test_load_config_explicit_nonexistent_path():
    # 指向不存在的文件 -> 候选列表耗尽，回退内置默认（覆盖 path 追加与 for 循环穿透）
    cfg = load_config(path="definitely_not_there_12345.yaml")
    assert cfg is not None
    assert cfg.get("symmetric.default_algorithm")


def test_load_config_yaml_import_missing(monkeypatch):
    # 让 `import yaml` 失败 -> 走"未安装 PyYAML"降级分支
    monkeypatch.setitem(sys.modules, "yaml", None)
    cfg = load_config()  # 仍会找到 cwd 的 config.yaml，但无法解析
    assert cfg is not None
    assert any("PyYAML" in w for w in cfg.warnings)


def test_load_config_empty_yaml(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("")  # yaml.safe_load 返回 None
    cfg = load_config(path=str(empty))
    assert cfg is not None


def test_apply_scaling_auto_scale_chunk_off():
    cfg = load_config()
    cfg.set("symmetric.streaming.auto_scale_chunk", False)
    # auto_scale_chunk=False 时跳过分块查表块，直接落到 Argon2 调参
    cfg.apply_environment_scaling()
    assert cfg.get("kdf.argon2id.parallelism") >= 1
