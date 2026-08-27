"""配置加载与自适应缩放测试：覆盖校验夹取、环境缩放、摘要与文件加载。"""

import textwrap

import pytest

from cipherforge.core.config import (
    Config,
    load_config,
    detect_total_ram_gb,
    detect_cpu_count,
    SystemProfile,
    _deep_merge,
    _clamp,
    DEFAULT_CONFIG,
)
from cipherforge.core.errors import ConfigError


def _fresh_config():
    return Config(
        data=dict(DEFAULT_CONFIG),
        system=SystemProfile.detect(),
    )


def test_deep_merge():
    base = {"a": 1, "nested": {"x": 1, "y": 2}}
    override = {"nested": {"y": 20, "z": 30}, "b": 2}
    merged = _deep_merge(base, override)
    assert merged == {"a": 1, "nested": {"x": 1, "y": 20, "z": 30}, "b": 2}
    # 不修改原 base
    assert base["nested"]["y"] == 2


def test_clamp_branches():
    w = []
    assert _clamp("not-a-number", 1, 10, 5, w, "X") == 5
    assert any("X" in m for m in w)
    w.clear()
    assert _clamp(2, 5, 10, 5, w, "Y") == 5  # 低于下限
    assert _clamp(20, 5, 10, 5, w, "Z") == 10  # 高于上限
    assert _clamp(7, 5, 10, 5, w, "W") == 7  # 正常


def test_config_get_set_section():
    cfg = _fresh_config()
    assert cfg.get("symmetric.default_algorithm") == "AES-256-GCM"
    assert cfg.get("missing.key", "default") == "default"
    assert isinstance(cfg.section("symmetric"), dict)
    assert cfg.section("nope") == {}
    cfg.set("symmetric.default_algorithm", "ChaCha20-Poly1305")
    assert cfg.get("symmetric.default_algorithm") == "ChaCha20-Poly1305"


def test_validate_clamps_and_forces():
    cfg = _fresh_config()
    # 强制修正安全关键参数
    cfg.set("symmetric.nonce_bytes", 8)
    cfg.set("symmetric.salt_bytes", 4)
    cfg.set("symmetric.tag_bytes", 8)
    cfg.set("kdf.pbkdf2.iterations", 100)  # 低于下限
    cfg.set("kdf.argon2id.memory_cost_kib", 100)  # 低于下限
    cfg.set("cascade.max_layers", 999)
    cfg.set("password_generator.min_length", 2)
    cfg.set("password_generator.max_length", 1)  # 小于 min
    cfg.set("gui.mode", "bogus")
    cfg.set("shamir.default_threshold", 99)  # 超过 shares
    w = cfg.validate()
    assert cfg.get("symmetric.nonce_bytes") == 12
    assert cfg.get("symmetric.salt_bytes") == 16
    assert cfg.get("symmetric.tag_bytes") == 16
    assert cfg.get("kdf.pbkdf2.iterations") >= 210000
    assert cfg.get("kdf.argon2id.memory_cost_kib") >= 65536
    assert cfg.get("cascade.max_layers") <= 16
    assert cfg.get("gui.mode") == "workshop"
    assert cfg.get("shamir.default_threshold") <= cfg.get("shamir.default_shares")
    assert len(w) > 0


def test_apply_environment_scaling():
    prof = SystemProfile(
        ram_gb=8.0, cpu_count=4, platform="win32", python_version="3.13.0"
    )
    cfg = Config(data=dict(DEFAULT_CONFIG), system=prof)
    cfg.apply_environment_scaling()
    # 8GB -> chunk 2 MiB
    assert cfg.get("symmetric.streaming.chunk_size_mib") <= 4
    # parallelism 夹到 1~8
    assert 1 <= cfg.get("kdf.argon2id.parallelism") <= 8
    # 32GB 档
    prof32 = SystemProfile(
        ram_gb=32.0, cpu_count=8, platform="win32", python_version="3.13.0"
    )
    cfg32 = Config(data=dict(DEFAULT_CONFIG), system=prof32)
    cfg32.apply_environment_scaling()
    assert cfg32.get("symmetric.streaming.chunk_size_mib") >= 8


def test_system_profile_tier_and_scale():
    for ram, expect in [
        (8, "轻量"),
        (16, "标准"),
        (32, "推荐"),
        (64, "高性能"),
        (128, "工作站"),
    ]:
        p = SystemProfile(ram_gb=float(ram), cpu_count=4, platform="win32",
                          python_version="3.13.0")
        assert expect in p.tier
    p = SystemProfile(ram_gb=32.0, cpu_count=4, platform="linux", python_version="3.13.0")
    assert 0.0 <= p.ram_scale <= 1.0
    assert "32" in p.describe()


def test_summary():
    cfg = _fresh_config()
    s = cfg.summary()
    assert "CipherForge" in s
    assert "AES-256-GCM" in s
    # 带告警时列出
    cfg.warnings.append("测试告警")
    s2 = cfg.summary()
    assert "测试告警" in s2


def test_detect_functions():
    ram = detect_total_ram_gb()
    assert isinstance(ram, float) and ram > 0
    cpu = detect_cpu_count()
    assert isinstance(cpu, int) and cpu >= 1


def test_load_config_inline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        textwrap.dedent(
            """
            environment:
              reference_ram_gb: 16
            gui:
              mode: minimal
            """
        )
    )
    cfg = load_config()
    assert cfg.get("gui.mode") == "minimal"
    assert cfg.source_path is not None


def test_load_config_bad_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("environment: [unclosed\n")
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_top_level_not_mapping(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError):
        load_config()
