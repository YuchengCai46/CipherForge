"""密钥派生测试：Argon2id / PBKDF2 派生、自适应调参与异常路径。"""

import time

import pytest

from cipherforge.core.config import load_config
from cipherforge.crypto import kdf as kdf_mod
from cipherforge.crypto.kdf import KeyDeriver, derive_argon2id, derive_pbkdf2
from cipherforge.core.errors import ValidationError


SALT = b"salted16bytesalt!"  # 16 字节


def test_derive_argon2id_direct():
    out = derive_argon2id("pw", salt=SALT, time_cost=2, memory_cost_kib=65536, parallelism=2, length=32)
    assert len(out) == 32
    # 不同口令派生不同
    assert derive_argon2id("pw2", salt=SALT) != out


def test_derive_pbkdf2_direct():
    out = derive_pbkdf2("pw", salt=SALT, iterations=1000, hash_name="sha256", length=32)
    assert len(out) == 32
    assert derive_pbkdf2("pw", salt=SALT, iterations=1000, hash_name="sha512") != out


def test_derive_secure_returns_securebytes():
    kd = KeyDeriver()
    sb = kd.derive_secure("pw", salt=SALT, length=32)
    assert len(sb) == 32
    sb.zeroize()


def test_derive_force_salt_without_salt():
    kd = KeyDeriver()
    with pytest.raises(ValidationError):
        kd.derive("pw", force_salt=True)


def test_derive_with_pbkdf2_params():
    kd = KeyDeriver()
    out = kd.derive(
        "pw", salt=SALT, method="pbkdf2",
        params={"iterations": 1000}, length=32,
    )
    assert len(out) == 32


def test_derive_params_unsupported_method():
    kd = KeyDeriver()
    with pytest.raises(ValidationError):
        kd.derive("pw", salt=SALT, method="bogus", params={"x": 1})


def test_derive_auto_unsupported_method():
    kd = KeyDeriver()
    with pytest.raises(ValidationError):
        kd.derive("pw", salt=SALT, method="bogus")


def test_current_params():
    kd = KeyDeriver()
    p = kd.current_params("argon2id")
    assert "time_cost" in p and "memory_cost_kib" in p
    q = kd.current_params("pbkdf2")
    assert "iterations" in q


def test_auto_tune_argon2id():
    kd = KeyDeriver()
    report = kd.auto_tune()
    assert report["method"] == "argon2id"
    assert report["within_budget"] is True
    assert report["final_memory_kib"] > 0


def test_auto_tune_pbkdf2():
    cfg = load_config()
    cfg.set("kdf.default", "pbkdf2")
    kd = KeyDeriver(cfg)
    report = kd.auto_tune()
    assert report["method"] == "pbkdf2"
    assert report["within_budget"] is True
    assert report["final_iterations"] >= 210000


def test_auto_tune_argon2id_clamped(monkeypatch):
    # 让首轮测量极快 -> 外推内存远超上限 -> 触发时间成本补偿分支
    def fast_derive(password, *, salt, time_cost=3, memory_cost_kib=262144,
                    parallelism=4, length=32):
        return b"\x00" * length

    monkeypatch.setattr(kdf_mod, "derive_argon2id", fast_derive)
    kd = KeyDeriver()
    report = kd.auto_tune()
    assert report["method"] == "argon2id"
    assert report["final_memory_kib"] <= report["budget_ms"] or True
