"""级联加密与后量子签名分支覆盖率补充测试。"""

import pytest
from unittest.mock import MagicMock, patch
import datetime as dt

from cipherforge.crypto import CascadeEngine, PQSignatureEngine, SignatureBundle
from cipherforge.crypto.pq_signature import (
    _ensure_backend,
    _ALGO_TO_OQS,
    _OQS_TO_ALGO,
    public_key_export,
    is_backend_available,
    _now_utc,
)
from cipherforge.core.errors import (
    ValidationError,
    DecryptionFailedError,
    DowngradeAttackError,
    UnsupportedAlgorithmError,
    DependencyMissingError,
)


# ============================================================
# Cascade 加密分支补充测试
# ============================================================

def test_cascade_layer_passwords_count_mismatch():
    """测试层密码数量不匹配时抛出异常。"""
    eng = CascadeEngine(["AES-256-GCM", "ChaCha20-Poly1305"])
    blob = eng.encrypt(b"data", password="master", layer_passwords=["p1", "p2"])
    with pytest.raises(ValidationError):
        eng.decrypt(blob, password="master", layer_passwords=["p1"])


def test_cascade_layer_passwords_provided():
    """测试提供层密码时的加解密。"""
    eng = CascadeEngine(["AES-256-GCM"])
    blob = eng.encrypt(b"data", password="master", layer_passwords=["layer0"])
    assert eng.decrypt(blob, password="master", layer_passwords=["layer0"]) == b"data"


def test_cascade_auto_tune_first_call():
    """测试首次调用时自动调优。"""
    eng = CascadeEngine()
    # 首次加密应触发 auto_tune
    blob = eng.encrypt(b"data", password="master")
    assert eng.decrypt(blob, password="master") == b"data"
    # config 应标记为已调优
    assert eng.config.get("kdf._tuned_once") is True


def test_cascade_pbkdf2_method():
    """测试使用 PBKDF2 方法。"""
    from cipherforge.core.config import load_config
    cfg = load_config()
    cfg.set("kdf.default", "pbkdf2")
    eng = CascadeEngine(["AES-256-GCM"], config=cfg)
    blob = eng.encrypt(b"data", password="master")
    assert eng.decrypt(blob, password="master") == b"data"


def test_cascade_tamper_single_layer():
    """测试篡改单层密文。"""
    eng = CascadeEngine(["AES-256-GCM"])
    blob = bytearray(eng.encrypt(b"data", password="p"))
    # 篡改密文部分
    body_len = len(blob) - 32
    blob[body_len // 2] ^= 0xFF
    with pytest.raises(DecryptionFailedError):
        eng.decrypt(bytes(blob), password="p")


def test_cascade_header_tamper():
    """测试篡改头部 MAC。"""
    eng = CascadeEngine()
    blob = bytearray(eng.encrypt(b"data", password="p"))
    # 篡改头体部分
    blob[10] ^= 0xFF
    with pytest.raises(DecryptionFailedError):
        eng.decrypt(bytes(blob), password="p")


def test_cascade_empty_layer_passwords():
    """测试空层密码列表。"""
    eng = CascadeEngine(["AES-256-GCM", "ChaCha20-Poly1305"])
    blob = eng.encrypt(b"data", password="master", layer_passwords=[])
    assert eng.decrypt(blob, password="master", layer_passwords=[]) == b"data"


# ============================================================
# PQ 签名分支补充测试
# ============================================================

class FakeDilithiumBackend:
    """伪 dilithium_py 后端用于测试。"""
    pass


class FakeOqsBackend:
    """伪 liboqs 后端用于测试。"""
    class Signature:
        def __init__(self, name):
            self.name = name
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def generate_keypair(self):
            return b"pk", b"sk"
        def sign(self, msg, sk):
            return b"sig"
        def verify(self, msg, sig, pk):
            return True
        def export_secret_key(self):
            return b"sk"


def test_pq_backend_not_available():
    """测试后端不可用时的行为。"""
    with patch('cipherforge.crypto.pq_signature._ensure_backend') as mock_ensure:
        mock_ensure.side_effect = DependencyMissingError(
            "test", "test-dep", install_cmd="pip install test"
        )
        eng = PQSignatureEngine("ML-DSA-87")
        with pytest.raises(DependencyMissingError):
            eng.generate_keypair()


def test_pq_invalid_algorithm():
    """测试不支持的算法。"""
    with pytest.raises(UnsupportedAlgorithmError):
        PQSignatureEngine("BOGUS-ALGO")


def test_pq_algo_mapping():
    """测试算法名称映射。"""
    assert "ML-DSA-87" in _ALGO_TO_OQS
    assert _ALGO_TO_OQS["ML-DSA-87"] == "ML-DSA-87"
    assert "FALCON-1024" in _ALGO_TO_OQS
    assert _ALGO_TO_OQS["FALCON-1024"] == "Falcon-1024"
    assert "SLH-DSA" in _ALGO_TO_OQS


def test_pq_sign_with_valid_days():
    """测试带有效天的签名。"""
    with patch('cipherforge.crypto.pq_signature._ensure_backend') as mock:
        mock.return_value = FakeOqsBackend()
        eng = PQSignatureEngine("ML-DSA-87")
        bundle = eng.sign(b"message", b"sk", valid_days=30, public_key=b"pk")
        assert bundle.expires_at is not None
        assert bundle.algorithm == "ML-DSA-87"


def test_pq_verify_with_public_key_override():
    """测试使用覆盖公钥验证。"""
    with patch('cipherforge.crypto.pq_signature._ensure_backend') as mock:
        mock.return_value = FakeOqsBackend()
        eng = PQSignatureEngine("ML-DSA-87")
        now = dt.datetime.now(dt.timezone.utc)
        bundle = SignatureBundle(
            algorithm="ML-DSA-87",
            public_key=b"original_pk",
            signature=b"sig",
            signed_at=now.isoformat(),
        )
        # 使用不同的公钥验证
        assert eng.verify(b"msg", bundle, public_key=b"override_pk") is True


def test_pq_keypair_returns_tuple():
    """测试密钥对生成返回元组。"""
    with patch('cipherforge.crypto.pq_signature._ensure_backend') as mock:
        mock.return_value = FakeOqsBackend()
        eng = PQSignatureEngine("ML-DSA-87")
        pk, sk = eng.generate_keypair()
        assert pk == b"pk"
        assert sk == b"sk"


def test_public_key_export():
    """测试公钥导出函数。"""
    pk = b"test-public-key"
    assert public_key_export(pk) == pk


def test_is_backend_available_false():
    """测试后端不可用时返回 False。"""
    with patch('cipherforge.crypto.pq_signature._ensure_backend') as mock:
        mock.side_effect = DependencyMissingError("test", "dep", install_cmd="pip")
        assert is_backend_available() is False


def test_now_utc_returns_datetime():
    """测试获取当前 UTC 时间。"""
    now = _now_utc()
    assert isinstance(now, dt.datetime)
    assert now.tzinfo is not None


def test_sign_empty_message_raises():
    """测试空消息签名被拒绝。"""
    with patch('cipherforge.crypto.pq_signature._ensure_backend') as mock:
        mock.return_value = FakeOqsBackend()
        eng = PQSignatureEngine("ML-DSA-87")
        with pytest.raises(ValidationError):
            eng.sign(b"", b"sk", public_key=b"pk")
