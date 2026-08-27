"""后量子签名补充测试：用伪 oqs 后端覆盖签名/验签/密钥生成的全部路径。

本环境无 liboqs（无 CMake/C 编译器），故通过 monkeypatch ``_ensure_backend``
注入一个行为可控的伪后端，使 sign/verify/generate_keypair 的真实代码分支
得以执行与覆盖。
"""

import datetime as dt

import pytest

import cipherforge.crypto.pq_signature as pq_mod
from cipherforge.crypto import PQSignatureEngine, SignatureBundle
from cipherforge.crypto.pq_signature import (
    is_backend_available,
    public_key_export,
    _now_utc,
)
from cipherforge.core.errors import (
    SignatureInvalidError,
    ValidationError,
)


class FakeSignature:
    def __init__(self, name: str) -> None:
        self.name = name

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def generate_keypair(self):
        return b"public-key-bytes"

    def export_secret_key(self):
        return b"secret-key-bytes"

    def sign(self, message, secret_key=None):
        return b"signature-bytes"

    def verify(self, message, signature, public_key):
        return not FakeOqs.fail_verify


class FakeOqs:
    fail_verify = False

    def Signature(self, name):
        return FakeSignature(name)


@pytest.fixture
def fake_backend(monkeypatch):
    monkeypatch.setattr(pq_mod, "_ensure_backend", lambda: FakeOqs())
    yield


def test_now_utc():
    assert isinstance(_now_utc(), dt.datetime)


def test_public_key_export():
    assert public_key_export(b"xyz") == b"xyz"


def test_is_backend_available_true(fake_backend):
    assert is_backend_available() is True


def test_generate_keypair(fake_backend):
    eng = PQSignatureEngine("ML-DSA-87")
    pk, sk = eng.generate_keypair()
    assert pk == b"public-key-bytes"
    assert sk == b"secret-key-bytes"


def test_sign_empty_message(fake_backend):
    eng = PQSignatureEngine("ML-DSA-87")
    with pytest.raises(ValidationError):
        # sign(secret_key, message, ...) —— 空 message 应被拒
        eng.sign(b"sk", b"", public_key=b"pk")


def test_sign_with_valid_days(fake_backend):
    eng = PQSignatureEngine("FALCON-1024")
    bundle = eng.sign(
        b"message", b"sk", valid_days=5, public_key=b"pk",
    )
    assert bundle.algorithm == "FALCON-1024"
    assert bundle.public_key == b"pk"
    assert bundle.expires_at is not None
    assert bundle.message_digest


def test_sign_with_valid_hours_and_not_before(fake_backend):
    eng = PQSignatureEngine("ML-DSA-87")
    nb = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
    bundle = eng.sign(
        b"msg", b"sk", valid_hours=12, not_before=nb, public_key=b"pk",
    )
    assert bundle.signed_at.startswith("2030-01-01")
    assert bundle.expires_at is not None


def test_verify_success(fake_backend):
    eng = PQSignatureEngine("ML-DSA-87")
    now = dt.datetime.now(dt.timezone.utc)
    bundle = SignatureBundle(
        algorithm="ML-DSA-87", public_key=b"pk", signature=b"sig",
        signed_at=(now - dt.timedelta(minutes=1)).isoformat(), expires_at=None,
    )
    assert eng.verify(b"msg", bundle, now=now, public_key=b"pk") is True


def test_verify_missing_public_key(fake_backend):
    eng = PQSignatureEngine("ML-DSA-87")
    now = dt.datetime.now(dt.timezone.utc)
    bundle = SignatureBundle(
        algorithm="ML-DSA-87", public_key=b"", signature=b"sig",
        signed_at=now.isoformat(), expires_at=None,
    )
    with pytest.raises(SignatureInvalidError):
        eng.verify(b"msg", bundle, now=now)


def test_verify_signature_invalid(fake_backend):
    FakeOqs.fail_verify = True
    try:
        eng = PQSignatureEngine("ML-DSA-87")
        now = dt.datetime.now(dt.timezone.utc)
        bundle = SignatureBundle(
            algorithm="ML-DSA-87", public_key=b"pk", signature=b"sig",
            signed_at=now.isoformat(), expires_at=None,
        )
        with pytest.raises(SignatureInvalidError):
            eng.verify(b"msg", bundle, now=now, public_key=b"pk")
    finally:
        FakeOqs.fail_verify = False


def test_verify_malformed_signed_at(fake_backend):
    eng = PQSignatureEngine("ML-DSA-87")
    now = dt.datetime.now(dt.timezone.utc)
    bundle = SignatureBundle(
        algorithm="ML-DSA-87", public_key=b"pk", signature=b"sig",
        signed_at="not-a-date", expires_at=None,
    )
    with pytest.raises(SignatureInvalidError):
        eng.verify(b"msg", bundle, now=now, public_key=b"pk")


def test_verify_malformed_expires_at(fake_backend):
    eng = PQSignatureEngine("ML-DSA-87")
    now = dt.datetime.now(dt.timezone.utc)
    bundle = SignatureBundle(
        algorithm="ML-DSA-87", public_key=b"pk", signature=b"sig",
        signed_at=now.isoformat(), expires_at="bad-date",
    )
    with pytest.raises(SignatureInvalidError):
        eng.verify(b"msg", bundle, now=now, public_key=b"pk")
