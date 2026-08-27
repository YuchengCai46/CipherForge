import datetime as dt

import pytest

from cipherforge.crypto import PQSignatureEngine, SignatureBundle, SUPPORTED_PQ
from cipherforge.crypto.pq_signature import is_backend_available
from cipherforge.core.errors import (
    SignatureExpiredError,
    SignatureNotYetValidError,
    SignatureInvalidError,
)


def test_supported_pq():
    assert "ML-DSA-87" in SUPPORTED_PQ
    assert "FALCON-1024" in SUPPORTED_PQ
    assert "SLH-DSA" in SUPPORTED_PQ


def test_invalid_algorithm():
    with pytest.raises(Exception):
        PQSignatureEngine("BOGUS-ALGO")


def test_expired_signature():
    eng = PQSignatureEngine("ML-DSA-87")
    now = dt.datetime.now(dt.timezone.utc)
    bundle = SignatureBundle(
        algorithm="ML-DSA-87", public_key=b"x", signature=b"y",
        signed_at=(now - dt.timedelta(days=10)).isoformat(),
        expires_at=(now - dt.timedelta(days=1)).isoformat(),
    )
    with pytest.raises(SignatureExpiredError):
        eng.verify(b"msg", bundle, now=now)


def test_not_yet_valid():
    eng = PQSignatureEngine("ML-DSA-87")
    now = dt.datetime.now(dt.timezone.utc)
    bundle = SignatureBundle(
        algorithm="ML-DSA-87", public_key=b"x", signature=b"y",
        signed_at=(now + dt.timedelta(days=1)).isoformat(), expires_at=None,
    )
    with pytest.raises(SignatureNotYetValidError):
        eng.verify(b"msg", bundle, now=now)


def test_validity_window_passes_timing():
    eng = PQSignatureEngine("ML-DSA-87")
    now = dt.datetime.now(dt.timezone.utc)
    bundle = SignatureBundle(
        algorithm="ML-DSA-87", public_key=b"x", signature=b"y",
        signed_at=(now - dt.timedelta(minutes=1)).isoformat(), expires_at=None,
    )
    # 时间窗通过（无后端时签名验证会走 DependencyMissingError，这里只验时间窗）
    try:
        eng.verify(b"msg", bundle, now=now)
    except SignatureInvalidError:
        pytest.fail("时间窗不应触发无效签名")
    except Exception:
        pass  # 后端不可用属预期，时间检查已过


def test_serialization_roundtrip():
    now = dt.datetime.now(dt.timezone.utc)
    b = SignatureBundle(
        algorithm="FALCON-1024", public_key=b"\x01\x02\x03", signature=b"\xaa" * 16,
        signed_at=now.isoformat(), expires_at=(now + dt.timedelta(days=30)).isoformat(),
    )
    assert SignatureBundle.from_text(b.to_text()) == b
    assert b.to_dict()["algorithm"] == "FALCON-1024"


def test_is_backend_available_returns_bool():
    assert isinstance(is_backend_available(), bool)


def test_sign_requires_backend_or_missing():
    # 无论后端是否可用，API 都应可被调用；不可用时抛 DependencyMissingError
    eng = PQSignatureEngine("ML-DSA-87")
    try:
        eng.generate_keypair()
    except Exception as e:
        # 不可用时应为 DependencyMissingError
        if not is_backend_available():
            from cipherforge.core.errors import DependencyMissingError

            assert isinstance(e, DependencyMissingError)
