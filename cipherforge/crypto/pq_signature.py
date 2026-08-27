"""
后量子数字签名（ML-DSA-87 / FALCON-1024 / SLH-DSA）
====================================================

对**经审计**的后量子签名算法提供统一封装。支持两种后端：

* **主后端**：`liboqs` —— 由 Open Quantum Safe 项目维护、NIST 后量子标准化
  过程直接采用的参考实现（C 语言，经广泛审计）。
* **备用后端**：`dilithium_py` —— 纯 Python 实现的 ML-DSA（Dilithium），
  无需编译，适用于没有 CMake/C 编译器的环境。

支持算法
--------
* **ML-DSA-87**（Dilithium，NIST FIPS 204 第三档）—— 双后端均支持
* **Falcon-1024**（NIST 第三档，格基，短签名）—— 仅 liboqs 后端
* **SLH-DSA-SHA2-256**（SPHINCS+，NIST FIPS 205，哈希基）—— 仅 liboqs 后端

生命周期与有效期
----------------
每个签名附带 ``signed_at``（签名时间）与可选的 ``expires_at``（过期时间）。
验证时会按规则抛出：

* :class:`SignatureExpiredError`  —— 已超过有效期（GUI 以**红字**醒目呈现）
* :class:`SignatureNotYetValidError` —— 签名时间晚于当前（时钟异常/被篡改）
* :class:`SignatureInvalidError` —— 签名本身与内容/公钥不匹配

时间检查**先于**密码学验签执行，因此有效期逻辑可独立测试，
且不向攻击者泄露任何密码学中间结果。

依赖
----
* 主后端：``liboqs``（``liboqs-python`` 绑定 + 原生 ``liboqs`` 库，需 CMake 与 C 编译器）
* 备用后端：``dilithium-py``（纯 Python，无编译依赖）

缺失时所有方法抛出 :class:`DependencyMissingError`，并给出安装指引；
其余模块不受影响。
"""

from __future__ import annotations

import base64
import datetime as _dt
from dataclasses import dataclass, field
from typing import Any

from ..core.errors import (
    DependencyMissingError,
    SignatureExpiredError,
    SignatureInvalidError,
    SignatureNotYetValidError,
    ValidationError,
)
from ..core.rng import random_bytes

__all__ = ["PQSignatureEngine", "SignatureBundle", "SUPPORTED_PQ"]

# 我们的算法名 -> liboqs 机制名
_ALGO_TO_OQS: dict[str, str] = {
    "ML-DSA-87": "ML-DSA-87",
    "FALCON-1024": "Falcon-1024",
    "SLH-DSA": "SLH-DSA-SHA2-256",
}
_OQS_TO_ALGO = {v: k for k, v in _ALGO_TO_OQS.items()}

SUPPORTED_PQ = tuple(_ALGO_TO_OQS.keys())

# 允许的系统时钟偏移（用于 not-yet-valid 判定）
_MAX_CLOCK_SKEW = _dt.timedelta(minutes=5)


def _now_utc() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


# ========================= 后端管理 =========================

_OQS_MODULE = None
_OQS_OK: bool | None = None
_DILITHIUM_OK: bool | None = None


def _ensure_backend():
    """确保后端可用，优先使用 liboqs，回退到 dilithium_py。"""
    global _OQS_MODULE, _OQS_OK, _DILITHIUM_OK

    # 1. 优先尝试 liboqs
    if _OQS_OK is False:
        pass  # liboqs 已确认为不可用，跳过
    elif _OQS_MODULE is not None:
        return _OQS_MODULE
    else:
        _OQS_OK = False
        home = __import__("pathlib").Path.home()
        oqs_bin = home / "_oqs" / "bin" / "oqs.dll"
        if oqs_bin.exists():
            try:
                import oqs  # type: ignore
                _OQS_MODULE = oqs
                _OQS_OK = True
                return oqs
            except Exception:
                pass

    # 2. 回退到 dilithium_py（仅支持 ML-DSA）
    if _DILITHIUM_OK is not None:
        # 已缓存参数字典（可能是 dict 或 False）
        if _DILITHIUM_OK is not False:
            return _DILITHIUM_OK  # type: ignore
        # _DILITHIUM_OK is False → 已探测过不可用，直接抛异常
        raise DependencyMissingError(
            "后量子签名", "liboqs + liboqs-python 或 dilithium-py",
            install_cmd="pip install dilithium-py",
        )
    try:
        from dilithium_py.ml_dsa.ml_dsa import ML_DSA
        from dilithium_py.ml_dsa.default_parameters import DEFAULT_PARAMETERS
        _DILITHIUM_OK = {
            "ML-DSA-87": DEFAULT_PARAMETERS["ML_DSA_87"],
            "ML-DSA-65": DEFAULT_PARAMETERS["ML_DSA_65"],
            "ML-DSA-44": DEFAULT_PARAMETERS["ML_DSA_44"],
        }
        return _DILITHIUM_OK
    except ImportError:
        _DILITHIUM_OK = False
        raise DependencyMissingError(
            "后量子签名", "liboqs + liboqs-python 或 dilithium-py",
            install_cmd="pip install dilithium-py",
        )


# ========================= 内部辅助 =========================

def _get_dilithium_engine(algorithm: str):
    """获取 dilithium_py 的 ML_DSA 引擎实例。"""
    params = _ensure_backend()
    from dilithium_py.ml_dsa.ml_dsa import ML_DSA
    return ML_DSA(params[algorithm])


def public_key_export(pk: bytes) -> bytes:
    """导出公钥（占位封装，便于未来扩展格式）。"""
    return pk


def is_backend_available() -> bool:
    """返回后端是否可用（liboqs 或 dilithium_py）。"""
    try:
        _ensure_backend()
        return True
    except DependencyMissingError:
        return False


# ========================= SignatureBundle =========================

@dataclass
class SignatureBundle:
    """一个自包含的后量子签名包。"""

    algorithm: str
    public_key: bytes
    signature: bytes
    signed_at: str                       # ISO-8601 UTC
    expires_at: str | None = None       # ISO-8601 UTC，None 表示永不过期
    message_digest: str = ""            # 仅用于展示/审计的 SHA-256 摘要（十六进制）

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
            "signature": base64.b64encode(self.signature).decode("ascii"),
            "signed_at": self.signed_at,
            "expires_at": self.expires_at,
            "message_digest": self.message_digest,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SignatureBundle":
        return cls(
            algorithm=d["algorithm"],
            public_key=base64.b64decode(d["public_key"]),
            signature=base64.b64decode(d["signature"]),
            signed_at=d["signed_at"],
            expires_at=d.get("expires_at"),
            message_digest=d.get("message_digest", ""),
        )

    @classmethod
    def from_text(cls, text: str) -> "SignatureBundle":
        """从 Base64(JSON) 文本还原。"""
        import json
        return cls.from_dict(json.loads(base64.b64decode(text.strip()).decode("utf-8")))

    def to_text(self) -> str:
        import json
        return base64.b64encode(
            json.dumps(self.to_dict(), ensure_ascii=False).encode("utf-8")
        ).decode("ascii")


# ========================= PQSignatureEngine =========================

class PQSignatureEngine:
    """后量子签名引擎门面。"""

    def __init__(self, algorithm: str = "ML-DSA-87") -> None:
        if algorithm not in _ALGO_TO_OQS:
            from ..core.errors import UnsupportedAlgorithmError
            raise UnsupportedAlgorithmError(algorithm, SUPPORTED_PQ)
        self.algorithm = algorithm

    # ------------------------------------------------------------ 密钥
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """返回 ``(public_key, secret_key)``。"""
        backend = _ensure_backend()
        import hashlib

        # 判断使用哪个后端
        if isinstance(backend, dict):
            # dilithium_py 后端
            engine = _get_dilithium_engine(self.algorithm)
            pk, sk = engine.keygen()
        else:
            # liboqs 后端
            oqs_name = _ALGO_TO_OQS[self.algorithm]
            with backend.Signature(oqs_name) as sig:
                pk = sig.generate_keypair()
                sk = sig.export_secret_key()
        return public_key_export(pk), sk

    # ------------------------------------------------------------ 签名
    def sign(
        self,
        secret_key: bytes,
        message: bytes,
        *,
        valid_days: int | None = None,
        valid_hours: int | None = None,
        not_before: _dt.datetime | None = None,
        public_key: bytes | None = None,
    ) -> SignatureBundle:
        """对 ``message`` 签名，附带有效期。"""
        if not message:
            raise ValidationError("待签名消息不能为空。")
        backend = _ensure_backend()
        signed_at = not_before or _now_utc()
        expires_at: _dt.datetime | None = None
        if valid_days is not None and valid_days > 0:
            expires_at = signed_at + _dt.timedelta(days=valid_days)
        elif valid_hours is not None and valid_hours > 0:
            expires_at = signed_at + _dt.timedelta(hours=valid_hours)

        if isinstance(backend, dict):
            # dilithium_py 后端
            engine = _get_dilithium_engine(self.algorithm)
            signature = engine.sign(secret_key, message)
        else:
            # liboqs 后端
            oqs_name = _ALGO_TO_OQS[self.algorithm]
            with backend.Signature(oqs_name) as sig:
                signature = sig.sign(message, secret_key)

        import hashlib
        return SignatureBundle(
            algorithm=self.algorithm,
            public_key=public_key or b"",
            signature=signature,
            signed_at=signed_at.isoformat(),
            expires_at=expires_at.isoformat() if expires_at else None,
            message_digest=hashlib.sha256(message).hexdigest(),
        )

    # ------------------------------------------------------------ 验证
    def verify(
        self,
        message: bytes,
        bundle: SignatureBundle,
        *,
        now: _dt.datetime | None = None,
        public_key: bytes | None = None,
    ) -> bool:
        """验证签名。顺序：先有效期 → 再密码学验签。"""
        now = now or _now_utc()
        self._check_validity(bundle, now)

        pk = public_key or bundle.public_key
        if not pk:
            raise SignatureInvalidError(
                self.algorithm, detail="缺少公钥，无法验证签名。"
            )
        backend = _ensure_backend()
        if isinstance(backend, dict):
            # dilithium_py 后端
            engine = _get_dilithium_engine(bundle.algorithm)
            ok = engine.verify(pk, message, bundle.signature)
        else:
            # liboqs 后端
            oqs_name = _ALGO_TO_OQS.get(bundle.algorithm, bundle.algorithm)
            with backend.Signature(oqs_name) as sig:
                ok = sig.verify(message, bundle.signature, pk)
        if not ok:
            raise SignatureInvalidError(self.algorithm)
        return True

    # ------------------------------------------------------------ 有效期
    @staticmethod
    def _check_validity(bundle: SignatureBundle, now: _dt.datetime) -> None:
        try:
            signed = _dt.datetime.fromisoformat(bundle.signed_at)
            if signed.tzinfo is None:
                signed = signed.replace(tzinfo=_dt.timezone.utc)
        except Exception as exc:
            raise SignatureInvalidError(
                bundle.algorithm, detail="签名时间格式无法解析。"
            ) from exc

        if signed - now > _MAX_CLOCK_SKEW:
            raise SignatureNotYetValidError(signed.isoformat(), now.isoformat())

        if bundle.expires_at:
            try:
                exp = _dt.datetime.fromisoformat(bundle.expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=_dt.timezone.utc)
            except Exception as exc:
                raise SignatureInvalidError(
                    bundle.algorithm, detail="过期时间格式无法解析。"
                ) from exc
            if now > exp:
                raise SignatureExpiredError(
                    signed.isoformat(), exp.isoformat(), now.isoformat()
                )
