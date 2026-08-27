"""错误体系单元测试：覆盖所有自定义异常类的构造与展示逻辑。"""

import pytest

from cipherforge.core import errors
from cipherforge.core.errors import (
    CipherForgeError,
    ConfigError,
    DependencyMissingError,
    DowngradeAttackError,
    EmptyInputError,
    FileTooLargeError,
    DecryptionFailedError,
    IntegrityError,
    InsufficientSharesError,
    NoHiddenDataError,
    SecurityViolationError,
    ShareCorruptedError,
    SignatureExpiredError,
    SignatureInvalidError,
    SignatureNotYetValidError,
    UnsupportedAlgorithmError,
    ValidationError,
    CarrierTooSmallError,
    SharingError,
    SteganographyError,
    CryptoError,
    SignatureError,
)


def test_base_to_dict_and_texts():
    e = CipherForgeError(
        "基础错误", hint="做点什么", detail="技术细节", context={"键": "值"}
    )
    d = e.to_dict()
    assert d["type"] == "CipherForgeError"
    assert d["message"] == "基础错误"
    assert d["hint"] == "做点什么"
    assert d["detail"] == "技术细节"
    assert d["context"] == {"键": "值"}
    # user_text 含消息与建议
    ut = e.user_text()
    assert "基础错误" in ut and "做点什么" in ut
    # diagnostic_text 含全部三段
    dt = e.diagnostic_text()
    assert "技术细节" in dt and "键" in dt
    # __str__ 走 user_text
    assert str(e) == ut


def test_config_error_default_hint():
    e = ConfigError("配置文件坏掉")
    assert e.hint
    assert "config.yaml" in e.hint


def test_dependency_missing_error():
    e = DependencyMissingError("后量子签名", "liboqs", install_cmd="pip install liboqs")
    assert "liboqs" in e.message
    assert "pip install liboqs" in e.hint
    assert e.context["缺失依赖"] == "liboqs"


def test_dependency_missing_error_default_cmd():
    e = DependencyMissingError("功能X", "package-x")
    assert "pip install package-x" in e.hint


def test_unsupported_algorithm_error():
    e = UnsupportedAlgorithmError("FOO", ["AES-256-GCM", "ChaCha20-Poly1305"])
    assert "AES-256-GCM" in e.hint and "FOO" in e.message


def test_empty_input_error():
    e = EmptyInputError("口令")
    assert "口令" in e.message


def test_file_too_large_error():
    e = FileTooLargeError(2 * 2**30, 1 * 2**30)
    assert "GiB" in e.message
    assert "2.00" in e.message


def test_decryption_failed_error():
    e = DecryptionFailedError(detail="x", foo="bar")
    assert e.context.get("foo") == "bar"
    assert e.default_hint


def test_integrity_and_downgrade():
    assert issubclass(DowngradeAttackError, IntegrityError)
    e = DowngradeAttackError(5, 3)
    assert "5" in e.message and "3" in e.message


def test_signature_errors():
    inv = SignatureInvalidError("ML-DSA-87", detail="bad")
    assert inv.context["算法"] == "ML-DSA-87"
    exp = SignatureExpiredError("2020-01-01", "2021-01-01", "2022-01-01")
    assert exp.render_style == "critical-red"
    assert "已过期" in exp.message
    nyv = SignatureNotYetValidError("2099-01-01", "2022-01-01")
    assert nyv.render_style == "critical-red"
    assert "尚未生效" in nyv.message


def test_sharing_errors():
    assert issubclass(SharingError, CipherForgeError)
    ins = InsufficientSharesError(2, 3)
    assert "2" in ins.message and "3" in ins.message
    assert "1 份" in ins.hint
    sc = ShareCorruptedError(7)
    assert "7" in sc.message


def test_stego_errors():
    assert issubclass(SteganographyError, CipherForgeError)
    cts = CarrierTooSmallError(1000, 200, 1)
    assert "1,000" in cts.message and "200" in cts.message
    nhd = NoHiddenDataError()
    assert nhd.default_hint


def test_security_violation_error():
    e = SecurityViolationError("检测到调试器附加。")
    assert e.default_hint


def test_crypto_signature_hierarchy():
    assert issubclass(CryptoError, CipherForgeError)
    assert issubclass(DecryptionFailedError, CryptoError)
    assert issubclass(SignatureError, CryptoError)
    assert issubclass(SignatureInvalidError, SignatureError)


def test_validation_error_hint():
    e = ValidationError("坏输入")
    assert e.default_hint


def test_all_error_classes_exported():
    names = [
        "CipherForgeError", "ConfigError", "DependencyMissingError",
        "UnsupportedAlgorithmError", "ValidationError", "EmptyInputError",
        "FileTooLargeError", "CryptoError", "DecryptionFailedError",
        "IntegrityError", "DowngradeAttackError", "SignatureError",
        "SignatureInvalidError", "SignatureExpiredError",
        "SignatureNotYetValidError", "SharingError", "InsufficientSharesError",
        "ShareCorruptedError", "SteganographyError", "CarrierTooSmallError",
        "NoHiddenDataError", "SecurityViolationError",
    ]
    for n in names:
        assert hasattr(errors, n)
