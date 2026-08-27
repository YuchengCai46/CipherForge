"""对称加密引擎补充测试：异常路径、文件头解析、流式文件与自检测。"""

import io
import os
import struct

import pytest

from cipherforge.crypto import SymmetricCipher, StreamCipher
from cipherforge.crypto.symmetric import (
    AES256GCM,
    make_aead,
    MAGIC_BYTES,
    _selftest_roundtrip,
)
from cipherforge.core.errors import (
    DecryptionFailedError,
    ValidationError,
    UnsupportedAlgorithmError,
    CipherForgeError,
)


KEY32 = os.urandom(32)


# ----------------------------------------------------------------------
#  UnifiedAEAD 异常路径
# ----------------------------------------------------------------------
def test_set_key_wrong_length():
    with pytest.raises(ValidationError):
        AES256GCM().set_key(b"short")


def test_set_key_twice_zeroizes_old():
    c = AES256GCM()
    c.set_key(KEY32)
    # 再次 set_key 不应抛，且旧密钥被擦除
    c.set_key(KEY32)
    c.close()


def test_require_key_without_key():
    with pytest.raises(CipherForgeError):
        AES256GCM().encrypt(b"data")


def test_close_without_key():
    # 未载入密钥时 close 不应抛（覆盖 _key is None 分支）
    AES256GCM().close()


def test_decrypt_too_short():
    c = AES256GCM()
    c.set_key(KEY32)
    with pytest.raises(DecryptionFailedError):
        c.decrypt(b"x")  # 长度不足


def test_make_aead_unsupported():
    with pytest.raises(UnsupportedAlgorithmError):
        make_aead("NOT-AN-ALGO")


# ----------------------------------------------------------------------
#  文件头解析
# ----------------------------------------------------------------------
def test_build_header_pbkdf2():
    c = SymmetricCipher("AES-256-GCM")
    header = c._build_header(b"AES-256-GCM", b"\x00" * 16, "pbkdf2",
                             {"iterations": 100000}, 32)
    assert header[:4] == MAGIC_BYTES
    parsed = c._read_header(header + b"payload")
    assert parsed["method"] == "pbkdf2"
    assert parsed["params"]["iterations"] == 100000


def test_read_header_magic_mismatch():
    with pytest.raises(DecryptionFailedError):
        SymmetricCipher("AES-256-GCM")._read_header(b"XXXX" + b"\x00" * 30)


def test_read_header_version_mismatch():
    blob = MAGIC_BYTES + b"\x02" + b"\x00" * 30
    with pytest.raises(DecryptionFailedError):
        SymmetricCipher("AES-256-GCM")._read_header(blob)


def test_read_header_algo_mismatch():
    blob = bytearray()
    blob += MAGIC_BYTES
    blob += b"\x01"
    blob += struct.pack("<H", 9)
    blob += b"OTHERALGO"
    blob += b"\x00" * 16
    with pytest.raises(DecryptionFailedError):
        SymmetricCipher("AES-256-GCM")._read_header(bytes(blob))


def test_read_header_pbkdf2_full():
    blob = bytearray()
    blob += MAGIC_BYTES
    blob += b"\x01"
    blob += struct.pack("<H", len("AES-256-GCM"))
    blob += b"AES-256-GCM"
    blob += b"\x00" * 16
    blob += b"\x01"  # pbkdf2
    blob += struct.pack("<H", 32)
    blob += struct.pack("<I", 100000)
    parsed = SymmetricCipher("AES-256-GCM")._read_header(bytes(blob))
    assert parsed["method"] == "pbkdf2"
    assert parsed["params"]["iterations"] == 100000


# ----------------------------------------------------------------------
#  StreamCipher 异常与文件模式
# ----------------------------------------------------------------------
def test_stream_unsupported_algo():
    with pytest.raises(UnsupportedAlgorithmError):
        StreamCipher("BOGUS")


def test_stream_roundtrip_with_paths_and_progress(tmp_path):
    src = tmp_path / "in.bin"
    enc = tmp_path / "enc.bin"
    dec = tmp_path / "dec.bin"
    src.write_bytes(os.urandom(300_000))
    sc = StreamCipher(algorithm="AES-256-GCM")
    progress_calls = []

    def progress(cur, total):
        progress_calls.append((cur, total))

    sc.encrypt_stream(str(src), str(enc), password="p", progress=progress)
    assert enc.exists()
    assert len(progress_calls) > 0
    sc.decrypt_stream(str(enc), str(dec), password="p")
    assert dec.read_bytes() == src.read_bytes()


def test_stream_wrong_password_with_paths(tmp_path):
    src = tmp_path / "in2.bin"
    enc = tmp_path / "enc2.bin"
    src.write_bytes(b"some payload for streaming test")
    sc = StreamCipher(algorithm="ChaCha20-Poly1305")
    sc.encrypt_stream(str(src), str(enc), password="right")
    dec = tmp_path / "dec2.bin"
    with pytest.raises(DecryptionFailedError):
        # 错误口令
        sc.decrypt_stream(str(enc), str(dec), password="wrong")


def test_stream_truncated_chunk(tmp_path):
    src = tmp_path / "in3.bin"
    enc = tmp_path / "enc3.bin"
    src.write_bytes(os.urandom(50_000))
    sc = StreamCipher(algorithm="AES-256-GCM")
    sc.encrypt_stream(str(src), str(enc), password="p")
    # 截断密文，使某块声明长度大于实际数据 -> 触发完整性异常
    data = bytearray(enc.read_bytes())
    data = data[:-5]
    enc.write_bytes(bytes(data))
    dec = tmp_path / "dec3.bin"
    with pytest.raises(DecryptionFailedError):
        sc.decrypt_stream(str(enc), str(dec), password="p")


# ----------------------------------------------------------------------
#  自检测
# ----------------------------------------------------------------------
def test_selftest_roundtrip():
    assert _selftest_roundtrip() is True
