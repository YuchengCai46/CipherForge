"""CipherForge 密码学层：对称加密、哈希、KDF、签名、共享、隐写、级联。

所有对外能力在此统一导出，调用方只需 ``from cipherforge.crypto import ...``。
"""

from .symmetric import (
    SymmetricCipher,
    StreamCipher,
    SUPPORTED_SYMMETRIC,
)
from .hashing import HashEngine, SUPPORTED_HASHES, generate_pepper
from .kdf import KeyDeriver
from .password_generator import PasswordGenerator
from .shamir import ShamirSecretSharing
from .steganography import LSBSteganography, lsb_capacity
from .pq_signature import PQSignatureEngine, SignatureBundle, SUPPORTED_PQ
from .cascade import CascadeEngine

__all__ = [
    "SymmetricCipher",
    "StreamCipher",
    "SUPPORTED_SYMMETRIC",
    "HashEngine",
    "SUPPORTED_HASHES",
    "generate_pepper",
    "KeyDeriver",
    "PasswordGenerator",
    "ShamirSecretSharing",
    "LSBSteganography",
    "lsb_capacity",
    "PQSignatureEngine",
    "SignatureBundle",
    "SUPPORTED_PQ",
    "CascadeEngine",
]
