"""
CipherForge — 桌面级密码学工具包
=================================

一个面向专业用户的本地密码学工作台，覆盖对称加密、抗量子签名、
高阶哈希、密钥派生、秘密共享、图片隐写、级联加密与高熵密码生成。

设计准则
--------
1. **默认安全**：所有密钥、盐、Nonce、Pepper 均来自操作系统 CSPRNG。
2. **恒定时间**：一切涉及秘密的比较走 ``hmac.compare_digest``，
   不以秘密作为分支条件。
3. **内存卫生**：秘密材料存放于可变缓冲区，使用完毕立即覆写清零。
4. **失败即安全**：任何异常路径都会擦除中间产物与临时文件。
5. **优雅降级**：可选依赖缺失时给出明确中文提示，不影响其余模块。

快速开始
--------
>>> from cipherforge import SymmetricCipher
>>> cipher = SymmetricCipher("AES-256-GCM")
>>> blob = cipher.encrypt(b"hello", password="correct horse battery staple")
>>> cipher.decrypt(blob, password="correct horse battery staple")
b'hello'
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "CipherForge Project"
__license__ = "MIT"

# 供 `from cipherforge import X` 直接取用的公开门面。
# 采用惰性导入，避免可选依赖（如 liboqs、Pillow）在导入包时就报错。
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "SymmetricCipher": ("cipherforge.crypto.symmetric", "SymmetricCipher"),
    "StreamCipher": ("cipherforge.crypto.symmetric", "StreamCipher"),
    "HashEngine": ("cipherforge.crypto.hashing", "HashEngine"),
    "KeyDeriver": ("cipherforge.crypto.kdf", "KeyDeriver"),
    "ShamirSecretSharing": ("cipherforge.crypto.shamir", "ShamirSecretSharing"),
    "PasswordGenerator": ("cipherforge.crypto.password", "PasswordGenerator"),
    "LSBSteganography": ("cipherforge.crypto.stego", "LSBSteganography"),
    "CascadeEngine": ("cipherforge.crypto.cascade", "CascadeEngine"),
    "PQSignatureEngine": ("cipherforge.crypto.pq_signature", "PQSignatureEngine"),
    "SecureBytes": ("cipherforge.core.memory", "SecureBytes"),
    "Config": ("cipherforge.core.config", "Config"),
    "load_config": ("cipherforge.core.config", "load_config"),
}

__all__ = ["__version__", *sorted(_LAZY_EXPORTS)]


def __getattr__(name: str):
    """PEP 562 惰性属性：按需导入子模块，缩短冷启动时间。"""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"模块 cipherforge 没有属性 {name!r}")
    import importlib

    module = importlib.import_module(target[0])
    value = getattr(module, target[1])
    globals()[name] = value  # 缓存，后续访问零开销
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
