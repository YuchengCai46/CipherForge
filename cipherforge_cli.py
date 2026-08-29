#!/usr/bin/env python3
"""
CipherForge 交互式命令行界面
=============================

支持命令：
  encrypt  <算法> <密码> <明文>     - 加密
  decrypt  <算法> <密码> <密文B64>  - 解密
  hash     <算法> <文本>            - 哈希
  verify   <算法> <文本> <哈希>     - 验证哈希
  gen      [长度]                   - 生成密码
  passphrase [词数]                 - 生成密语密码
  shamir-split <阈值> <总数> <秘密> - Shamir分片
  shamir-combine <分片1> <分片2>    - Shamir合并
  cascade  <算法列表> <密码> <明文> - 级联加密
  pq-keygen <算法>                  - 抗量子密钥生成
  pq-sign  <算法> <私钥文件> <文本> - 抗量子签名
  pq-verify <算法> <公钥文件> <文本> <签名文件> - 抗量子验证
  help                                - 显示帮助
  exit / quit / q                   - 退出

示例：
  cipherforge> encrypt AES-256-GCM mypass hello
  cipherforge> hash SHA-256 hello
  cipherforge> gen 16
  cipherforge> help
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

# 添加项目路径
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cipherforge.crypto import (
    SymmetricCipher,
    HashEngine,
    PasswordGenerator,
    ShamirSecretSharing,
    CascadeEngine,
    PQSignatureEngine,
    SUPPORTED_SYMMETRIC,
    SUPPORTED_HASHES,
    SUPPORTED_PQ,
)

# 版本
__version__ = "1.0.0"

# 提示符
PROMPT = "\033[36mcipherforge\033[0m> "


def cmd_encrypt(args: list[str]) -> None:
    """加密命令"""
    if len(args) < 3:
        print("用法: encrypt <算法> <密码> <明文>")
        print(f"可用算法: {', '.join(SUPPORTED_SYMMETRIC)}")
        return
    algo, password, plaintext = args[0], args[1], " ".join(args[2:])
    try:
        cipher = SymmetricCipher(algo)
        ciphertext = cipher.encrypt(plaintext.encode(), password=password)
        result = {
            "algorithm": algo,
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "length": len(ciphertext),
        }
        print(f"\033[32m✓ 加密成功\033[0m")
        print(f"  算法: {algo}")
        print(f"  密文长度: {len(ciphertext)} 字节")
        print(f"  密文(B64): {result['ciphertext_b64'][:64]}...")
        # 存入剪贴板（可选）
        print(f"  完整密文: {result['ciphertext_b64']}")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_decrypt(args: list[str]) -> None:
    """解密命令"""
    if len(args) < 3:
        print("用法: decrypt <算法> <密码> <密文B64>")
        print(f"可用算法: {', '.join(SUPPORTED_SYMMETRIC)}")
        return
    algo, password = args[0], args[1]
    ciphertext_b64 = " ".join(args[2:])
    try:
        cipher = SymmetricCipher(algo)
        plaintext = cipher.decrypt(
            base64.b64decode(ciphertext_b64), password=password
        )
        print(f"\033[32m✓ 解密成功\033[0m")
        print(f"  明文: {plaintext.decode()}")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_hash(args: list[str]) -> None:
    """哈希命令"""
    if len(args) < 2:
        print("用法: hash <算法> <文本>")
        print(f"可用算法: {', '.join(SUPPORTED_HASHES)}")
        return
    algo = args[0]
    text = " ".join(args[1:])
    try:
        he = HashEngine()
        digest = he.hash(text.encode(), algo)
        print(f"\033[32m✓ 哈希完成\033[0m")
        print(f"  算法: {algo}")
        print(f"  输入: {text}")
        print(f"  哈希: {digest}")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_verify(args: list[str]) -> None:
    """验证哈希命令"""
    if len(args) < 3:
        print("用法: verify <算法> <文本> <哈希>")
        return
    algo, text, expected = args[0], " ".join(args[1:-1]), args[-1]
    try:
        he = HashEngine()
        actual = he.hash(text.encode(), algo)
        if actual == expected:
            print(f"\033[32m✓ 验证通过\033[0m")
        else:
            print(f"\033[31m✗ 验证失败\033[0m")
            print(f"  期望: {expected}")
            print(f"  实际: {actual}")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_gen(args: list[str]) -> None:
    """生成密码命令"""
    length = int(args[0]) if args else 20
    try:
        pg = PasswordGenerator()
        pwd = pg.generate(length, exclude_ambiguous=False)
        bits = pg.entropy_bits(pwd, len(pg.default_charset()))
        print(f"\033[32m✓ 密码已生成\033[0m")
        print(f"  长度: {length}")
        print(f"  密码: {pwd}")
        print(f"  熵: {bits:.1f} bit")
        if bits >= 80:
            print(f"  强度: \033[32m强\033[0m")
        elif bits >= 60:
            print(f"  强度: \033[33m中等\033[0m")
        else:
            print(f"  强度: \033[31m弱\033[0m")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_passphrase(args: list[str]) -> None:
    """生成密语密码命令"""
    words = int(args[0]) if args else 4
    try:
        pg = PasswordGenerator()
        phrase = pg.generate_passphrase(words)
        bits = pg.passphrase_entropy(words, len(pg._WORDLIST))
        print(f"\033[32m✓ 密语密码已生成\033[0m")
        print(f"  词数: {words}")
        print(f"  密语: {phrase}")
        print(f"  熵: {bits:.1f} bit")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_shamir_split(args: list[str]) -> None:
    """Shamir分片命令"""
    if len(args) < 4:
        print("用法: shamir-split <阈值> <总数> <秘密>")
        return
    try:
        threshold = int(args[0])
        total = int(args[1])
        secret = " ".join(args[2:])
        sss = ShamirSecretSharing(threshold, total)
        shares = sss.split_to_text(secret.encode())
        print(f"\033[32m✓ Shamir 分片完成\033[0m")
        print(f"  阈值/总数: {threshold}/{total}")
        print(f"  分片数: {len(shares)}")
        for i, share in enumerate(shares):
            print(f"  分片{i+1}: {share[:40]}...")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_shamir_combine(args: list[str]) -> None:
    """Shamir合并命令"""
    if len(args) < 2:
        print("用法: shamir-combine <分片1> <分片2> ...")
        return
    try:
        sss = ShamirSecretSharing(2, 2)
        secret = sss.combine_from_text(args)
        print(f"\033[32m✓ Shamir 合并成功\033[0m")
        print(f"  原始秘密: {secret.decode()}")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_cascade(args: list[str]) -> None:
    """级联加密命令"""
    if len(args) < 3:
        print("用法: cascade <算法1,算法2,...> <密码> <明文>")
        print(f"可用算法: {', '.join(SUPPORTED_SYMMETRIC)}")
        return
    algo_list = args[0].split(",")
    password = args[1]
    plaintext = " ".join(args[2:])
    try:
        ce = CascadeEngine(algorithms=algo_list)
        result = ce.encrypt(plaintext.encode(), password=password)
        print(f"\033[32m✓ 级联加密完成\033[0m")
        print(f"  算法层: {', '.join(algo_list)}")
        print(f"  密文长度: {len(result)} 字节")
        print(f"  密文(B64): {base64.b64encode(result).decode()[:64]}...")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_pq_keygen(args: list[str]) -> None:
    """抗量子密钥生成命令"""
    if not args:
        print("用法: pq-keygen <算法>")
        print(f"可用算法: {', '.join(SUPPORTED_PQ)}")
        return
    algo = args[0]
    try:
        pq = PQSignatureEngine()
        pk, sk = pq.keygen(algo)
        # 保存密钥到文件
        out_dir = Path("pq_keys")
        out_dir.mkdir(exist_ok=True)
        pk_file = out_dir / f"{algo.replace('-', '_')}.pk"
        sk_file = out_dir / f"{algo.replace('-', '_')}.sk"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)
        print(f"\033[32m✓ 密钥对已生成\033[0m")
        print(f"  算法: {algo}")
        print(f"  公钥文件: {pk_file}")
        print(f"  私钥文件: {sk_file}")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_pq_sign(args: list[str]) -> None:
    """抗量子签名命令"""
    if len(args) < 3:
        print("用法: pq-sign <算法> <私钥文件> <文本>")
        return
    algo, sk_file, text = args[0], args[1], " ".join(args[2:])
    try:
        sk = Path(sk_file).read_bytes()
        pq = PQSignatureEngine()
        sig = pq.sign(sk, text.encode(), algo)
        print(f"\033[32m✓ 签名完成\033[0m")
        print(f"  算法: {algo}")
        print(f"  签名(B64): {base64.b64encode(sig).decode()}")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_pq_verify(args: list[str]) -> None:
    """抗量子验证命令"""
    if len(args) < 4:
        print("用法: pq-verify <算法> <公钥文件> <文本> <签名文件>")
        return
    algo = args[0]
    pk_file = args[1]
    text = " ".join(args[2:-1])
    sig_file = args[-1]
    try:
        pk = Path(pk_file).read_bytes()
        sig = Path(sig_file).read_bytes()
        pq = PQSignatureEngine()
        valid = pq.verify(pk, text.encode(), sig, algo)
        if valid:
            print(f"\033[32m✓ 签名验证通过\033[0m")
        else:
            print(f"\033[31m✗ 签名验证失败\033[0m")
    except Exception as e:
        print(f"\033[31m✗ 错误: {e}\033[0m")


def cmd_help(args: list[str] = None) -> None:
    """显示帮助"""
    print("\033[1mCipherForge 交互式 CLI v{}\033[0m".format(__version__))
    print("\n\033[36m可用命令:\033[0m")
    print("  encrypt  <算法> <密码> <明文>     - 加密")
    print("  decrypt  <算法> <密码> <密文B64>  - 解密")
    print("  hash     <算法> <文本>            - 哈希")
    print("  verify   <算法> <文本> <哈希>     - 验证哈希")
    print("  gen      [长度]                   - 生成密码")
    print("  passphrase [词数]                 - 生成密语密码")
    print("  shamir-split <阈值> <总数> <秘密> - Shamir分片")
    print("  shamir-combine <分片1> <分片2>    - Shamir合并")
    print("  cascade  <算法列表> <密码> <明文> - 级联加密")
    print("  pq-keygen <算法>                  - 抗量子密钥生成")
    print("  pq-sign  <算法> <私钥文件> <文本> - 抗量子签名")
    print("  pq-verify <算法> <公钥文件> <文本> <签名文件> - 抗量子验证")
    print("  help                                - 显示帮助")
    print("  exit / quit / q                   - 退出")
    print("\n\033[36m示例:\033[0m")
    print("  cipherforge> encrypt AES-256-GCM mypass hello")
    print("  cipherforge> hash SHA-256 hello")
    print("  cipherforge> gen 20")
    print("  cipherforge> help")
    print()


def cmd_exit(args: list[str] = None) -> None:
    """退出命令"""
    print("\033[33m再见!\033[0m")
    sys.exit(0)


# 命令映射
COMMANDS = {
    "encrypt": cmd_encrypt,
    "decrypt": cmd_decrypt,
    "hash": cmd_hash,
    "verify": cmd_verify,
    "gen": cmd_gen,
    "generate": cmd_gen,
    "passphrase": cmd_passphrase,
    "shamir-split": cmd_shamir_split,
    "shamir-combine": cmd_shamir_combine,
    "cascade": cmd_cascade,
    "pq-keygen": cmd_pq_keygen,
    "pq-sign": cmd_pq_sign,
    "pq-verify": cmd_pq_verify,
    "help": cmd_help,
    "?": cmd_help,
    "exit": cmd_exit,
    "quit": cmd_exit,
    "q": cmd_exit,
}


def process_command(line: str) -> bool:
    """处理单行命令，返回 False 表示退出"""
    line = line.strip()
    if not line:
        return True
    if line.startswith("#"):
        return True

    parts = line.split(maxsplit=1)
    cmd = parts[0].lower()
    args = parts[1].split() if len(parts) > 1 else []

    if cmd in COMMANDS:
        try:
            COMMANDS[cmd](args)
        except Exception as e:
            print(f"\033[31m✗ 内部错误: {e}\033[0m")
    else:
        print(f"\033[31m未知命令: {cmd}\033[0m")
        print("输入 'help' 查看可用命令")
    return True


def main() -> None:
    """主函数"""
    print("\033[36m" + "=" * 50)
    print("  CipherForge 交互式 CLI v{}".format(__version__))
    print("  密码学工具箱 | 输入 'help' 查看帮助")
    print("=" * 50 + "\033[0m")
    print()

    # 检查是否通过 bat 文件运行（非交互模式）
    if not sys.stdin.isatty():
        # 非交互模式：从 stdin 读取并执行命令
        for line in sys.stdin:
            if not process_command(line):
                break
        return

    # 交互模式
    while process_command(input(PROMPT)):
        pass


if __name__ == "__main__":
    main()
