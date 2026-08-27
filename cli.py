#!/usr/bin/env python3
"""
CipherForge 命令行接口（CLI）
=============================

覆盖全部能力的非交互式入口，便于脚本化与自动化。

示例
----
  python cli.py encrypt --algo AES-256-GCM --password xxx --in f.txt --out f.enc
  python cli.py decrypt --algo AES-256-GCM --password xxx --in f.enc --out f.txt
  python cli.py hash --algo SHA-256 --in f.txt
  python cli.py passgen --length 24
  python cli.py shamir-split --threshold 3 --total 5 --in secret.bin --out-dir shares/
  python cli.py shamir-combine --shares shares/*.txt --out secret.bin
  python cli.py stego-hide --carrier pic.png --out hidden.png --password xxx --in data.bin
  python cli.py stego-reveal --in hidden.png --password xxx --out data.bin
  python cli.py pq-keygen --algo ML-DSA-87 --out alice
  python cli.py pq-sign --algo ML-DSA-87 --secret-key alice.sk --in doc.txt --out doc.sig --days 30
  python cli.py pq-verify --algo ML-DSA-87 --public-key alice.pk --in doc.txt --bundle doc.sig
  python cli.py cascade-encrypt --layers AES-256-GCM,ChaCha20-Poly1305 --password xxx --in f.txt --out f.csc
"""

from __future__ import annotations

import argparse
import base64
import glob
import os
import sys

from cipherforge.crypto import (
    SymmetricCipher,
    StreamCipher,
    HashEngine,
    generate_pepper,
    PasswordGenerator,
    ShamirSecretSharing,
    LSBSteganography,
    PQSignatureEngine,
    SignatureBundle,
    CascadeEngine,
    SUPPORTED_SYMMETRIC,
    SUPPORTED_HASHES,
    SUPPORTED_PQ,
)


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


# ----------------------------------------------------------------------
#  子命令实现
# ----------------------------------------------------------------------
def _cmd_symmetric(args, encrypt: bool) -> None:
    cipher = SymmetricCipher(args.algo)
    if encrypt:
        data = _read(args.infile)
        out = cipher.encrypt(data, password=args.password, aad=args.aad.encode() if args.aad else b"")
        _write(args.outfile, out)
        print(f"已加密 -> {args.outfile} ({len(out)} 字节)")
    else:
        blob = _read(args.infile)
        out = cipher.decrypt(blob, password=args.password, aad=args.aad.encode() if args.aad else b"")
        _write(args.outfile, out)
        print(f"已解密 -> {args.outfile} ({len(out)} 字节)")


def _cmd_stream(args, encrypt: bool) -> None:
    sc = StreamCipher(algorithm=args.algo)
    if encrypt:
        with open(args.infile, "rb") as src, open(args.outfile, "wb") as dst:
            sc.encrypt_stream(src, dst, password=args.password)
        print(f"已流式加密 -> {args.outfile}")
    else:
        with open(args.infile, "rb") as src, open(args.outfile, "wb") as dst:
            sc.decrypt_stream(src, dst, password=args.password)
        print(f"已流式解密 -> {args.outfile}")


def _cmd_hash(args) -> None:
    he = HashEngine()
    if args.infile:
        data = _read(args.infile)
    else:
        data = args.text.encode("utf-8")
    digest = he.hash(data, args.algo, shake_len=args.shake_len)
    print(digest)
    if args.verify:
        ok = he.verify(data, args.verify, args.algo, shake_len=args.shake_len)
        print("校验:", "通过 ✓" if ok else "失败 ✗")
        if not ok:
            sys.exit(1)


def _cmd_passgen(args) -> None:
    pg = PasswordGenerator()
    if args.passphrase:
        pw = pg.generate_passphrase(args.words, separator=args.separator)
        print(pw)
    else:
        pw = pg.generate(args.length, exclude_ambiguous=args.exclude_ambiguous)
        bits = pg.entropy_bits(pw, len(pg.default_charset(exclude_ambiguous=args.exclude_ambiguous)))
        print(pw)
        print(f"熵 ≈ {bits:.1f} bit  强度: {pg.strength_label(bits)}")


def _cmd_shamir_split(args) -> None:
    s = ShamirSecretSharing(args.threshold, args.total)
    secret = _read(args.infile)
    texts = s.split_to_text(secret)
    os.makedirs(args.out_dir, exist_ok=True)
    for i, t in enumerate(texts):
        with open(os.path.join(args.out_dir, f"share_{i + 1}.txt"), "w", encoding="utf-8") as fh:
            fh.write(t)
    print(f"已生成 {len(texts)} 份分片 -> {args.out_dir}/share_*.txt")


def _cmd_shamir_combine(args) -> None:
    paths = []
    for pat in args.shares:
        paths.extend(glob.glob(pat) if any(c in pat for c in "*?[") else [pat])
    texts = [open(p, "r", encoding="utf-8").read() for p in sorted(set(paths))]
    s = ShamirSecretSharing(args.threshold, len(texts))
    secret = s.combine(texts)
    _write(args.outfile, secret)
    print(f"已恢复秘密 -> {args.outfile} ({len(secret)} 字节)")


def _cmd_stego_hide(args) -> None:
    lsb = LSBSteganography(bit_depth=args.bit_depth)
    data = _read(args.infile)
    n = lsb.hide(data, args.carrier, args.outfile, password=args.password)
    print(f"已隐藏 {n} 字节载荷 -> {args.outfile}")


def _cmd_stego_reveal(args) -> None:
    lsb = LSBSteganography(bit_depth=args.bit_depth)
    data = lsb.reveal(args.infile, password=args.password, bit_depth=args.bit_depth)
    _write(args.outfile, data)
    print(f"已提取 {len(data)} 字节载荷 -> {args.outfile}")


def _cmd_pq_keygen(args) -> None:
    eng = PQSignatureEngine(args.algo)
    pk, sk = eng.generate_keypair()
    _write(f"{args.out}.pk", pk)
    _write(f"{args.out}.sk", sk)
    print(f"公钥 -> {args.out}.pk  私钥 -> {args.out}.sk")


def _cmd_pq_sign(args) -> None:
    eng = PQSignatureEngine(args.algo)
    sk = _read(args.secret_key)
    pk = _read(args.public_key) if args.public_key else None
    msg = _read(args.infile)
    bundle = eng.sign(sk, msg, valid_days=args.days, valid_hours=args.hours, public_key=pk)
    _write(args.outfile, bundle.to_text().encode("utf-8"))
    print(f"签名 -> {args.outfile}（有效期至 {bundle.expires_at or '永久'}）")


def _cmd_pq_verify(args) -> None:
    eng = PQSignatureEngine(args.algo)
    pk = _read(args.public_key)
    msg = _read(args.infile)
    bundle = SignatureBundle.from_text(_read(args.bundle).decode("utf-8"))
    eng.verify(msg, bundle, public_key=pk)
    print("签名验证通过 ✓")


def _cmd_cascade(args, encrypt: bool) -> None:
    layers = [a.strip() for a in args.layers.split(",") if a.strip()]
    eng = CascadeEngine(layers)
    if encrypt:
        data = _read(args.infile)
        out = eng.encrypt(data, password=args.password)
        _write(args.outfile, out)
        print(f"已级联加密（{len(layers)} 层）-> {args.outfile}")
    else:
        blob = _read(args.infile)
        out = eng.decrypt(blob, password=args.password)
        _write(args.outfile, out)
        print(f"已级联解密 -> {args.outfile}")


# ----------------------------------------------------------------------
#  参数解析
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cipherforge", description="CipherForge 密码学工具集")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_io(sp, stream=False):
        sp.add_argument("--infile", "--in", "-i", dest="infile", required=True)
        sp.add_argument("--outfile", "--out", "-o", dest="outfile", required=True)

    sp = sub.add_parser("encrypt"); add_io(sp)
    sp.add_argument("--algo", required=True, choices=SUPPORTED_SYMMETRIC)
    sp.add_argument("--password", required=True)
    sp.add_argument("--aad", default="")
    sp.set_defaults(func=lambda a: _cmd_symmetric(a, True))

    sp = sub.add_parser("decrypt"); add_io(sp)
    sp.add_argument("--algo", required=True, choices=SUPPORTED_SYMMETRIC)
    sp.add_argument("--password", required=True)
    sp.add_argument("--aad", default="")
    sp.set_defaults(func=lambda a: _cmd_symmetric(a, False))

    sp = sub.add_parser("stream-encrypt"); add_io(sp)
    sp.add_argument("--algo", required=True, choices=SUPPORTED_SYMMETRIC)
    sp.add_argument("--password", required=True)
    sp.set_defaults(func=lambda a: _cmd_stream(a, True))

    sp = sub.add_parser("stream-decrypt"); add_io(sp)
    sp.add_argument("--algo", required=True, choices=SUPPORTED_SYMMETRIC)
    sp.add_argument("--password", required=True)
    sp.set_defaults(func=lambda a: _cmd_stream(a, False))

    sp = sub.add_parser("hash")
    sp.add_argument("--algo", required=True, choices=SUPPORTED_HASHES)
    sp.add_argument("--infile", "--in", "-i")
    sp.add_argument("--text")
    sp.add_argument("--shake-len", type=int, default=None)
    sp.add_argument("--verify", default=None, help="待校验的十六进制摘要")
    sp.set_defaults(func=_cmd_hash)

    sp = sub.add_parser("passgen")
    sp.add_argument("--length", type=int, default=20)
    sp.add_argument("--passphrase", action="store_true")
    sp.add_argument("--words", type=int, default=6)
    sp.add_argument("--separator", default="-")
    sp.add_argument("--exclude-ambiguous", action="store_true")
    sp.set_defaults(func=_cmd_passgen)

    sp = sub.add_parser("shamir-split"); sp.add_argument("--infile", required=True)
    sp.add_argument("--out-dir", required=True)
    sp.add_argument("--threshold", type=int, required=True)
    sp.add_argument("--total", type=int, required=True)
    sp.set_defaults(func=_cmd_shamir_split)

    sp = sub.add_parser("shamir-combine")
    sp.add_argument("--shares", nargs="+", required=True)
    sp.add_argument("--outfile", required=True)
    sp.add_argument("--threshold", type=int, required=True)
    sp.set_defaults(func=_cmd_shamir_combine)

    sp = sub.add_parser("stego-hide")
    sp.add_argument("--carrier", required=True)
    sp.add_argument("--outfile", required=True)
    sp.add_argument("--infile", required=True)
    sp.add_argument("--password", required=True)
    sp.add_argument("--bit-depth", type=int, default=1)
    sp.set_defaults(func=_cmd_stego_hide)

    sp = sub.add_parser("stego-reveal")
    sp.add_argument("--infile", required=True)
    sp.add_argument("--outfile", required=True)
    sp.add_argument("--password", required=True)
    sp.add_argument("--bit-depth", type=int, default=1)
    sp.set_defaults(func=_cmd_stego_reveal)

    sp = sub.add_parser("pq-keygen")
    sp.add_argument("--algo", required=True, choices=SUPPORTED_PQ)
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=_cmd_pq_keygen)

    sp = sub.add_parser("pq-sign"); sp.add_argument("--algo", required=True, choices=SUPPORTED_PQ)
    sp.add_argument("--secret-key", required=True)
    sp.add_argument("--public-key", default=None)
    sp.add_argument("--infile", required=True)
    sp.add_argument("--outfile", required=True)
    sp.add_argument("--days", type=int, default=None)
    sp.add_argument("--hours", type=int, default=None)
    sp.set_defaults(func=_cmd_pq_sign)

    sp = sub.add_parser("pq-verify"); sp.add_argument("--algo", required=True, choices=SUPPORTED_PQ)
    sp.add_argument("--public-key", required=True)
    sp.add_argument("--infile", required=True)
    sp.add_argument("--bundle", required=True)
    sp.set_defaults(func=_cmd_pq_verify)

    for verb, enc in (("cascade-encrypt", True), ("cascade-decrypt", False)):
        sp = sub.add_parser(verb); add_io(sp)
        sp.add_argument("--layers", default="AES-256-GCM,ChaCha20-Poly1305,Serpent-GCM")
        sp.add_argument("--password", required=True)
        sp.set_defaults(func=lambda a, e=enc: _cmd_cascade(a, e))

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except SystemExit:
        raise
    except Exception as exc:
        from cipherforge.core.errors import CipherForgeError

        if isinstance(exc, CipherForgeError):
            print(exc.user_text(), file=sys.stderr)
        else:
            print(f"错误：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
