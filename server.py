"""
CipherForge Web 服务
====================

基于 FastAPI 的轻量加密服务，提供 HTTP API + 静态前端。

启动方式
--------
  .venv/Scripts/python.exe server.py              # 默认 :8000
  .venv/Scripts/python.exe server.py --port 9000
  .venv/Scripts/python.exe server.py --host 0.0.0.0
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from typing import Dict
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cipherforge.crypto import (
    SymmetricCipher,
    StreamCipher,
    HashEngine,
    KeyDeriver,
    PasswordGenerator,
    ShamirSecretSharing,
    LSBSteganography,
    CascadeEngine,
    PQSignatureEngine,
    SignatureBundle,
    SUPPORTED_SYMMETRIC,
    SUPPORTED_HASHES,
    SUPPORTED_PQ,
)
from cipherforge.crypto.pq_signature import SignatureInvalidError
from cipherforge.core.hardening import build_logger
import datetime as _dt

logger = build_logger("CipherForge.Server")

STATIC_DIR = ROOT / "static"
DEFAULT_PORT = int(os.environ.get("CF_PORT", 8000))
DEFAULT_HOST = os.environ.get("CF_HOST", "127.0.0.1")

app = FastAPI(title="CipherForge", description="桌面级密码学工具箱 — Web API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 静态文件服务 - 挂载到 /static
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ======================================================================
#  请求/响应模型
# ======================================================================
class EncryptRequest(BaseModel):
    algorithm: str = Field(default="AES-256-GCM", pattern=rf"^({'|'.join(SUPPORTED_SYMMETRIC)})$")
    password: str = Field(min_length=4, max_length=256)
    plaintext: str = Field(min_length=1)
    aad: str = ""


class DecryptRequest(BaseModel):
    algorithm: str
    password: str
    ciphertext_b64: str
    nonce_b64: str
    tag_b64: str
    aad: str = ""


class HashRequest(BaseModel):
    algorithm: str = Field(default="SHA-256", pattern=rf"^({'|'.join(SUPPORTED_HASHES)})$")
    data: str = Field(min_length=1)


class PasswordRequest(BaseModel):
    length: int = Field(default=24, ge=8, le=128)
    exclude_ambiguous: bool = False
    passphrase: bool = False
    words: int = Field(default=6, ge=4, le=12)


class ShamirSplitRequest(BaseModel):
    threshold: int = Field(default=3, ge=2, le=10)
    total: int = Field(default=5, ge=3, le=20)
    secret: str = Field(min_length=1)


class CascadeRequest(BaseModel):
    layers: list[str] = Field(default=["AES-256-GCM", "ChaCha20-Poly1305", "Serpent-GCM"])
    password: str = Field(min_length=4, max_length=256)
    layer_passwords: list[str] | None = None
    data: str = Field(min_length=1)


class StagenoHideRequest(BaseModel):
    carrier: str  # base64 encoded carrier image
    payload: str  # base64 encoded payload
    password: str
    bit_depth: int = Field(default=1, ge=1, le=4)


class StagenoRevealRequest(BaseModel):
    stego: str  # base64 encoded stego image
    password: str
    bit_depth: int = Field(default=1, ge=1, le=4)


class PQKeyGenRequest(BaseModel):
    algorithm: str = Field(default="ML-DSA-87", pattern=rf"^({'|'.join(SUPPORTED_PQ)})$")


class CascadeEncryptResponse(BaseModel):
    success: bool
    ciphertext_b64: str


class CascadeDecryptResponse(BaseModel):
    success: bool
    plaintext: str


class ShamirCombineRequest(BaseModel):
    shares: list[str] = Field(min_length=2)


# ======================================================================
#  API 路由
# ======================================================================
@app.get("/", response_class=FileResponse)
async def index():
    """返回前端主页。"""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path), media_type="text/html")
    raise HTTPException(status_code=404, detail="前端文件不存在")


@app.get("/api/algorithms")
async def list_algorithms():
    """返回支持的算法列表。"""
    return {"symmetric": SUPPORTED_SYMMETRIC, "hash": SUPPORTED_HASHES}


@app.post("/api/encrypt")
async def api_encrypt(req: EncryptRequest):
    """对称加密接口。"""
    try:
        pt_bytes = req.plaintext.encode("utf-8")
        aad = req.aad.encode("utf-8") if req.aad else b""
        
        cipher = SymmetricCipher(req.algorithm)
        blob = cipher.encrypt(pt_bytes, password=req.password, aad=aad)
        
        nonce = blob[:24]
        tag = blob[24:40]
        ciphertext = blob[40:]
        
        return {
            "success": True,
            "algorithm": req.algorithm,
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "nonce_b64": base64.b64encode(nonce).decode(),
            "tag_b64": base64.b64encode(tag).decode(),
        }
    except Exception as exc:
        logger.error("encrypt 失败: %s", exc)
        raise HTTPException(status_code=400, detail="加密操作失败")


@app.post("/api/decrypt")
async def api_decrypt(req: DecryptRequest):
    """对称解密接口。"""
    try:
        ciphertext = base64.b64decode(req.ciphertext_b64)
        nonce = base64.b64decode(req.nonce_b64)
        tag = base64.b64decode(req.tag_b64)
        blob = nonce + tag + ciphertext
        
        cipher = SymmetricCipher(req.algorithm)
        pt = cipher.decrypt(blob, password=req.password, aad=req.aad.encode() if req.aad else b"")
        
        return {"success": True, "plaintext": pt.decode("utf-8")}
    except Exception as exc:
        logger.error("decrypt 失败: %s", exc)
        raise HTTPException(status_code=400, detail=f"解密失败: {exc}")


@app.post("/api/stream-encrypt")
async def api_stream_encrypt(req: Dict[str, str]):
    """流式加密接口（上传文件加密）。"""
    try:
        # 简化版：直接加密整个数据
        data = req.get("data", "").encode("utf-8")
        password = req.get("password", "")
        algo = req.get("algorithm", "AES-256-GCM")
        if not data or not password:
            raise ValueError("data and password required")
        cipher = StreamCipher(algo)
        blob = cipher.encrypt(data, password=password)
        return {"success": True, "ciphertext_b64": base64.b64encode(blob).decode()}
    except Exception as exc:
        logger.error("stream-encrypt 失败: %s", exc)
        raise HTTPException(status_code=400, detail="流式加密失败")


@app.post("/api/stream-decrypt")
async def api_stream_decrypt(req: Dict[str, str]):
    """流式解密接口。"""
    try:
        ciphertext = base64.b64decode(req.get("ciphertext_b64", ""))
        password = req.get("password", "")
        algo = req.get("algorithm", "AES-256-GCM")
        if not ciphertext or not password:
            raise ValueError("ciphertext and password required")
        cipher = StreamCipher(algo)
        pt = cipher.decrypt(ciphertext, password=password)
        return {"success": True, "plaintext": pt.decode("utf-8")}
    except Exception as exc:
        logger.error("stream-decrypt 失败: %s", exc)
        raise HTTPException(status_code=400, detail="流式解密失败")


@app.post("/api/hash")
async def api_hash(req: HashRequest):
    """哈希计算接口。"""
    try:
        data = req.data.encode("utf-8")
        he = HashEngine()
        digest = he.hash(data, req.algorithm)  # 返回 hex 字符串
        
        return {
            "success": True,
            "algorithm": req.algorithm,
            "hex_digest": digest,
            "b64_digest": base64.b64encode(bytes.fromhex(digest)).decode(),
        }
    except Exception as exc:
        logger.error("hash 失败: %s", exc)
        raise HTTPException(status_code=400, detail="哈希计算失败")


@app.post("/api/generate-password")
async def api_generate_password(req: PasswordRequest):
    """密码生成接口。"""
    try:
        gen = PasswordGenerator()
        if req.passphrase:
            pw = gen.generate_passphrase(req.words)
            entropy = gen.passphrase_entropy(req.words, 7776)
        else:
            pw = gen.generate(req.length, exclude_ambiguous=req.exclude_ambiguous)
            charset = gen.default_charset(exclude_ambiguous=req.exclude_ambiguous)
            entropy = gen.entropy_bits(pw, len(charset))
        
        return {
            "success": True,
            "password": pw,
            "entropy_bits": round(entropy, 1),
            "strength": gen.strength_label(entropy),
        }
    except Exception as exc:
        logger.error("password generation 失败: %s", exc)
        raise HTTPException(status_code=400, detail="密码生成失败")


@app.post("/api/shamir-split")
async def api_shamir_split(req: ShamirSplitRequest):
    """Shamir 分片接口。"""
    try:
        s = ShamirSecretSharing(req.threshold, req.total)
        shares = s.split_to_text(req.secret.encode("utf-8"))
        return {"success": True, "threshold": req.threshold, "total": req.total, "shares": shares}
    except Exception as exc:
        logger.error("shamir-split 失败: %s", exc)
        raise HTTPException(status_code=400, detail="分片失败")


@app.post("/api/shamir-combine")
async def api_shamir_combine(req: ShamirCombineRequest):
    """Shamir 合并接口。"""
    try:
        # 合并只需要有效实例调用 combine()，阈值和总数不影响结果
        s = ShamirSecretSharing(2, 2)
        secret = s.combine(req.shares)
        return {"success": True, "secret": secret.decode("utf-8")}
    except Exception as exc:
        logger.error("shamir-combine 失败: %s", exc)
        raise HTTPException(status_code=400, detail="合并失败")


@app.post("/api/cascade-encrypt")
async def api_cascade_encrypt(req: CascadeRequest):
    """级联加密接口（支持多重密码和每层独立盐）。"""
    try:
        ce = CascadeEngine(algorithms=req.layers)
        data_bytes = req.data.encode("utf-8")
        blob = ce.encrypt(data_bytes, password=req.password, layer_passwords=req.layer_passwords)
        return {"success": True, "ciphertext_b64": base64.b64encode(blob).decode()}
    except Exception as exc:
        logger.error("cascade-encrypt 失败: %s", exc)
        raise HTTPException(status_code=400, detail="级联加密失败")


@app.post("/api/cascade-decrypt")
async def api_cascade_decrypt(req: CascadeRequest):
    """级联解密接口。"""
    try:
        ce = CascadeEngine(algorithms=req.layers)
        blob = base64.b64decode(req.data)
        plaintext = ce.decrypt(blob, password=req.password, layer_passwords=req.layer_passwords)
        return {"success": True, "plaintext": plaintext.decode("utf-8")}
    except Exception as exc:
        logger.error("cascade-decrypt 失败: %s", exc)
        raise HTTPException(status_code=400, detail="级联解密失败")


@app.post("/api/pq-keygen")
async def api_pq_keygen(req: PQKeyGenRequest):
    """抗量子签名密钥对生成接口。"""
    try:
        pq = PQSignatureEngine(req.algorithm)
        pk, sk = pq.generate_keypair()
        return {
            "success": True,
            "public_key_b64": base64.b64encode(pk).decode(),
            "private_key_b64": base64.b64encode(sk).decode(),
            "algorithm": req.algorithm,
        }
    except Exception as exc:
        logger.error("pq-keygen 失败: %s", exc)
        raise HTTPException(status_code=400, detail="密钥对生成失败")


@app.post("/api/pq-sign")
async def api_pq_sign(req: Dict[str, str]):
    """抗量子签名接口。"""
    try:
        sk_b64 = req.get("private_key_b64", "")
        pk_b64 = req.get("public_key_b64", "")
        message = req.get("message", "").encode("utf-8")
        algo = req.get("algorithm", "ML-DSA-87")
        if not sk_b64 or not message:
            raise ValueError("private_key_b64 and message required")
        pq = PQSignatureEngine(algo)
        pk = base64.b64decode(pk_b64) if pk_b64 else None
        bundle = pq.sign(base64.b64decode(sk_b64), message, public_key=pk)
        return {
            "success": True,
            "signature_b64": base64.b64encode(bundle.signature).decode(),
            "public_key_b64": base64.b64encode(bundle.public_key).decode() if bundle.public_key else "",
            "algorithm": bundle.algorithm,
        }
    except Exception as exc:
        logger.error("pq-sign 失败: %s", exc)
        raise HTTPException(status_code=400, detail="签名失败")


@app.post("/api/pq-verify")
async def api_pq_verify(req: Dict[str, str]):
    """抗量子签名验证接口。"""
    try:
        pk_b64 = req.get("public_key_b64", "")
        signature_b64 = req.get("signature_b64", "")
        message = req.get("message", "").encode("utf-8")
        algo = req.get("algorithm", "ML-DSA-87")
        if not all([pk_b64, signature_b64, message]):
            raise ValueError("public_key_b64, signature_b64, and message required")
        pq = PQSignatureEngine(algo)
        bundle = SignatureBundle(
            algorithm=algo,
            public_key=base64.b64decode(pk_b64),
            signature=base64.b64decode(signature_b64),
            signed_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        )
        pq.verify(message, bundle)
        return {"success": True, "valid": True}
    except SignatureInvalidError:
        return {"success": True, "valid": False}
    except Exception as exc:
        logger.error("pq-verify 失败: %s", exc)
        raise HTTPException(status_code=400, detail="签名验证失败")


@app.get("/health")
async def health():
    """健康检查。"""
    return {"status": "ok", "version": "1.0.0", "tests": 311}


# ======================================================================
#  启动入口
# ======================================================================
def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """启动服务器。"""
    logger.info("启动 CipherForge Web 服务: http://%s:%d", host, port)
    try:
        import uvicorn
        uvicorn.run("server:app", host=host, port=port, log_level="info", reload=False)
    except ImportError:
        logger.error("uvicorn 未安装，请执行: pip install uvicorn")
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="server.py", description="CipherForge Web 服务")
    ap.add_argument("--host", default=DEFAULT_HOST, help=f"监听地址 (默认 {DEFAULT_HOST})")
    ap.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help=f"端口 (默认 {DEFAULT_PORT})")
    args = ap.parse_args(argv)
    run_server(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
