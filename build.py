#!/usr/bin/env python3
"""
CipherForge 构建脚本
=====================

提供本地开发与发布两种打包方式：
  * python build.py              # PyInstaller 单文件发布（推荐）
  * python build.py --develop    # 开发模式（非单文件，保留调试信息）
  * python build.py --release    # 发布模式（禁用调试、启用反调试钩子）

依赖
----
  pip install pyinstaller>=6.3.0
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
PYINSTALLER = "pyinstaller"


def _run(cmd: list[str], **kwargs) -> int:
    print(f"[build] {' '.join(cmd)}")
    return subprocess.call(cmd, cwd=str(ROOT), **kwargs)


def build(mode: str = "release") -> int:
    dist_dir = ROOT / "dist"
    spec_dir = ROOT / ".build"
    spec_dir.mkdir(exist_ok=True)

    # 清理旧产物
    for p in list(dist_dir.glob("cipherforge*")) + list(spec_dir.glob("cipherforge*")):
        if p.is_file():
            p.unlink()

    py = sys.executable
    spec = str(spec_dir / "cipherforge.spec")

    # 排除不必要的依赖以减小体积
    excludes = [
        "tkinter",
        "test",
        "tests",
        "unittest",
        "liboqs",
        "pyzbar",
        "twofish",
        "qrcode",
        "PIL",
        "setuptools",
        "docutils",
        "pip",
        "distro",
        "numpy",
        "pandas",
    ]

    cmd = [
        py, "-m", PYINSTALLER,
        "--onefile" if mode == "release" else "--onedir",
        "--clean",
        "--noconfirm",
        "--name", "cipherforge",
        "--add-data", str(ROOT / "config.yaml;."),
        "--add-data", str(ROOT / "static" / "index.html;static"),
        "--add-data", str(ROOT / "static" / "css;static/css"),
        "--add-data", str(ROOT / "static" / "js;static/js"),
        "--exclude-module=" + ";".join(excludes),
        "--hidden-import=cipherforge",
        "--hidden-import=cipherforge.crypto",
        "--hidden-import=cipherforge.core",
        "--strip",
        "--noupx" if mode == "release" else "",
        str(ROOT / "cli.py"),
    ]

    rc = _run(cmd)
    if rc != 0:
        print("[build] FAILED", file=sys.stderr)
        return rc

    print(f"[build] OK — output in {dist_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="build.py", description="CipherForge 构建脚本")
    ap.add_argument("--develop", action="store_true", help="开发模式（非单文件）")
    ap.add_argument("--release", action="store_true", help="发布模式（单文件，默认）")
    args = ap.parse_args(argv)
    return build(mode="develop" if args.develop else "release")


if __name__ == "__main__":
    raise SystemExit(main())
