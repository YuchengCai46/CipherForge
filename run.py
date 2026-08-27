#!/usr/bin/env python3
"""
CipherForge 启动器
===================

根据运行环境自动选择入口：
  * ``--gui`` / ``-g``    → 图形界面
  * 无参数                → 交互式 CLI（调用 cli.py 主菜单）
  * 其他参数              → 透传给 cli.py 子命令

用法
----
  python run.py
  python run.py --gui
  python run.py encrypt --algo AES-256-GCM --password xxx --in f.txt --out f.enc
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ is None and str(Path(__file__).parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).parent))


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if "--gui" in args or "-g" in args:
        from gui import main as run_gui
        run_gui()
        return 0
    # 透传给 cli.main(argv)
    from cli import main as cli_main
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
