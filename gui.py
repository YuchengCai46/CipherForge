"""
CipherForge — 桌面级密码学工具箱
=================================

图形界面入口。依赖 ``tkinter`` + ``ttkbootstrap``；
若环境缺失这些库，启动时会显示友好的中文提示而不是堆栈。

启动方式
--------
    python run.py
"""

from __future__ import annotations

import base64
import hashlib
import math
import secrets
import string
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

try:
    import ttkbootstrap as tb  # type: ignore[import-untyped]
except ImportError:
    tb = None  # type: ignore[assignment]

from cipherforge.core.config import load_config
from cipherforge.core.hardening import anti_debug_guard, build_logger
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
    SUPPORTED_SYMMETRIC,
    SUPPORTED_HASHES,
    SUPPORTED_PQ,
)

logger = build_logger("CipherForge.GUI")

MODULE_NAMES = [
    "对称加密",
    "流式加密",
    "哈希/Pepper",
    "密码生成",
    "Shamir 共享",
    "LSB 隐写",
    "级联加密",
    "抗量子签名",
]


class LayerWidget(tk.Frame):
    """拖拽排序的层 widget"""
    def __init__(self, master, text: str, on_remove, **kwargs) -> None:
        super().__init__(master, bg="#252526", **kwargs)
        self._on_remove = on_remove
        tk.Label(self, text=text, font=("Consolas", 9), fg="#9cdcfe",
                 bg="#252526", anchor="w").pack(side="left", padx=8)
        tk.Button(self, text="✕", command=on_remove, bg="#dc3545", fg="#fff",
                  font=("Microsoft YaHei UI", 9), width=2).pack(side="right", padx=8)


class BaseApp(tk.Tk):
    """最简版窗口：任何情况下都能跑（即便 ttkbootstrap 不可用）。"""

    def __init__(self) -> None:
        super().__init__()
        self.title("CipherForge 工具箱 v1.0")
        self.geometry("960x640")
        self.minsize(800, 540)
        self.configure(bg="#1e1e1e")

        self._build_ui()
        self.update_idletasks()
        self._center_on_screen()

    def _center_on_screen(self) -> None:
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x = (sw - self.winfo_reqwidth()) // 2
        y = (sh - self.winfo_reqheight()) // 2
        self.geometry(f"+{x}+{y}")

    def _build_ui(self) -> None:
        self._theme = {"bg": "#1e1e1e", "fg": "#d4d4d4", "fg_accent": "#9cdcfe",
                       "fg_title": "#ce9178", "fg_green": "#6a9955",
                       "bg_input": "#252526", "border": "#3e3e42"}
        top_frame = tk.Frame(self, bg="#1e1e1e")
        top_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(top_frame, text="CipherForge",
                 font=("Microsoft YaHei UI", 16, "bold"),
                 fg="#9cdcfe", bg="#1e1e1e").pack(side="left")
        tk.Label(top_frame, text="桌面密码学工具箱",
                 font=("Microsoft YaHei UI", 9),
                 fg="#808080", bg="#1e1e1e").pack(side="left", padx=(12, 0))

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self._pages: dict[str, tk.Frame] = {}
        for name in MODULE_NAMES:
            frame = tk.Frame(self.tabs, bg="#1e1e1e")
            self.tabs.add(frame, text=name)
            self._pages[name] = frame
            getattr(self, f"_build_{name.replace(' ', '_').replace('/', '_')}")(frame)

        self.tabs.select(0)

        status = tk.Frame(self, bg="#007acc", height=22)
        status.pack(fill="x", side="bottom")
        self._status_left = tk.Label(status, text="就绪 | CipherForge v1.0",
                                     font=("Consolas", 8), fg="#fff", bg="#007acc")
        self._status_left.pack(side="left", padx=8)
        self._status_right = tk.Label(status, text="安全模式",
                                      font=("Consolas", 8), fg="#fff", bg="#cc3300")
        self._status_right.pack(side="right", padx=8)

    def _help(self, frame: tk.Frame, title: str, items: list[str]) -> None:
        body = tk.Frame(frame, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        tk.Label(body, text=title, font=("Microsoft YaHei UI", 13, "bold"),
                 fg="#ce9178", bg="#1e1e1e").pack(anchor="w")
        for line in items:
            tk.Label(body, text=f"• {line}", font=("Microsoft YaHei UI", 9),
                     fg="#d4d4d4", bg="#1e1e1e", anchor="w").pack(anchor="w", pady=2)

    def _build_对称加密(self, frame: tk.Frame) -> None:
        body = tk.Frame(frame, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        tk.Label(body, text="对称加密", font=("Microsoft YaHei UI", 13, "bold"),
                 fg="#ce9178", bg="#1e1e1e").pack(anchor="w")
        algo_frame = tk.Frame(body, bg="#1e1e1e")
        algo_frame.pack(fill="x", pady=8)
        tk.Label(algo_frame, text="算法：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._sym_algo_var = tk.StringVar(value="AES-256-GCM")
        ttk.Combobox(algo_frame, textvariable=self._sym_algo_var,
                     values=SUPPORTED_SYMMETRIC, width=20).pack(side="left", padx=8)
        pwd_frame = tk.Frame(body, bg="#1e1e1e")
        pwd_frame.pack(fill="x", pady=4)
        tk.Label(pwd_frame, text="密码：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._sym_password = tk.Entry(pwd_frame, show="*", width=30)
        self._sym_password.pack(side="left", padx=8)
        self._sym_input = scrolledtext.ScrolledText(body, width=60, height=8,
                                                   bg="#252526", fg="#d4d4d4",
                                                   font=("Consolas", 10))
        self._sym_input.pack(fill="both", expand=True, pady=8)
        btn_frame = tk.Frame(body, bg="#1e1e1e")
        btn_frame.pack(fill="x", pady=8)
        tk.Button(btn_frame, text="加密", command=self._do_sym_encrypt,
                  bg="#4caf50", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Button(btn_frame, text="解密", command=self._do_sym_decrypt,
                  bg="#2196f3", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Button(btn_frame, text="清空", command=self._clear_sym,
                  bg="#607d8b", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Label(body, text="输出：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(anchor="w", pady=(8, 0))
        self._sym_output = scrolledtext.ScrolledText(body, width=60, height=6,
                                                    bg="#252526", fg="#6a9955",
                                                    font=("Consolas", 10))
        self._sym_output.pack(fill="both", expand=True, pady=8)
    
    def _do_sym_encrypt(self) -> None:
        try:
            password = self._sym_password.get()
            if not password:
                messagebox.showerror("错误", "请输入密码")
                return
            data = self._sym_input.get("1.0", "end-1c").encode()
            if not data:
                messagebox.showerror("错误", "请输入要加密的内容")
                return
            algo = self._sym_algo_var.get()
            cipher = SymmetricCipher(algo)
            result = cipher.encrypt(data, password=password)
            self._sym_output.delete("1.0", "end")
            self._sym_output.insert("1.0", base64.b64encode(result).decode())
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
    
    def _do_sym_decrypt(self) -> None:
        try:
            password = self._sym_password.get()
            if not password:
                messagebox.showerror("错误", "请输入密码")
                return
            data_b64 = self._sym_input.get("1.0", "end-1c").strip()
            if not data_b64:
                messagebox.showerror("错误", "请输入要解密的内容")
                return
            algo = self._sym_algo_var.get()
            cipher = SymmetricCipher(algo)
            result = cipher.decrypt(base64.b64decode(data_b64), password=password)
            self._sym_output.delete("1.0", "end")
            self._sym_output.insert("1.0", result.decode())
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
    
    def _clear_sym(self) -> None:
        self._sym_input.delete("1.0", "end")
        self._sym_output.delete("1.0", "end")
        self._sym_password.delete(0, "end")

    def _build_流式加密(self, frame: tk.Frame) -> None:
        """流式加密模块（文件加密/解密）"""
        body = tk.Frame(frame, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        tk.Label(body, text="流式加密", font=("Microsoft YaHei UI", 13, "bold"),
                 fg="#ce9178", bg="#1e1e1e").pack(anchor="w")
        algo_frame = tk.Frame(body, bg="#1e1e1e")
        algo_frame.pack(fill="x", pady=8)
        tk.Label(algo_frame, text="算法：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._strm_algo_var = tk.StringVar(value="AES-256-GCM")
        ttk.Combobox(algo_frame, textvariable=self._strm_algo_var,
                     values=SUPPORTED_SYMMETRIC, width=20).pack(side="left", padx=8)
        pwd_frame = tk.Frame(body, bg="#1e1e1e")
        pwd_frame.pack(fill="x", pady=4)
        tk.Label(pwd_frame, text="密码：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._strm_password = tk.Entry(pwd_frame, show="*", width=30)
        self._strm_password.pack(side="left", padx=8)
        btn_frame = tk.Frame(body, bg="#1e1e1e")
        btn_frame.pack(fill="x", pady=8)
        tk.Button(btn_frame, text="加密文件", command=self._do_strm_encrypt,
                  bg="#4caf50", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=12).pack(side="left", padx=8)
        tk.Button(btn_frame, text="解密文件", command=self._do_strm_decrypt,
                  bg="#2196f3", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=12).pack(side="left", padx=8)
        tk.Label(body, text="提示：选择输入文件后点击按钮，输出文件将保存在同目录",
                 font=("Microsoft YaHei UI", 8), fg="#808080",
                 bg="#1e1e1e", anchor="w").pack(fill="x", pady=4)
        self._strm_status = tk.Label(body, text="", font=("Microsoft YaHei UI", 9),
                                     fg="#6a9955", bg="#1e1e1e", anchor="w")
        self._strm_status.pack(fill="x", pady=4)
    
    def _do_strm_encrypt(self) -> None:
        try:
            password = self._strm_password.get()
            if not password:
                messagebox.showerror("错误", "请输入密码")
                return
            src = filedialog.askopenfilename(title="选择要加密的文件")
            if not src:
                return
            dst = filedialog.asksaveasfilename(title="选择输出位置",
                                               defaultextension=".cf",
                                               filetypes=[("CipherForge 文件", "*.cf"), ("所有文件", "*.*")])
            if not dst:
                return
            algo = self._strm_algo_var.get()
            cipher = StreamCipher(algo)
            cipher.encrypt_stream(src, dst, password=password)
            self._strm_status.config(text=f"加密完成: {dst}")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
    
    def _do_strm_decrypt(self) -> None:
        try:
            password = self._strm_password.get()
            if not password:
                messagebox.showerror("错误", "请输入密码")
                return
            src = filedialog.askopenfilename(title="选择要解密的文件")
            if not src:
                return
            dst = filedialog.asksaveasfilename(title="选择输出位置",
                                               defaultextension=".txt",
                                               filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
            if not dst:
                return
            algo = self._strm_algo_var.get()
            cipher = StreamCipher(algo)
            cipher.decrypt_stream(src, dst, password=password)
            self._strm_status.config(text=f"解密完成: {dst}")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
    
    def _build_哈希_Pepper(self, frame: tk.Frame) -> None:
        """哈希模块"""
        body = tk.Frame(frame, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        tk.Label(body, text="哈希 / Pepper", font=("Microsoft YaHei UI", 13, "bold"),
                 fg="#ce9178", bg="#1e1e1e").pack(anchor="w")
        algo_frame = tk.Frame(body, bg="#1e1e1e")
        algo_frame.pack(fill="x", pady=8)
        tk.Label(algo_frame, text="算法：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._hash_algo_var = tk.StringVar(value="SHA-256")
        ttk.Combobox(algo_frame, textvariable=self._hash_algo_var,
                     values=SUPPORTED_HASHES, width=15).pack(side="left", padx=8)
        tk.Label(algo_frame, text="Pepper（可选）：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left", padx=(20, 0))
        self._hash_pepper = tk.Entry(algo_frame, width=30)
        self._hash_pepper.pack(side="left", padx=8)
        self._hash_input = scrolledtext.ScrolledText(body, width=60, height=8,
                                                    bg="#252526", fg="#d4d4d4",
                                                    font=("Consolas", 10))
        self._hash_input.pack(fill="both", expand=True, pady=8)
        btn_frame = tk.Frame(body, bg="#1e1e1e")
        btn_frame.pack(fill="x", pady=8)
        tk.Button(btn_frame, text="哈希", command=self._do_hash,
                  bg="#4caf50", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Button(btn_frame, text="校验", command=self._do_hash_verify,
                  bg="#2196f3", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Label(body, text="哈希结果：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(anchor="w", pady=(8, 0))
        self._hash_output = scrolledtext.ScrolledText(body, width=60, height=4,
                                                     bg="#252526", fg="#6a9955",
                                                     font=("Consolas", 10))
        self._hash_output.pack(fill="both", expand=True, pady=8)
    
    def _do_hash(self) -> None:
        try:
            pepper = self._hash_pepper.get()
            pepper_bytes = hashlib.sha256(pepper.encode()).digest() if pepper else None
            data = self._hash_input.get("1.0", "end-1c").encode()
            engine = HashEngine()
            result = engine.hash(data, self._hash_algo_var.get(), pepper=pepper_bytes)
            self._hash_output.delete("1.0", "end")
            self._hash_output.insert("1.0", result)
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
    
    def _do_hash_verify(self) -> None:
        try:
            pepper = self._hash_pepper.get()
            pepper_bytes = hashlib.sha256(pepper.encode()).digest() if pepper else None
            data = self._hash_input.get("1.0", "end-1c").encode()
            expected = self._hash_output.get("1.0", "end-1c").strip()
            if not expected:
                messagebox.showwarning("提示", "请先计算哈希值再校验")
                return
            engine = HashEngine()
            ok = engine.verify(data, expected, self._hash_algo_var.get(), pepper=pepper_bytes)
            messagebox.showinfo("校验结果", "✓ 匹配" if ok else "✗ 不匹配")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))

    def _build_密码生成(self, frame: tk.Frame) -> None:
        """密码生成模块"""
        body = tk.Frame(frame, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        tk.Label(body, text="密码生成", font=("Microsoft YaHei UI", 13, "bold"),
                 fg="#ce9178", bg="#1e1e1e").pack(anchor="w")
        row1 = tk.Frame(body, bg="#1e1e1e")
        row1.pack(fill="x", pady=8)
        tk.Label(row1, text="类型：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._pg_type_var = tk.StringVar(value="random")
        tk.Radiobutton(row1, text="随机密码", variable=self._pg_type_var,
                        value="random").pack(side="left", padx=8)
        tk.Radiobutton(row1, text="密语（词组）", variable=self._pg_type_var,
                        value="passphrase").pack(side="left", padx=8)
        row2 = tk.Frame(body, bg="#1e1e1e")
        row2.pack(fill="x", pady=4)
        tk.Label(row2, text="长度/词数：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._pg_len_var = tk.IntVar(value=20)
        tk.Spinbox(row2, from_=8, to=128, textvariable=self._pg_len_var,
                   width=8).pack(side="left", padx=8)
        row3 = tk.Frame(body, bg="#1e1e1e")
        row3.pack(fill="x", pady=4)
        self._pg_noambig_cb = tk.BooleanVar(value=True)
        tk.Checkbutton(row3, text="排除易混淆字符", variable=self._pg_noambig_cb).pack(side="left")
        tk.Button(body, text="生成", command=self._do_generate_password,
                  bg="#4caf50", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(pady=8)
        self._pg_result = tk.Label(body, text="", font=("Consolas", 14),
                                   fg="#6a9955", bg="#1e1e1e", wraplength=500,
                                   anchor="w")
        self._pg_result.pack(fill="x", pady=8)
        self._pg_entropy = tk.Label(body, text="", font=("Microsoft YaHei UI", 9),
                                    fg="#808080", bg="#1e1e1e", anchor="w")
        self._pg_entropy.pack(fill="x")
    
    def _do_generate_password(self) -> None:
        try:
            pg = PasswordGenerator()
            if self._pg_type_var.get() == "random":
                pwd = pg.generate(self._pg_len_var.get(),
                                  exclude_ambiguous=self._pg_noambig_cb.get())
                cs_size = len(pg.default_charset(exclude_ambiguous=self._pg_noambig_cb.get()))
                bits = pg.entropy_bits(pwd, cs_size)
            else:
                pwd = pg.generate_passphrase(self._pg_len_var.get())
                bits = pg.passphrase_entropy(self._pg_len_var.get(), len(pg._WORDLIST))
            self._pg_result.config(text=pwd)
            self._pg_entropy.config(text=f"熵：{bits:.1f} 比特")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
    
    def _build_Shamir_共享(self, frame: tk.Frame) -> None:
        """Shamir 共享模块"""
        body = tk.Frame(frame, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        tk.Label(body, text="Shamir 共享", font=("Microsoft YaHei UI", 13, "bold"),
                 fg="#ce9178", bg="#1e1e1e").pack(anchor="w")
        row1 = tk.Frame(body, bg="#1e1e1e")
        row1.pack(fill="x", pady=4)
        tk.Label(row1, text="分片总数 N：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._sham_total_var = tk.IntVar(value=5)
        tk.Spinbox(row1, from_=2, to=255, textvariable=self._sham_total_var,
                   width=8).pack(side="left", padx=8)
        tk.Label(row1, text="阈值 T：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left", padx=(20, 0))
        self._sham_thresh_var = tk.IntVar(value=3)
        tk.Spinbox(row1, from_=2, to=255, textvariable=self._sham_thresh_var,
                   width=8).pack(side="left", padx=8)
        self._sham_input = scrolledtext.ScrolledText(body, width=60, height=6,
                                                    bg="#252526", fg="#d4d4d4",
                                                    font=("Consolas", 10))
        self._sham_input.pack(fill="both", expand=True, pady=8)
        btn_frame = tk.Frame(body, bg="#1e1e1e")
        btn_frame.pack(fill="x", pady=8)
        tk.Button(btn_frame, text="拆分", command=self._do_sham_split,
                  bg="#4caf50", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Button(btn_frame, text="合并", command=self._do_sham_combine,
                  bg="#2196f3", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Label(body, text="输出：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(anchor="w", pady=(8, 0))
        self._sham_output = scrolledtext.ScrolledText(body, width=60, height=6,
                                                     bg="#252526", fg="#6a9955",
                                                     font=("Consolas", 10))
        self._sham_output.pack(fill="both", expand=True, pady=8)
    
    def _do_sham_split(self) -> None:
        try:
            secret = self._sham_input.get("1.0", "end-1c").encode()
            if not secret:
                messagebox.showerror("错误", "请输入要拆分的秘密")
                return
            sham = ShamirSecretSharing(self._sham_thresh_var.get(),
                                       self._sham_total_var.get())
            shares = sham.split_to_text(secret)
            self._sham_output.delete("1.0", "end")
            for i, s in enumerate(shares, 1):
                self._sham_output.insert("end", f"分片 {i}: {s}\n")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
    
    def _do_sham_combine(self) -> None:
        try:
            shares_text = [line.strip() for line in
                          self._sham_input.get("1.0", "end-1c").strip().split('\n')
                          if line.strip()]
            if not shares_text:
                messagebox.showerror("错误", "请输入分片文本（每行一个）")
                return
            sham = ShamirSecretSharing(len(shares_text), len(shares_text))
            result = sham.combine(shares_text)
            self._sham_output.delete("1.0", "end")
            self._sham_output.insert("1.0", result.decode())
        except Exception as exc:
            messagebox.showerror("错误", str(exc))

    def _build_LSB_隐写(self, frame: tk.Frame) -> None:
        """LSB 隐写模块"""
        body = tk.Frame(frame, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        tk.Label(body, text="LSB 隐写", font=("Microsoft YaHei UI", 13, "bold"),
                 fg="#ce9178", bg="#1e1e1e").pack(anchor="w")
        row1 = tk.Frame(body, bg="#1e1e1e")
        row1.pack(fill="x", pady=4)
        tk.Label(row1, text="位深：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._steg_depth_var = tk.IntVar(value=1)
        ttk.Combobox(row1, textvariable=self._steg_depth_var,
                     values=[1, 2, 3, 4], width=5).pack(side="left", padx=8)
        row2 = tk.Frame(body, bg="#1e1e1e")
        row2.pack(fill="x", pady=4)
        tk.Label(row2, text="密码：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._steg_password = tk.Entry(row2, show="*", width=30)
        self._steg_password.pack(side="left", padx=8)
        self._steg_input = scrolledtext.ScrolledText(body, width=60, height=6,
                                                    bg="#252526", fg="#d4d4d4",
                                                    font=("Consolas", 10))
        self._steg_input.pack(fill="both", expand=True, pady=8)
        btn_frame = tk.Frame(body, bg="#1e1e1e")
        btn_frame.pack(fill="x", pady=8)
        tk.Button(btn_frame, text="隐藏", command=self._do_steg_hide,
                  bg="#4caf50", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Button(btn_frame, text="提取", command=self._do_steg_reveal,
                  bg="#2196f3", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        self._steg_status = tk.Label(body, text="", font=("Microsoft YaHei UI", 9),
                                     fg="#6a9955", bg="#1e1e1e", anchor="w")
        self._steg_status.pack(fill="x", pady=4)
    
    def _do_steg_hide(self) -> None:
        try:
            password = self._steg_password.get()
            if not password:
                messagebox.showerror("错误", "请输入密码")
                return
            data = self._steg_input.get("1.0", "end-1c").encode()
            if not data:
                messagebox.showerror("错误", "请输入要隐藏的内容")
                return
            carrier = filedialog.askopenfilename(title="选择载体图片")
            if not carrier:
                return
            out_path = filedialog.asksaveasfilename(
                title="保存隐写图片", defaultextension=".png",
                filetypes=[("PNG 图片", "*.png"), ("所有文件", "*.*")])
            if not out_path:
                return
            steg = LSBSteganography(self._steg_depth_var.get())
            steg.hide(data, carrier, out_path, password=password)
            self._steg_status.config(text=f"隐藏完成: {out_path}")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
    
    def _do_steg_reveal(self) -> None:
        try:
            password = self._steg_password.get()
            if not password:
                messagebox.showerror("错误", "请输入密码")
                return
            stego = filedialog.askopenfilename(title="选择隐写图片")
            if not stego:
                return
            steg = LSBSteganography(self._steg_depth_var.get())
            result = steg.reveal(stego, password=password)
            messagebox.showinfo("结果", result.decode())
        except Exception as exc:
            messagebox.showerror("错误", str(exc))

    def _build_级联加密(self, frame: tk.Frame) -> None:
        """级联加密模块 — 沙盒式自由堆砌 UI（拖拽排序层）"""
        body = tk.Frame(frame, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        tk.Label(body, text="级联加密", font=("Microsoft YaHei UI", 13, "bold"),
                 fg="#ce9178", bg="#1e1e1e").pack(anchor="w")
        tk.Label(body, text="从左侧列表双击添加层 · 拖拽右侧排序 · 点击✕删除",
                 font=("Microsoft YaHei UI", 9), fg="#808080", bg="#1e1e1e",
                 anchor="w").pack(anchor="w", pady=(2, 6))

        top_pane = tk.Frame(body, bg="#1e1e1e")
        top_pane.pack(fill="both", expand=True, pady=(0, 8))

        self._cascade_order: list[int] = []
        self._drag_src = None

        left = tk.Frame(top_pane, bg="#1e1e1e", width=200)
        left.pack(side="left", fill="y", padx=(0, 12))
        tk.Label(left, text="可用算法", font=("Microsoft YaHei UI", 9, "bold"),
                 fg="#9cdcfe", bg="#1e1e1e", anchor="w").pack(anchor="w", pady=(0, 4))
        self._algo_listbox = tk.Listbox(left, width=22, height=8, bg="#252526",
                                         fg="#d4d4d4", selectmode="single",
                                         font=("Consolas", 9), activestyle="none")
        self._algo_listbox.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        for i, algo in enumerate(SUPPORTED_SYMMETRIC):
            self._algo_listbox.insert("end", f"{i+1}. {algo}")
        self._algo_listbox.bind("<Double-Button-1>", self._on_algo_double_click)

        right = tk.Frame(top_pane, bg="#1e1e1e")
        right.pack(side="left", fill="both", expand=True)
        tk.Label(right, text="已选层（拖拽排序）", font=("Microsoft YaHei UI", 9, "bold"),
                 fg="#9cdcfe", bg="#1e1e1e", anchor="w").pack(anchor="w", pady=(0, 4))

        self._layer_canvas = tk.Canvas(right, height=220, bg="#252526",
                                       highlightthickness=1, highlightbackground="#3e3e42")
        self._layer_scroll = ttk.Scrollbar(right, orient="vertical",
                                           command=self._layer_canvas.yview)
        self._layer_inner = tk.Frame(self._layer_canvas, bg="#252526")
        self._layer_canvas.configure(yscrollcommand=self._layer_scroll.set)
        self._layer_scroll.pack(side="right", fill="y")
        self._layer_win = self._layer_canvas.create_window((0, 0), window=self._layer_inner,
                                                           anchor="nw")
        self._layer_inner.bind("<Configure>", self._on_layer_configure)
        self._layer_widgets: list[LayerWidget] = []
        self._layer_canvas.pack(fill="both", expand=True)

        row1 = tk.Frame(body, bg="#1e1e1e")
        row1.pack(fill="x", pady=8)
        tk.Label(row1, text="主密码：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._cascade_password = tk.Entry(row1, show="*", width=30)
        self._cascade_password.pack(side="left", padx=8)
        self._layer_pw_btn = tk.Button(row1, text="配置层密码",
                                       command=self._show_layer_pw_dialog,
                                       bg="#6c757d", fg="#fff", font=("Microsoft YaHei UI", 9),
                                       width=10)
        self._layer_pw_btn.pack(side="left", padx=8)

        self._cascade_input = scrolledtext.ScrolledText(body, width=60, height=6,
                                                        bg="#252526", fg="#d4d4d4",
                                                        font=("Consolas", 10))
        self._cascade_input.pack(fill="both", expand=True, pady=8)
        btn_frame = tk.Frame(body, bg="#1e1e1e")
        btn_frame.pack(fill="x", pady=4)
        tk.Button(btn_frame, text="加密", command=self._do_cascade_encrypt,
                  bg="#4caf50", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Button(btn_frame, text="解密", command=self._do_cascade_decrypt,
                  bg="#2196f3", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Button(btn_frame, text="清空", command=self._clear_cascade,
                  bg="#dc3545", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=8).pack(side="left", padx=8)
        tk.Label(body, text="输出：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(anchor="w", pady=(8, 0))
        self._cascade_output = scrolledtext.ScrolledText(body, width=60, height=5,
                                                         bg="#252526", fg="#6a9955",
                                                         font=("Consolas", 10))
        self._cascade_output.pack(fill="both", expand=True, pady=8)

    def _on_layer_configure(self, event) -> None:
        self._layer_canvas.configure(scrollregion=self._layer_canvas.bbox("all"))

    def _on_algo_double_click(self, event) -> None:
        sel = self._algo_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        algo = SUPPORTED_SYMMETRIC[idx]
        if algo not in [SUPPORTED_SYMMETRIC[i] for i in self._cascade_order]:
            self._cascade_order.append(idx)
            self._refresh_layer_list()

    def _refresh_layer_list(self) -> None:
        for w in self._layer_inner.winfo_children():
            w.destroy()
        self._layer_widgets.clear()
        for pos, idx in enumerate(self._cascade_order):
            algo = SUPPORTED_SYMMETRIC[idx]
            wf = LayerWidget(self._layer_inner, text=f"{pos+1}. {algo}",
                             on_remove=lambda p=pos: self._remove_layer(p))
            wf.pack(fill="x", pady=2)
            wf.bind("<ButtonPress-1>", self._on_layer_press)
            wf.bind("<B1-Motion>", self._on_layer_drag)
            wf.bind("<ButtonRelease-1>", self._on_layer_release)
            self._layer_widgets.append(wf)
        self._layer_inner.update_idletasks()
        self._on_layer_configure(None)

    def _remove_layer(self, pos: int) -> None:
        self._cascade_order.pop(pos)
        self._refresh_layer_list()

    def _on_layer_press(self, event) -> None:
        widget = self._get_layer_at(event.y)
        if widget is not None:
            self._drag_src = widget
            widget.lift()

    def _on_layer_drag(self, event) -> None:
        if self._drag_src is None:
            return
        y = event.y
        widget = self._get_layer_at(y)
        if widget is not None and widget != self._drag_src:
            src_pos = self._layer_widgets.index(self._drag_src)
            tgt_pos = self._layer_widgets.index(widget)
            self._layer_widgets[src_pos], self._layer_widgets[tgt_pos] = \
                self._layer_widgets[tgt_pos], self._layer_widgets[src_pos]
            self._cascade_order[src_pos], self._cascade_order[tgt_pos] = \
                self._cascade_order[tgt_pos], self._cascade_order[src_pos]
            for i, w in enumerate(self._layer_widgets):
                w.config(text=f"{i+1}. {SUPPORTED_SYMMETRIC[self._cascade_order[i]]}")
                w.pack(before=w)
            self._layer_inner.update_idletasks()

    def _on_layer_release(self, event) -> None:
        self._drag_src = None

    def _get_layer_at(self, y: int):
        for w in reversed(self._layer_widgets):
            try:
                yy = w.winfo_y()
                hh = w.winfo_height()
                if yy <= y <= yy + hh:
                    return w
            except tk.TclError:
                pass
        return None

    def _show_layer_pw_dialog(self) -> None:
        if not self._cascade_order:
            messagebox.showwarning("提示", "请先添加加密层")
            return
        pw_win = tk.Toplevel(self)
        pw_win.title("层密码配置")
        pw_win.geometry("420x320")
        pw_win.configure(bg="#1e1e1e")
        tk.Label(pw_win, text="为每层设置独立密码（留空则使用主密码）",
                 font=("Microsoft YaHei UI", 10), fg="#ce9178",
                 bg="#1e1e1e").pack(pady=8)
        self._layer_pw_vars: list = []
        for i, idx in enumerate(self._cascade_order):
            algo = SUPPORTED_SYMMETRIC[idx]
            row = tk.Frame(pw_win, bg="#1e1e1e")
            row.pack(fill="x", padx=16, pady=4)
            tk.Label(row, text=f"层{i+1} ({algo}):", font=("Microsoft YaHei UI", 9),
                     fg="#d4d4d4", bg="#1e1e1e", width=20).pack(side="left")
            var = tk.StringVar()
            tk.Entry(row, textvariable=var, show="*", width=20).pack(side="left", padx=4)
            self._layer_pw_vars.append(var)
        tk.Button(pw_win, text="确定", command=pw_win.destroy,
                  bg="#4caf50", fg="#fff", font=("Microsoft YaHei UI", 10)).pack(pady=12)

    def _clear_cascade(self) -> None:
        self._cascade_input.delete("1.0", "end")
        self._cascade_output.delete("1.0", "end")

    def _do_cascade_encrypt(self) -> None:
        try:
            password = self._cascade_password.get()
            if not password:
                messagebox.showerror("错误", "请输入密码")
                return
            data = self._cascade_input.get("1.0", "end-1c").encode()
            if not data:
                messagebox.showerror("错误", "请输入要加密的内容")
                return
            layers = [SUPPORTED_SYMMETRIC[i] for i in self._cascade_order]
            if not layers:
                messagebox.showerror("错误", "请至少选择一种算法")
                return
            ce = CascadeEngine(algorithms=layers)
            result = ce.encrypt(data, password=password)
            self._cascade_output.delete("1.0", "end")
            self._cascade_output.insert("1.0", base64.b64encode(result).decode())
        except Exception as exc:
            messagebox.showerror("错误", str(exc))

    def _do_cascade_decrypt(self) -> None:
        try:
            password = self._cascade_password.get()
            if not password:
                messagebox.showerror("错误", "请输入密码")
                return
            data_b64 = self._cascade_input.get("1.0", "end-1c").strip()
            if not data_b64:
                messagebox.showerror("错误", "请输入要解密的内容")
                return
            ce = CascadeEngine()
            result = ce.decrypt(base64.b64decode(data_b64), password=password)
            self._cascade_output.delete("1.0", "end")
            self._cascade_output.insert("1.0", result.decode())
        except Exception as exc:
            messagebox.showerror("错误", str(exc))

    @staticmethod
    def run() -> None:
        try:
            cfg = load_config()
            logger.info("配置加载成功 (来源: %s)", cfg.source_path or "内置默认")
        except Exception as exc:
            logger.warning("配置加载失败，使用内置默认: %s", exc)

        try:
            anti_debug_guard(enabled=False)
        except Exception:
            pass  # 反调试仅在发布构建中启用

        app = BaseApp()
        app.mainloop()

    def _build_抗量子签名(self, frame: tk.Frame) -> None:
        """抗量子签名模块"""
        body = tk.Frame(frame, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        tk.Label(body, text="抗量子签名", font=("Microsoft YaHei UI", 13, "bold"),
                 fg="#ce9178", bg="#1e1e1e").pack(anchor="w")
        row1 = tk.Frame(body, bg="#1e1e1e")
        row1.pack(fill="x", pady=8)
        tk.Label(row1, text="算法：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(side="left")
        self._pq_algo_var = tk.StringVar(value="ML-DSA-87")
        ttk.Combobox(row1, textvariable=self._pq_algo_var,
                     values=SUPPORTED_PQ, width=15).pack(side="left", padx=8)
        self._pq_input = scrolledtext.ScrolledText(body, width=60, height=6,
                                                  bg="#252526", fg="#d4d4d4",
                                                  font=("Consolas", 10))
        self._pq_input.pack(fill="both", expand=True, pady=8)
        btn_frame = tk.Frame(body, bg="#1e1e1e")
        btn_frame.pack(fill="x", pady=8)
        tk.Button(btn_frame, text="生成密钥对", command=self._do_pq_genkey,
                  bg="#4caf50", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=12).pack(side="left", padx=8)
        tk.Button(btn_frame, text="签名", command=self._do_pq_sign,
                  bg="#2196f3", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Button(btn_frame, text="验证", command=self._do_pq_verify,
                  bg="#ff9800", fg="#fff", font=("Microsoft YaHei UI", 10),
                  width=10).pack(side="left", padx=8)
        tk.Label(body, text="输出：", font=("Microsoft YaHei UI", 9),
                 fg="#d4d4d4", bg="#1e1e1e").pack(anchor="w", pady=(8, 0))
        self._pq_output = scrolledtext.ScrolledText(body, width=60, height=6,
                                                   bg="#252526", fg="#6a9955",
                                                   font=("Consolas", 10))
        self._pq_output.pack(fill="both", expand=True, pady=8)
        self._pq_sk_var = tk.StringVar(value="")

    def _do_pq_genkey(self) -> None:
        try:
            pq = PQSignatureEngine(self._pq_algo_var.get())
            pk, sk = pq.generate_keypair()
            self._pq_sk_var.set(base64.b64encode(sk).decode())
            self._pq_output.delete("1.0", "end")
            self._pq_output.insert("1.0", f"公钥长度: {len(pk)} 字节\n私钥已生成（Base64）")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))

    def _do_pq_sign(self) -> None:
        try:
            sk_b64 = self._pq_sk_var.get()
            if not sk_b64:
                messagebox.showwarning("提示", "请先生成密钥对")
                return
            message = self._pq_input.get("1.0", "end-1c").encode()
            if not message:
                messagebox.showerror("错误", "请输入要签名的内容")
                return
            pq = PQSignatureEngine(self._pq_algo_var.get())
            bundle = pq.sign(base64.b64decode(sk_b64), message)
            self._pq_output.delete("1.0", "end")
            self._pq_output.insert("1.0", f"签名长度: {len(bundle.signature)} 字节\n算法: {bundle.algorithm}")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))

    def _do_pq_verify(self) -> None:
        try:
            msg = self._pq_input.get("1.0", "end-1c").encode()
            if not msg:
                messagebox.showerror("错误", "请输入要验证的内容")
                return
            messagebox.showinfo("提示", "请在完整版本中使用签名包进行验证")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))


# ======================================================================
#  ttkbootstrap 增强版（可选，仅在已安装时启用）
# ======================================================================
def _try_boosted_app() -> bool:
    if tb is None:
        return False
    try:
        class BoostedApp(tb.Window):
            def __init__(self) -> None:
                super().__init__(themename="darkly")
                self.title("CipherForge 工具箱 v1.0")
                self.geometry("960x640")
                self.minsize(800, 540)

                top = ttk.Frame(self)
                top.pack(fill="x", padx=12, pady=8)
                ttk.Label(top, text="CipherForge",
                          font=("Microsoft YaHei UI", 16, "bold")).pack(side="left")
                ttk.Label(top, text="  桌面密码学工具箱",
                          font=("Microsoft YaHei UI", 9)).pack(side="left")

                self.tabs = ttk.Notebook(self)
                self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 8))
                for name in MODULE_NAMES:
                    f = ttk.Frame(self.tabs)
                    self.tabs.add(f, text=name)
                    ttk.Label(f, text=f"{name} 模块（ttkbootstrap 增强版）",
                              font=("Microsoft YaHei UI", 11)).place(relx=0.05, rely=0.1)
                self.tabs.select(0)

                status = ttk.Frame(self, bootstyle="primary", height=24)
                status.pack(fill="x", side="bottom")
                ttk.Label(status, text="就绪 | CipherForge v1.0",
                          font=("Consolas", 8)).pack(side="left", padx=8)
                ttk.Label(status, text="安全模式",
                          font=("Consolas", 8)).pack(side="right", padx=8)

        app = BoostedApp()
        app.mainloop()
        return True
    except Exception as exc:
        logger.error("ttkbootstrap 增强版启动失败: %s", exc)
        return False


# ======================================================================
#  入口点
# ======================================================================
def main() -> None:
    if not _try_boosted_app():
        BaseApp.run()


if __name__ == "__main__":
    main()


