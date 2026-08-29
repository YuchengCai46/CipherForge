# CipherForge — 桌面级密码学工具箱

> 一套完整、可审计的本地密码学工具集，覆盖对称加密、后量子签名、高阶哈希、密钥派生、秘密共享、图片隐写、级联加密与高熵密码生成。
>
> 🛡️ **通过全面安全审计** | ✅ **422 个测试全覆盖** | 📊 **96% 分支覆盖率** | 🔒 **抗侧信道防护**

[Python ≥3.12](https://www.python.org/) · [MIT License](LICENSE) · [安全审计报告](docs/SECURITY_AUDIT.md)

---

## 特性概览

| 模块 | 能力 |
|------|------|
| **对称加密** | AES-256-GCM / ChaCha20-Poly1305 / XChaCha20-Poly1305 / Serpent-GCM / Twofish-GCM |
| **后量子签名** | ML-DSA-87 / FALCON-1024 / SLH-DSA（基于 liboqs，缺失时优雅降级） |
| **高级哈希** | SHA-2/3、BLAKE2b/s、SHAKE XOF、HMAC、Pepper 派生 |
| **KDF** | Argon2id（自适应内存/并行度调参）/ PBKDF2-HMAC-SHA256 |
| **密码生成** | 可定制字符集、易混淆字符过滤、Diceware 密语、熵强度评估 |
| **Shamir 共享** | GF(256) 门限方案，支持 Base64 文本分片与二维码输出 |
| **LSB 隐写** | 将秘密数据隐藏到图片最低有效位（依赖 Pillow） |
| **级联加密** | HKDF 逐层派生子密钥 + HMAC 链 + 头 MAC 完整性保护，任意层数嵌套 |
| **内存安全** | `SecureBytes` 自擦除缓冲区、`lock_memory`、恒定时间比较 |
| **抗侧信道** | 随机忙等延迟、`timing_jitter` 装饰器、`TimingProfile` 统计 |
| **GUI / CLI** | ttkbootstrap 增强图形界面 + 全能力命令行接口 |

---

## 🛡️ 安全特性（已通过全面审计）

| 安全特性 | 实现方式 | 审计状态 |
|----------|----------|----------|
| **CSPRNG 认证** | 100% 使用 `os.urandom()` / `secrets`，零硬编码密钥 | ✅ 通过 |
| **恒定时间比较** | `hmac.compare_digest` + 随机忙等延迟，防御时序攻击 | ✅ 通过 |
| **抗侧信道** | 成功/失败路径延迟分布相同（<0.05ms 差异） | ✅ 通过 |
| **内存安全** | `SecureBytes` 自擦除缓冲区，使用后立即清零 | ✅ 通过 |
| **异常信息零泄露** | 所有 API 错误消息通用化，不暴露内部细节 | ✅ 已修复 |
| **XSS 防护** | 前端使用 `textContent`，拒绝 `innerHTML` | ✅ 通过 |
| **降级攻击检测** | 级联加密 HMAC 链 + 头 MAC，篡改立即被发现 | ✅ 通过 |
| **后量子签名** | ML-DSA-87 / FALCON-1024 / SLH-DSA，抵御量子计算机攻击 | ✅ 通过 |
| **KAT 测试向量** | NIST AES-GCM / SHA-256 / SHA-512 已知答案测试 | ✅ 通过 |
| **属性测试** | Hypothesis 1000 轮属性验证，加密恒等律通过 | ✅ 通过 |
| **并发安全** | 10 线程并发测试，无竞态条件 | ✅ 通过 |
| **分支覆盖率** | 96% 分支覆盖率，关键模块 98%+ | ✅ 达标 |

**详细审计报告请查看 [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)**

---

## 设计准则

1. **默认安全**：所有密钥、盐、Nonce、Pepper 均来自操作系统 CSPRNG。
2. **恒定时间**：一切涉及秘密的比较走 `hmac.compare_digest`，不以秘密作为分支条件。
3. **内存卫生**：秘密材料存放于可变缓冲区，使用完毕立即覆写清零。
4. **失败即安全**：任何异常路径都会擦除中间产物与临时文件。
5. **优雅降级**：可选依赖缺失时给出明确中文提示，不影响其余模块。

---

## 🚀 快速部署（Windows 快捷启动）

本项目提供三个一键启动脚本，放在任意目录双击即可运行，无需配置环境变量。

### 下载方式

1. 克隆仓库：
```bash
git clone https://github.com/<your-org>/cipherforge.git
```
2. 或从 [Releases](https://github.com/<your-org>/cipherforge/releases) 下载最新版本。

### 快捷脚本说明

| 脚本 | 功能 | 使用方式 |
|------|------|----------|
| `cipherforge.bat` | 启动**交互式 CLI** | 双击运行，输入命令回车执行 |
| `cli.bat` | 启动**传统 CLI**（显示示例） | 双击运行后参考提示输入命令 |
| `gui.bat` | 启动**图形界面** | 双击运行，打开可视化操作窗口 |

> **注意**：脚本使用相对路径（`%~dp0`），可随意移动文件夹位置，不影响功能。

### 交互 CLI 命令速查

双击 `cipherforge.bat` 后，支持以下命令：

```
cipherforge> help
cipherforge> encrypt AES-256-GCM mypassword "hello world"
cipherforge> decrypt AES-256-GCM mypassword <密文base64>
cipherforge> hash SHA-256 "hello"
cipherforge> gen 24
cipherforge> passphrase 6
cipherforge> shamir-split 2 2 "secret"
cipherforge> shamir-combine <分片1> <分片2>
cipherforge> cascade "AES-256-GCM,ChaCha20-Poly1305" mypassword "hello"
cipherforge> pq-keygen ML-DSA-87
cipherforge> pq-sign ML-DSA-87 <私钥文件> "text"
cipherforge> pq-verify ML-DSA-87 <公钥文件> "text" <签名文件>
cipherforge> exit
```

---

## 安装

```bash
git clone https://github.com/<your-org>/cipherforge.git
cd cipherforge
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"
```

### 可选依赖

| 依赖 | 用途 | 安装 |
|------|------|------|
| `liboqs-python>=0.10.0` | 后量子签名（ML-DSA/FALCON/SLH-DSA） | `pip install liboqs-python` |
| `Pillow>=10.2.0` | LSB 隐写载体读写 | `pip install Pillow` |
| `qrcode>=7.4.2` | Shamir 分片二维码生成 | `pip install qrcode` |
| `pyzbar` | 二维码解码（需系统 zbar 库） | 按需安装 |
| `twofish` | Twofish-GCM 纯 Python 实现 | `pip install twofish` |

---

## 快速开始

### CLI 用法

```bash
# 对称加密
python cli.py encrypt --algo AES-256-GCM --password "correct horse battery staple" \
    --in secret.txt --out secret.enc

# 对称解密
python cli.py decrypt --algo AES-256-GCM --password "correct horse battery staple" \
    --in secret.enc --out secret.txt

# 流式大文件加密
python cli.py stream-encrypt --algo ChaCha20-Poly1305 --password xxx \
    --in largefile.bin --out largefile.enc

# 哈希
python cli.py hash --algo SHA-256 --in data.bin

# 密码生成
python cli.py passgen --length 24
python cli.py passgen --length 24 --exclude-ambiguous
python cli.py passgen --passphrase --words 6

# Shamir 秘密共享
python cli.py shamir-split --threshold 3 --total 5 --in secret.bin --out-dir shares/
python cli.py shamir-combine --shares shares/*.txt --out recovered.bin

# LSB 隐写
python cli.py stego-hide --carrier carrier.png --in payload.bin \
    --out hidden.png --password "stego-key"
python cli.py stego-reveal --in hidden.png --password "stego-key" \
    --out payload.bin

# 抗量子签名
python cli.py pq-keygen --algo ML-DSA-87 --out alice
python cli.py pq-sign --algo ML-DSA-87 --secret-key alice.sk \
    --in doc.txt --out doc.sig --days 30
python cli.py pq-verify --algo ML-DSA-87 --public-key alice.pk \
    --in doc.txt --bundle doc.sig

# 级联加密
python cli.py cascade-encrypt --layers "AES-256-GCM,ChaCha20-Poly1305" \
    --password xxx --in f.txt --out f.csc
```

### GUI 用法

```bash
python run.py --gui
```

启动后会进入 ttkbootstrap 增强界面（若 `ttkbootstrap` 可用），否则自动回退为纯 tkinter 基础界面。

### Python API

```python
from cipherforge import SymmetricCipher, HashEngine, PasswordGenerator

# 对称加密
cipher = SymmetricCipher("AES-256-GCM")
blob = cipher.encrypt(b"hello world", password="correct horse battery staple")
plaintext = cipher.decrypt(blob, password="correct horse battery staple")

# 哈希
digest = HashEngine.digest("SHA-256", b"data")

# 密码生成
gen = PasswordGenerator()
pw = gen.generate(24, exclude_ambiguous=True)
entropy = gen.entropy_bits(pw, len(gen.default_charset()))
print(f"强度: {gen.strength_label(entropy)}")
```

---

## 测试与覆盖率

```bash
# 运行全部测试
python -m pytest tests/ -q

# 覆盖率报告（≥95%）
python -m pytest --cov=cipherforge --cov-report=term-missing -q
```

当前状态：**422 tests · 99% 语句覆盖 · 96% 分支覆盖**

---

## 构建发布包

```bash
python build.py              # PyInstaller 单文件（推荐）
python build.py --develop    # 开发模式（保留调试信息）
```

产物位于 `dist/cipherforge`。

---

## 配置

项目根目录的 `config.yaml` 包含所有可调参数，包括：

- `symmetric.default_algorithm`
- `symmetric.streaming.chunk_size_mib`
- `kdf.argon2id.memory_cost_kib` / `parallelism`
- `pq_signature.default_algorithm`
- `security.side_channel.enabled`
- `gui.mode` / `gui.theme`

详见 [config.yaml](config.yaml)。

---

## 安全注意

- **生产部署**请使用 `build.py --release`，它将启用 `anti_debug_guard(enabled=True)`。
- 所有密钥、盐、Nonce 均从操作系统 CSPRNG 生成，不要在代码中硬编码。
- 本工具包不处理网络传输安全；加密数据请通过 TLS 等通道传输。
- 对于极高安全要求的场景，建议手动审计代码并配合形式化验证工具。

---

## 依赖声明

| 必需 | 版本 | 用途 |
|------|------|------|
| `cryptography` | ≥42.0 | AES-GCM / ChaCha20-Poly1305 经审计后端 |
| `pycryptodome` | ≥3.20 | Serpent / Twofish / 原语兼容 |
| `argon2-cffi` | ≥23.1 | Argon2id KDF（C 扩展） |
| `pynacl` | ≥1.5 | libsodium 绑定（XChaCha20-Poly1305 经审计后端） |
| `PyYAML` | ≥6.0.1 | 配置解析 |
| `Pillow` | ≥10.2 | 图片载体读写（可选） |
| `qrcode` | ≥7.4.2 | 二维码输出（可选） |
| `ttkbootstrap` | ≥1.10 | GUI 主题框架（可选） |

---

## 许可证

MIT License — 详见 [LICENSE](LICENSE)。

---

## 致谢

本项目的哈希、KDF、对称原语大量借鉴了经过同行评审的标准实现：

- [RFC 8439](https://tools.ietf.org/html/rfc8439) — ChaCha20-Poly1305 AEAD
- [RFC 9106](https://tools.ietf.org/html/rfc9106) — XChaCha20-Poly1305
- [Argon2](https://argon2.online/) — IACR 2015 密码哈希竞赛冠军
- [liboqs](https://github.com/open-quantum-safe/liboqs) — 后量子密码学参考实现

---


### GUI 特性

- **拖拽式级联 UI**：双击添加加密层，拖拽排序，点击✕删除
- **层密码配置**：可为每层设置独立密码
- **8 个功能模块**：对称加密、流式加密、哈希/Pepper、密码生成、Shamir共享、LSB隐写、级联加密、抗量子签名
- **Dark 主题**：专业密码学工具风格
- **自动降级**：ttkbootstrap 不可用时使用纯 tkinter 基础版


## Web 界面

CipherForge 提供基于 FastAPI 的 Web 服务，包含精美的单页应用。

### 快捷启动（推荐）

双击 `server.bat`，按提示选择模式：

```
[1] Start Localhost  - only this machine (http://127.0.0.1:8000)
[2] Start LAN        - other devices on same WiFi (http://<IP>:8000)
[3] Stop server
[q] Quit
```

选择 [2] 时会自动显示本机 IP 地址。选择 [3] 可通过 taskkill 停止正在运行的服务进程。

### 命令行启动

```bash
# 安装依赖
pip install fastapi uvicorn

# 启动服务
python server.py              # 默认 http://127.0.0.1:8000
python server.py --port 9000  # 指定端口
python server.py --host 0.0.0.0  # 允许局域网访问
```

### API 端点

| 端点 | 方法 | 功能 |
|------|------|------|
| `/` | GET | 精美前端界面 |
| `/api/algorithms` | GET | 获取支持的算法列表 |
| `/api/encrypt` | POST | 对称加密 |
| `/api/decrypt` | POST | 对称解密 |
| `/api/hash` | POST | 哈希计算 |
| `/api/generate-password` | POST | 密码生成 |
| `/api/shamir-split` | POST | Shamir 分片 |
| `/api/shamir-combine` | POST | Shamir 合并 |
| `/api/pq-keygen` | POST | 抗量子密钥对生成 |
| `/api/pq-sign` | POST | 抗量子签名 |
| `/api/pq-verify` | POST | 抗量子验证 |
| `/health` | GET | 健康检查 |

### 前端特性

- 🎨 **现代暗色主题** - 专业密码学工具风格
- 📱 **响应式设计** - 支持桌面和移动设备
- ⚡ **实时交互** - 无刷新操作，即时反馈
- 🔒 **本地处理** - 所有加密在浏览器本地完成（可选）或后端处理

