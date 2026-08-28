/* CipherForge Web 前端逻辑 */

const API_BASE = window.location.origin;
let currentModule = "encrypt";

// 模块切换
function switchModule(name) {
    currentModule = name;
    document.querySelectorAll(".module").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".nav-btn").forEach(el => el.classList.remove("active"));
    const moduleEl = document.getElementById(name + "Module");
    const navBtn = document.querySelector('[data-module="' + name + '"]');
    if (moduleEl) moduleEl.classList.add("active");
    if (navBtn) navBtn.classList.add("active");
}

// 密码显示切换
function togglePassword(id) {
    const input = document.getElementById(id);
    input.type = input.type === "password" ? "text" : "password";
}

// 复制结果
function copyResult(id) {
    const text = document.getElementById(id).textContent;
    navigator.clipboard.writeText(text).then(() => showToast("已复制到剪贴板", "success"));
}

// Toast 通知
function showToast(message, type = "success") {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = "toast " + type;
    const icon = type === "success" ? "✓" : type === "error" ? "✗" : "⚠";
    toast.innerHTML = "<span>" + icon + "</span> " + message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

// API 请求封装
async function apiRequest(endpoint, data) {
    try {
        const resp = await fetch(API_BASE + endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });
        const json = await resp.json();
        if (!resp.ok) throw new Error(json.detail || "请求失败");
        return json;
    } catch (err) {
        showToast(err.message, "error");
        throw err;
    }
}

// 主题切换
function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const newTheme = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('cipherforge-theme', newTheme);
}

// 使用说明弹窗
function openHelp() {
    document.getElementById('helpModal').classList.add('active');
}

function closeHelp() {
    document.getElementById('helpModal').classList.remove('active');
}

// 帮助标签页切换
function switchHelpTab(tab) {
    document.querySelectorAll('.help-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.help-panel').forEach(p => p.classList.remove('active'));
    document.querySelector('[data-tab="' + tab + '"]').classList.add('active');
    document.getElementById('helpPanel-' + tab).classList.add('active');
}

// 加密操作
async function doEncrypt() {
    const algo = document.getElementById("encAlgo").value;
    const plaintext = document.getElementById("encInput").value.trim();
    const password = document.getElementById("encPassword").value;
    if (!plaintext) { showToast("请输入明文", "warning"); return; }
    if (!password) { showToast("请输入密码", "warning"); return; }
    try {
        const result = await apiRequest("/api/encrypt", { algorithm: algo, password, plaintext });
        document.getElementById("encCiphertext").textContent = result.ciphertext_b64;
        document.getElementById("encNonce").textContent = result.nonce_b64;
        document.getElementById("encTag").textContent = result.tag_b64;
        document.getElementById("encResult").style.display = "block";
        showToast("加密成功", "success");
    } catch (e) {}
}

// 解密操作
async function doDecrypt() {
    const algo = document.getElementById("decAlgo").value;
    const ciphertext = document.getElementById("decCiphertext").value.trim();
    const nonce = document.getElementById("decNonce").value.trim();
    const tag = document.getElementById("decTag").value.trim();
    const password = document.getElementById("decPassword").value;
    if (!ciphertext || !nonce || !tag || !password) { showToast("请填写所有字段", "warning"); return; }
    try {
        const result = await apiRequest("/api/decrypt", { algorithm: algo, password, ciphertext_b64: ciphertext, nonce_b64: nonce, tag_b64: tag });
        document.getElementById("decPlaintext").textContent = result.plaintext;
        document.getElementById("decResult").style.display = "block";
        showToast("解密成功", "success");
    } catch (e) {}
}

// 哈希计算
async function doHash() {
    const algo = document.getElementById("hashAlgo").value;
    const data = document.getElementById("hashInput").value.trim();
    if (!data) { showToast("请输入数据", "warning"); return; }
    try {
        const result = await apiRequest("/api/hash", { algorithm: algo, data });
        document.getElementById("hashHex").textContent = result.hex_digest;
        document.getElementById("hashB64").textContent = result.b64_digest;
        document.getElementById("hashResult").style.display = "block";
        showToast("哈希计算完成", "success");
    } catch (e) {}
}

// 级联加密
async function doCascadeEncrypt() {
    const layers = Array.from(document.querySelectorAll('#cascadeModule .layer-item input:checked'))
                        .map(cb => cb.value);
    const data = document.getElementById("cascadeInput").value.trim();
    const password = document.getElementById("cascadePassword").value;
    if (layers.length === 0) { showToast("请选择至少一个算法层", "warning"); return; }
    if (!data) { showToast("请输入明文", "warning"); return; }
    if (!password) { showToast("请输入密码", "warning"); return; }
    try {
        const result = await apiRequest("/api/cascade-encrypt", { layers, password, data });
        document.getElementById("cascadeCiphertext").textContent = result.ciphertext_b64;
        document.getElementById("cascadeEncResult").style.display = "block";
        showToast(`级联加密成功 (${layers.length} 层)`, "success");
    } catch (e) {}
}

// 级联解密
async function doCascadeDecrypt() {
    const layers = Array.from(document.querySelectorAll('#cascadeModule .layer-item input:checked'))
                        .map(cb => cb.value);
    const ciphertext = document.getElementById("cascadeDecInput").value.trim();
    const password = document.getElementById("cascadePassword").value;
    if (layers.length === 0) { showToast("请选择至少一个算法层", "warning"); return; }
    if (!ciphertext) { showToast("请粘贴密文", "warning"); return; }
    if (!password) { showToast("请输入密码", "warning"); return; }
    try {
        const result = await apiRequest("/api/cascade-decrypt", { layers, password, data: ciphertext });
        document.getElementById("cascadePlaintext").textContent = result.plaintext;
        document.getElementById("cascadeDecResult").style.display = "block";
        showToast(`级联解密成功 (${layers.length} 层)`, "success");
    } catch (e) {}
}

// 密码生成
async function doGeneratePassword() {
    const length = parseInt(document.getElementById("pwLength").value);
    const exclude = document.getElementById("pwExclude").checked;
    const mode = document.getElementById("pwMode").value;
    const words = parseInt(document.getElementById("pwWords").value);
    try {
        const result = await apiRequest("/api/generate-password", { length, exclude_ambiguous: exclude, passphrase: mode === "passphrase", words });
        document.getElementById("pwPassword").textContent = result.password;
        document.getElementById("pwEntropy").textContent = result.entropy_bits;
        const strengthEl = document.getElementById("pwStrength");
        strengthEl.textContent = result.strength;
        strengthEl.className = "strength-badge " + result.strength;
        document.getElementById("pwResult").style.display = "block";
        showToast("密码生成成功", "success");
    } catch (e) {}
}

// 层密码管理
function updateLayerPasswords() {
    const checkboxes = document.querySelectorAll('#cascadeModule .layer-selector input[type="checkbox"]:checked');
    const container = document.getElementById('layerPasswordContainer');
    container.innerHTML = '';
    checkboxes.forEach((cb, idx) => {
        const div = document.createElement('div');
        div.className = 'layer-pw-row';
        div.innerHTML = `<span class="layer-pw-label">${cb.value}</span><input type="password" class="form-input layer-pw-input" data-idx="${idx}" placeholder="该层密码（可选）">`;
        container.appendChild(div);
    });
}

// 监听算法选择变化

document.addEventListener('DOMContentLoaded', function() {
    // 导航按钮点击事件
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const module = this.getAttribute('data-module');
            switchModule(module);
        });
    });

    // 主题切换
    const savedTheme = localStorage.getItem('cipherforge-theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);

    document.getElementById('themeToggle').addEventListener('click', toggleTheme);
    document.getElementById('helpBtn').addEventListener('click', openHelp);
    document.getElementById('helpModalClose').addEventListener('click', closeHelp);
    document.getElementById('helpModal').addEventListener('click', function(e) {
        if (e.target === this) closeHelp();
    });
    // 帮助标签页
    document.querySelectorAll('.help-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            switchHelpTab(this.getAttribute('data-tab'));
        });
    });

    switchModule("encrypt");
    fetch("/health")
        .then(function(r) { return r.json(); })
        .then(function() {
            document.querySelector(".status-dot").className = "status-dot online";
            document.querySelector(".status-text").textContent = "已连接";
        })
        .catch(function() {
            document.querySelector(".status-dot").className = "status-dot offline";
            document.querySelector(".status-text").textContent = "未连接";
        });

    // 监听层选择变化
    document.querySelectorAll('#cascadeModule .layer-selector input[type="checkbox"]').forEach(cb => {
        cb.addEventListener('change', updateLayerPasswords);
    });
    // 初始化
    updateLayerPasswords();
});

// LSB 隐写 - 隐藏
async function doStegHide() {
    const payload = document.getElementById("stegInput").value;
    const password = document.getElementById("stegPassword").value;
    if (!payload || !password) { showToast("请输入数据和密码", "warning"); return; }
    showToast("注意: LSB 隐写需要后端支持，当前为演示模式", "warning");
    document.getElementById("stegOutput").textContent = "此功能需要后端实现。请查看 CipherForge GUI 或 CLI 版本。";
    document.getElementById("stegResult").style.display = "block";
}

// LSB 隐写 - 提取
async function doStegReveal() {
    const password = document.getElementById("stegPassword").value;
    if (!password) { showToast("请输入密码", "warning"); return; }
    showToast("注意: LSB 隐写需要后端支持，当前为演示模式", "warning");
    document.getElementById("stegOutput").textContent = "此功能需要后端实现。请查看 CipherForge GUI 或 CLI 版本。";
    document.getElementById("stegResult").style.display = "block";
}

// 抗量子签名 - 生成密钥对
async function doPQKeygen() {
    const algo = document.getElementById("pqAlgo").value;
    try {
        const result = await apiRequest("/api/pq-keygen", { algorithm: algo });
        document.getElementById("publicKey").value = result.public_key_b64;
        document.getElementById("privateKey").value = result.private_key_b64;
        document.getElementById("pkContainer").style.display = "block";
        document.getElementById("skContainer").style.display = "block";
        document.getElementById("pqOutput").textContent = `算法: ${result.algorithm}\n公钥长度: ${result.public_key_b64.length} 字符\n私钥已生成（请妥善保管）`;
        document.getElementById("pqResult").style.display = "block";
        showToast("密钥对生成成功", "success");
    } catch (e) {
        const msg = e.message || "未知错误";
        // 只保留核心错误信息，去掉冗余提示
        const cleanMsg = msg.replace(/\n→ 建议：.*$/s, '').replace(/\n提示：.*$/s, '');
        document.getElementById("pqOutput").textContent = "错误: " + cleanMsg;
        document.getElementById("pqResult").style.display = "block";
    }
}

// 抗量子签名 - 签名
async function doPQSign() {
    const algo = document.getElementById("pqAlgo").value;
    const message = document.getElementById("pqMessage").value;
    const sk = document.getElementById("privateKey").value;
    const pk = document.getElementById("publicKey").value;
    if (!sk) { showToast("请先生成密钥对", "warning"); return; }
    if (!message) { showToast("请输入消息", "warning"); return; }
    try {
        const result = await apiRequest("/api/pq-sign", { algorithm: algo, private_key_b64: sk, public_key_b64: pk, message });
        document.getElementById("pqOutput").textContent = `算法: ${result.algorithm}\n签名长度: ${result.signature_b64.length} 字符`;
        document.getElementById("pqResult").style.display = "block";
        // 保存签名到全局变量供验证使用
        window._pqSignature = result.signature_b64;
        showToast("签名成功", "success");
    } catch (e) {
        const msg = e.message || "未知错误";
        const cleanMsg = msg.replace(/\n→ 建议：.*$/s, '').replace(/\n提示：.*$/s, '');
        document.getElementById("pqOutput").textContent = "错误: " + cleanMsg;
        document.getElementById("pqResult").style.display = "block";
    }
}

// 抗量子签名 - 验证
async function doPQVerify() {
    const algo = document.getElementById("pqAlgo").value;
    const message = document.getElementById("pqMessage").value;
    const pk = document.getElementById("publicKey").value;
    const sig = window._pqSignature || "";
    if (!pk) { showToast("请先生成密钥对", "warning"); return; }
    if (!message) { showToast("请输入消息", "warning"); return; }
    if (!sig) { showToast("请先进行签名操作", "warning"); return; }
    try {
        const result = await apiRequest("/api/pq-verify", { algorithm: algo, public_key_b64: pk, message, signature_b64: sig });
        document.getElementById("pqOutput").textContent = result.valid ? "✓ 签名有效" : "✗ 签名无效";
        document.getElementById("pqResult").style.display = "block";
        showToast(result.valid ? "验证通过" : "验证失败", result.valid ? "success" : "error");
    } catch (e) {
        const msg = e.message || "未知错误";
        const cleanMsg = msg.replace(/\n→ 建议：.*$/s, '').replace(/\n提示：.*$/s, '');
        document.getElementById("pqOutput").textContent = "错误: " + cleanMsg;
        document.getElementById("pqResult").style.display = "block";
    }
}

// Shamir 分片
async function doShamirSplit() {
    const threshold = parseInt(document.getElementById("shamirThreshold").value);
    const total = parseInt(document.getElementById("shamirTotal").value);
    const secret = document.getElementById("shamirSecret").value.trim();
    if (!secret) { showToast("请输入秘密数据", "warning"); return; }
    if (threshold > total) { showToast("阈值不能大于总分片数", "warning"); return; }
    try {
        const result = await apiRequest("/api/shamir-split", { secret, threshold, total_shares: total });
        const sharesList = document.getElementById("shamirSharesList");
        sharesList.innerHTML = '';
        result.shares.forEach((share, idx) => {
            const div = document.createElement('div');
            div.className = 'share-item';
            div.innerHTML = `<span class="share-label">分片 ${idx + 1}</span><code class="share-code">${share}</code>`;
            sharesList.appendChild(div);
        });
        document.getElementById("shamirSplitResult").style.display = "block";
        showToast(`成功生成 ${result.total} 个分片（需 ${result.threshold} 份恢复）`, "success");
    } catch (e) {
        showToast(e.message, "error");
    }
}

// Shamir 合并
async function doShamirCombine() {
    const sharesText = document.getElementById("shamirSharesInput").value.trim();
    if (!sharesText) { showToast("请输入分片数据", "warning"); return; }
    const shares = sharesText.split('\n').map(s => s.trim()).filter(s => s);
    if (shares.length < 2) { showToast("至少需要 2 个分片", "warning"); return; }
    try {
        const result = await apiRequest("/api/shamir-combine", { shares });
        document.getElementById("shamirRecovered").textContent = result.secret;
        document.getElementById("shamirCombineResult").style.display = "block";
        showToast("秘密恢复成功", "success");
    } catch (e) {
        showToast(e.message, "error");
    }
}
