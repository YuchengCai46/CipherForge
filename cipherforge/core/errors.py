"""
友好中文异常体系
================

所有面向用户的错误都继承自 :class:`CipherForgeError`，并携带三段信息：

* ``message``   —— 一句话说明发生了什么（中文，可直接显示在界面上）
* ``hint``      —— 可执行的修复建议（中文，可选）
* ``detail``    —— 技术细节，供诊断报告使用（不面向普通用户）

**安全约束**：异常文本永不包含密钥、口令、Pepper 或明文片段。
构造异常时如需引用输入，只允许引用长度、类型、算法名等非敏感元数据。
"""

from __future__ import annotations

from typing import Any


class CipherForgeError(Exception):
    """CipherForge 所有业务异常的根类。"""

    #: 默认提示语，子类可覆盖
    default_hint: str = ""

    def __init__(
        self,
        message: str,
        *,
        hint: str = "",
        detail: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.hint = hint or self.default_hint
        self.detail = detail
        # context 只允许非敏感元数据（长度、算法名、文件名等）
        self.context: dict[str, Any] = dict(context or {})
        super().__init__(message)

    # ---------------------------------------------------------------- 展示
    def user_text(self) -> str:
        """返回适合直接呈现给用户的多行中文文本。"""
        lines = [f"✖ {self.message}"]
        if self.hint:
            lines.append(f"→ 建议：{self.hint}")
        return "\n".join(lines)

    def diagnostic_text(self) -> str:
        """返回用于诊断报告的完整文本（含技术细节）。"""
        lines = [f"[{type(self).__name__}] {self.message}"]
        if self.hint:
            lines.append(f"  建议: {self.hint}")
        if self.detail:
            lines.append(f"  细节: {self.detail}")
        for key, value in self.context.items():
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": type(self).__name__,
            "message": self.message,
            "hint": self.hint,
            "detail": self.detail,
            "context": self.context,
        }

    def __str__(self) -> str:  # pragma: no cover - 展示逻辑
        return self.user_text()


# ====================================================================
#  配置与环境
# ====================================================================
class ConfigError(CipherForgeError):
    """配置文件缺失、格式错误或取值越界。"""

    default_hint = "请检查 config.yaml 的对应字段，或删除该文件以恢复内置默认配置。"


class DependencyMissingError(CipherForgeError):
    """可选依赖未安装，对应功能不可用。"""

    default_hint = "请按 README.md『可选依赖』一节安装后重试。"

    def __init__(self, feature: str, package: str, *, install_cmd: str = "") -> None:
        cmd = install_cmd or f"pip install {package}"
        CipherForgeError.__init__(
            self,
            f"功能「{feature}」需要依赖 {package}，但当前环境未安装。",
            hint=f"执行：{cmd}",
            detail=f"feature={feature}, package={package}",
            context={"功能": feature, "缺失依赖": package},
        )


class UnsupportedAlgorithmError(CipherForgeError):
    """请求了不支持或拼写错误的算法名。"""

    default_hint = "请从受支持的算法列表中选择。"

    def __init__(self, name: str, supported: list[str] | tuple[str, ...] = ()) -> None:
        listed = "、".join(supported) if supported else "（无）"
        CipherForgeError.__init__(
            self,
            f"不支持的算法：{name}",
            hint=f"可用算法：{listed}",
            context={"请求算法": name},
        )


# ====================================================================
#  输入校验
# ====================================================================
class ValidationError(CipherForgeError):
    """用户输入不满足约束。"""

    default_hint = "请修正输入后重试。"


class EmptyInputError(ValidationError):
    """必填输入为空。"""

    def __init__(self, field: str) -> None:
        CipherForgeError.__init__(
            self,
            f"「{field}」不能为空。",
            hint="请填写该项后再执行。",
            context={"字段": field},
        )


class FileTooLargeError(ValidationError):
    """文件体积超出配置上限。"""

    def __init__(self, size_bytes: int, limit_bytes: int) -> None:
        CipherForgeError.__init__(
            self,
            f"文件体积 {size_bytes / 2**30:.2f} GiB 超出上限 "
            f"{limit_bytes / 2**30:.2f} GiB。",
            hint="可在 config.yaml 中调高 symmetric.streaming.max_file_size_gib。",
            context={"文件字节数": size_bytes, "上限字节数": limit_bytes},
        )


# ====================================================================
#  密码学运算
# ====================================================================
class CryptoError(CipherForgeError):
    """密码学运算失败的基类。"""


class DecryptionFailedError(CryptoError):
    """解密或认证失败。

    出于安全考虑，**不区分**「口令错误」与「数据被篡改」——
    两者返回完全相同的错误，避免为攻击者提供可区分的预言机。
    """

    default_hint = "请确认口令是否正确，以及文件在传输过程中未被修改或截断。"

    def __init__(self, detail: str = "", **context: Any) -> None:
        CipherForgeError.__init__(
            self,
            "解密失败：认证标签校验未通过。",
            hint=self.default_hint,
            detail=detail,
            context=context,
        )


class IntegrityError(CryptoError):
    """完整性校验失败（文件头、层间 Tag 链、分片校验和等）。"""

    default_hint = "数据可能已损坏或被篡改，请使用可信来源的副本重试。"


class DowngradeAttackError(IntegrityError):
    """检测到级联层被删除、重排或替换。"""

    def __init__(self, expected: int, actual: int) -> None:
        CipherForgeError.__init__(
            self,
            f"检测到降级攻击：文件头声明 {expected} 层级联，实际仅能验证 {actual} 层。",
            hint="该文件已被篡改，请勿使用其解密结果。",
            context={"声明层数": expected, "实际层数": actual},
        )


class SignatureError(CryptoError):
    """签名相关错误的基类。"""


class SignatureInvalidError(SignatureError):
    """签名验证不通过。"""

    default_hint = "请确认公钥与签名文件配对正确，且被签名内容未被修改。"

    def __init__(self, algorithm: str = "", detail: str = "") -> None:
        CipherForgeError.__init__(
            self,
            "签名验证失败：内容与签名不匹配。",
            hint=self.default_hint,
            detail=detail,
            context={"算法": algorithm} if algorithm else {},
        )


class SignatureExpiredError(SignatureError):
    """签名已过有效期。

    GUI 会将此异常渲染为**红色醒目文本**，与普通验签失败区分开来。
    """

    #: 供前端识别并使用红字样式
    render_style = "critical-red"
    default_hint = "该签名已超过设定的有效期，请向签名方索取新签名。"

    def __init__(self, signed_at: str, expires_at: str, now: str) -> None:
        CipherForgeError.__init__(
            self,
            f"签名已过期：有效期至 {expires_at}，当前时间 {now}。",
            hint=self.default_hint,
            detail=f"signed_at={signed_at}, expires_at={expires_at}, now={now}",
            context={"签名时间": signed_at, "过期时间": expires_at, "当前时间": now},
        )


class SignatureNotYetValidError(SignatureError):
    """签名时间戳位于未来，超出允许的时钟偏移。"""

    render_style = "critical-red"
    default_hint = "请检查本机系统时间是否准确，或联系签名方核对。"

    def __init__(self, signed_at: str, now: str) -> None:
        CipherForgeError.__init__(
            self,
            f"签名尚未生效：签名时间 {signed_at} 晚于当前时间 {now}。",
            hint=self.default_hint,
            context={"签名时间": signed_at, "当前时间": now},
        )


# ====================================================================
#  秘密共享
# ====================================================================
class SharingError(CipherForgeError):
    """Shamir 秘密共享错误。"""

    default_hint = "请检查分片数量与阈值设置。"


class InsufficientSharesError(SharingError):
    """提供的分片数量少于阈值。"""

    def __init__(self, provided: int, threshold: int) -> None:
        CipherForgeError.__init__(
            self,
            f"分片不足：需要至少 {threshold} 份，当前仅提供 {provided} 份。",
            hint=f"请再收集 {threshold - provided} 份分片。",
            context={"已提供": provided, "所需阈值": threshold},
        )


class ShareCorruptedError(SharingError):
    """分片校验和不匹配，可能是抄写错误。"""

    def __init__(self, index: int | str = "?") -> None:
        CipherForgeError.__init__(
            self,
            f"分片 #{index} 校验失败，内容可能在抄写或传输中出错。",
            hint="请逐字核对该分片，特别注意 0/O、1/l、5/S 等易混淆字符。",
            context={"分片编号": index},
        )


# ====================================================================
#  隐写
# ====================================================================
class SteganographyError(CipherForgeError):
    """隐写错误基类。"""


class CarrierTooSmallError(SteganographyError):
    """载体图片容量不足。"""

    def __init__(self, need_bytes: int, capacity_bytes: int, bit_depth: int) -> None:
        CipherForgeError.__init__(
            self,
            f"载体容量不足：需要 {need_bytes:,} 字节，"
            f"当前图片在 {bit_depth} 位深下仅可容纳 {capacity_bytes:,} 字节。",
            hint="请换用分辨率更高的图片，或提高位深（1→4，但隐蔽性会下降）。",
            context={
                "所需字节": need_bytes,
                "可用字节": capacity_bytes,
                "位深": bit_depth,
            },
        )


class NoHiddenDataError(SteganographyError):
    """在载体中找不到有效的隐写载荷。"""

    default_hint = "请确认这张图片确实由 CipherForge 生成，且口令与位深设置一致。"

    def __init__(self) -> None:
        CipherForgeError.__init__(
            self,
            "未在该图片中发现有效的隐藏数据。",
            hint=self.default_hint,
        )


# ====================================================================
#  运行时加固
# ====================================================================
class SecurityViolationError(CipherForgeError):
    """检测到运行环境存在安全威胁（如调试器附加）。"""

    default_hint = "请在无调试器的正常环境中运行本程序。"


__all__ = [
    "CipherForgeError",
    "ConfigError",
    "DependencyMissingError",
    "UnsupportedAlgorithmError",
    "ValidationError",
    "EmptyInputError",
    "FileTooLargeError",
    "CryptoError",
    "DecryptionFailedError",
    "IntegrityError",
    "DowngradeAttackError",
    "SignatureError",
    "SignatureInvalidError",
    "SignatureExpiredError",
    "SignatureNotYetValidError",
    "SharingError",
    "InsufficientSharesError",
    "ShareCorruptedError",
    "SteganographyError",
    "CarrierTooSmallError",
    "NoHiddenDataError",
    "SecurityViolationError",
]
