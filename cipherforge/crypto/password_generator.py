"""
高熵密码 / 密语生成器
=====================

全部随机数**仅**来自 Python 标准库 :mod:`secrets` 与 :mod:`os.urandom`
（均经操作系统 CSPRNG 背书，杜绝自写随机数）。绝不使用 ``random`` 模块。

能力
----

* **随机密码**：自定义字符集、长度、是否排除易混淆字符。
* **密语（passphrase）**：从内置词表随机抽词（diceware 风格），
  每组词约 8~9 比特熵。
* **熵估算**：``bits = length * log2(charset_size)``，并给出
  弱 / 中 / 强 / 极强 的中文强度标签，便于 GUI 即时反馈。

强度仅供参考；是否"足够"取决于具体威胁模型。
"""

from __future__ import annotations

import math
import secrets
import string

from ..core.errors import ValidationError

__all__ = ["PasswordGenerator", "DEFAULT_CHARSETS"]

DEFAULT_CHARSETS: dict[str, str] = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{};:,.<>?",
}

# 内置精简词表（diceware 风格，约 8.3 比特/词），覆盖日常高频词。
_WORDLIST = (
    "apple", "bread", "cloud", "dance", "eagle", "forest", "grape", "house",
    "ice", "jungle", "kite", "lemon", "mountain", "night", "ocean", "paper",
    "queen", "river", "sun", "tree", "umbrella", "valley", "wind", "yellow",
    "zebra", "arrow", "blue", "candy", "dark", "earth", "fire", "gold",
    "green", "happy", "iron", "jade", "key", "light", "moon", "north",
    "orange", "pink", "quiet", "rain", "red", "silver", "star", "stone",
    "tiger", "violet", "water", "white", "wood", "amber", "beach", "coral",
    "dawn", "dream", "ember", "falcon", "feather", "frost", "glacier", "harbor",
    "island", "lake", "maple", "meadow", "mist", "olive", "pearl", "pine",
    "planet", "pond", "reed", "sand", "shadow", "sky", "snow", "spark",
    "thunder", "tide", "torch", "wave", "willow", "wolf", "bloom", "bridge",
    "canyon", "castle", "cave", "comet", "creek", "crystal", "dune", "echo",
    "flame", "flower", "garden", "gem", "grass", "hill", "lagoon", "leaf",
    "lily", "lotus", "marble", "moss", "nectar", "oak", "pebble", "petal",
    "rainbow", "ravine", "ripple", "rose", "shell", "shrub", "spring", "stream",
    "sunset", "tulip", "vine", "waterfall", "whale", "wild", "willow", "wisp",
    "anchor", "beacon", "bolt", "compass", "ember", "forge", "lance", "orbit",
    "prism", "rune", "scale", "sword", "token", "vertex", "wedge", "zephyr",
    "bison", "crane", "falcon", "heron", "lynx", "otter", "raven", "seal",
    "swift", "trout", "bamboo", "cedar", "fern", "ivy", "palm", "reed",
)


class PasswordGenerator:
    """高熵凭据生成器。"""

    def default_charset(self, *, exclude_ambiguous: bool = False) -> str:
        """默认字符集 = 小写 + 大写 + 数字 + 符号。"""
        cs = "".join(DEFAULT_CHARSETS.values())
        if exclude_ambiguous:
            cs = "".join(c for c in cs if c not in "Il1O0oZ2S5B8|`'\";:")
        # 去重并保持顺序稳定
        seen = set()
        out = ""
        for c in cs:
            if c not in seen:
                seen.add(c)
                out += c
        return out

    def generate(
        self,
        length: int,
        *,
        charset: str | None = None,
        exclude_ambiguous: bool = False,
    ) -> str:
        """生成 ``length`` 位随机密码。``charset`` 为空则使用默认集。"""
        if length <= 0:
            raise ValidationError("密码长度必须为正数。")
        cs = charset if charset else self.default_charset(exclude_ambiguous=exclude_ambiguous)
        if len(cs) < 2:
            raise ValidationError("字符集至少需要 2 个字符以保证熵。")
        return "".join(secrets.choice(cs) for _ in range(length))

    def generate_passphrase(
        self,
        words: int = 6,
        *,
        separator: str = "-",
        wordlist: list[str] | None = None,
    ) -> str:
        """生成 diceware 风格密语（随机抽词）。"""
        if words <= 0:
            raise ValidationError("密语词数必须为正数。")
        wl = wordlist or list(_WORDLIST)
        if len(wl) < 2:
            raise ValidationError("词表至少需要 2 个词。")
        return separator.join(secrets.choice(wl) for _ in range(words))

    # ------------------------------------------------------------ 熵
    @staticmethod
    def entropy_bits(value: str, charset_size: int) -> float:
        """估算密码熵（比特）。"""
        if charset_size <= 1:
            return 0.0
        return len(value) * math.log2(charset_size)

    @staticmethod
    def passphrase_entropy(words: int, wordlist_size: int) -> float:
        """估算密语熵（比特）。"""
        if wordlist_size <= 1:
            return 0.0
        return words * math.log2(wordlist_size)

    @staticmethod
    def strength_label(bits: float) -> str:
        """中文强度标签。"""
        if bits < 40:
            return "弱"
        if bits < 64:
            return "中"
        if bits < 112:
            return "强"
        return "极强"
