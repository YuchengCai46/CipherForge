"""内存安全基类与 SecureBytes 测试：覆盖登记、擦除、协议方法与平台原语。"""

import pytest

from cipherforge.core.memory import (
    SecureBytes,
    SecureMemoryBase,
    wipe_bytearray,
    constant_time_copy,
    lock_memory,
    unlock_memory,
)


def test_secure_bytes_from_bytes():
    sb = SecureBytes(b"secret")
    assert len(sb) == 6
    assert sb.to_bytes() == b"secret"
    sb.zeroize()
    assert len(sb) == 0


def test_secure_bytes_from_str():
    sb = SecureBytes("secret")
    assert sb.to_bytes() == b"secret"


def test_secure_bytes_random_and_zeros():
    sb = SecureBytes.random(16)
    assert len(sb) == 16
    sb2 = SecureBytes.zeros(8)
    assert len(sb2) == 8
    assert sb2.to_bytes() == b"\x00" * 8
    with pytest.raises(ValueError):
        SecureBytes.random(0)


def test_secure_bytes_read_protocol():
    sb = SecureBytes(b"abcd")
    assert sb.view()[:4] == b"abcd"
    assert sb.hex() == b"abcd".hex()
    assert sb[0] == ord("a")
    assert sb[1:3] == b"bc"
    assert list(sb) == [ord(c) for c in "abcd"]
    assert sb
    assert bytes(sb) == b"abcd"
    # 缓冲区协议
    mv = memoryview(sb)
    assert len(mv) == 4


def test_secure_bytes_repr_and_str():
    sb = SecureBytes(b"xyz")
    r = repr(sb)
    assert "SecureBytes" in r and "3" in r
    assert str(sb) == r
    sb.zeroize()
    assert "已擦除" in repr(sb)


def test_secure_bytes_eq():
    a = SecureBytes(b"same")
    b = SecureBytes(b"same")
    c = SecureBytes(b"diff")
    assert a == b
    assert a != c
    assert a == b"same"
    assert a != b"diff"
    # 已擦除比较
    a.zeroize()
    assert not (a == b)
    # 非字节类型返回 NotImplemented
    assert a.__eq__(object()) is NotImplemented
    with pytest.raises(TypeError):
        b.__hash__()  # SecureBytes.__hash__ 应抛 TypeError
    with pytest.raises(TypeError):
        hash(SecureBytes(b"x"))


def test_secure_bytes_transform():
    sb = SecureBytes(b"abc")
    sb.append(b"def")
    assert sb.to_bytes() == b"abcdef"
    s1, s2 = sb.split_at(3)
    assert s1.to_bytes() == b"abc" and s2.to_bytes() == b"def"
    with pytest.raises(ValueError):
        sb.split_at(99)
    sb.zeroize()


def test_secure_bytes_already_erased_read():
    sb = SecureBytes(b"x")
    sb.zeroize()
    with pytest.raises(ValueError):
        sb.view()
    with pytest.raises(ValueError):
        sb.to_bytes()
    with pytest.raises(ValueError):
        sb.hex()
    with pytest.raises(ValueError):
        sb[0]
    with pytest.raises(ValueError):
        list(sb)
    with pytest.raises(ValueError):
        sb.append(b"y")


def test_context_manager_guarantees_wipe():
    sb = SecureBytes(b"ctx")
    with sb as s:
        assert s.to_bytes() == b"ctx"
    assert len(sb) == 0  # 退出时擦除


def test_constant_time_copy():
    dst = bytearray(8)
    constant_time_copy(dst, b"abcdefgh", 0)
    assert dst == b"abcdefgh"
    with pytest.raises(ValueError):
        constant_time_copy(dst, b"xy", 7)  # 越界
    with pytest.raises(ValueError):
        constant_time_copy(dst, b"xyz", -1)


def test_wipe_bytearray_variants():
    # 正常擦除
    buf = bytearray(b"sensitive")
    wipe_bytearray(buf)
    assert buf == bytearray(len(buf))
    # 随机覆写关闭
    buf2 = bytearray(b"sensitive")
    wipe_bytearray(buf2, overwrite_random=False)
    assert buf2 == bytearray(len(buf2))
    # passes 夹取到 1~7
    buf3 = bytearray(b"x" * 10)
    wipe_bytearray(buf3, passes=100)
    # 空 / 非 bytearray 直接返回
    wipe_bytearray(bytearray())
    wipe_bytearray(b"not bytearray")  # type: ignore[arg-type]


def test_secure_memory_base_register_and_zeroize():
    base = SecureMemoryBase()
    with pytest.raises(TypeError):
        base._register(b"not bytearray")  # type: ignore[arg-type]
    buf = base._allocate(16)
    assert len(buf) == 16
    assert base._zeroized is False
    base.zeroize()
    assert base._zeroized is True
    # 幂等
    base.zeroize()
    assert repr(base)


def test_lock_unlock_memory(tmp_path=None):
    buf = bytearray(b"x" * 64)
    # 锁/解锁至少返回布尔；失败属"尽力而为"
    assert isinstance(lock_memory(buf), bool)
    assert isinstance(unlock_memory(buf), bool)
    # 空缓冲区返回 False
    assert lock_memory(bytearray()) is False
    assert unlock_memory(bytearray()) is False


def test_del_does_not_raise():
    sb = SecureBytes(b"del-test")
    import gc

    del sb
    gc.collect()
