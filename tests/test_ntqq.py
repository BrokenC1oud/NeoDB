"""ntqq 工具包的离线单元测试。

运行方式::

    python -m unittest discover -s tests -v

这里不需要真实的 QQ 数据库或已恢复的密钥；测试自行构造 protobuf 消息、
容器头和 SQLCipher 页。
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ntqq import header as header_mod
from ntqq import protobuf, sqlcipher
from ntqq.elements import decode_message_bodies
from ntqq.reader import unwrap_column, unwrap_columns

# ---------------------------------------------------------------------------
# protobuf
# ---------------------------------------------------------------------------


def _tag(number: int, wire: int) -> bytes:
    return protobuf.encode_varint((number << 3) | wire)


def _field_len(number: int, value: bytes) -> bytes:
    return _tag(number, protobuf.WIRE_LEN) + protobuf.encode_varint(len(value)) + value


def _field_varint(number: int, value: int) -> bytes:
    return _tag(number, protobuf.WIRE_VARINT) + protobuf.encode_varint(value)


class ProtobufTests(unittest.TestCase):
    def test_varint_round_trip(self):
        for value in (0, 1, 127, 128, 300, 2**31, 2**63 - 1):
            encoded = protobuf.encode_varint(value)
            decoded, offset = protobuf.read_varint(encoded, 0)
            self.assertEqual(decoded, value)
            self.assertEqual(offset, len(encoded))

    def test_parse_and_tree(self):
        inner = _field_varint(1, 7) + _field_len(2, b"hi")
        data = _field_len(100, inner) + _field_varint(101, 5)
        fields = protobuf.decode_tree(data)
        self.assertEqual([f.number for f in fields], [100, 101])
        self.assertIsNotNone(fields[0].message)
        self.assertEqual(fields[0].message[0].value, 7)
        self.assertEqual(fields[0].message[1].value, b"hi")
        self.assertEqual(fields[1].value, 5)

    def test_jsonable_keeps_everything(self):
        data = _field_len(1, b"\x00\x01\xff") + _field_varint(2, 9)
        encoded = protobuf.to_jsonable(protobuf.parse(data))
        self.assertEqual(encoded[0]["hex"], "0001ff")
        self.assertEqual(encoded[1]["value"], 9)

    def test_rejects_garbage(self):
        with self.assertRaises(protobuf.ProtobufError):
            protobuf.parse(b"\xff\xff\xff\xff")


# ---------------------------------------------------------------------------
# header
# ---------------------------------------------------------------------------


class HeaderTests(unittest.TestCase):
    def _build(self) -> bytes:
        body = _field_len(2, b"ab" * 64) + _field_len(3, b"1.1.0.1") + _field_len(4, b"HMAC_SHA1")
        raw = bytearray(header_mod.HEADER_SIZE)
        raw[0:16] = header_mod.MAGIC
        raw[16:32] = bytes.fromhex("04001000" + "00" * 12)
        raw[32:40] = header_mod.MARKER
        struct.pack_into("<I", raw, 40, len(body))
        raw[44 : 44 + len(body)] = body
        return bytes(raw)

    def test_parse(self):
        head = header_mod.parse_header(self._build())
        self.assertEqual(head.version, "1.1.0.1")
        self.assertEqual(head.hmac_algorithm, "HMAC_SHA1")
        self.assertEqual(head.rand, "ab" * 64)
        self.assertEqual(head.marker_length, len(head.rand) + 8 + 9 + 6)

    def test_rejects_bad_magic(self):
        with self.assertRaises(ValueError):
            header_mod.parse_header(b"\x00" * header_mod.HEADER_SIZE)


# ---------------------------------------------------------------------------
# sqlcipher
# ---------------------------------------------------------------------------


def _encrypt_page(pgno: int, keys: sqlcipher.Keys, content: bytes) -> bytes:
    """按 SQLCipher 的布局构造一个加密页。"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv = bytes(range(16))
    encryptor = Cipher(algorithms.AES(keys.enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(content) + encryptor.finalize()
    mac = hmac_mod.new(keys.hmac_key, ciphertext + iv + struct.pack("<I", pgno), "sha1").digest()
    return ciphertext + iv + mac + bytes(12)


class SqlcipherTests(unittest.TestCase):
    def setUp(self):
        self.keys = sqlcipher.keys_for(b"0123456789abcdef", bytes(range(16)))

    def test_key_derivation(self):
        enc = hashlib.pbkdf2_hmac("sha512", b"0123456789abcdef", bytes(range(16)), 4000, 32)
        self.assertEqual(self.keys.enc_key, enc)
        masked = bytes(b ^ 0x3A for b in bytes(range(16)))
        self.assertEqual(self.keys.hmac_key, hashlib.pbkdf2_hmac("sha512", enc, masked, 2, 32))

    def test_page_round_trip(self):
        content = os.urandom(sqlcipher.PAGE_SIZE - sqlcipher.RESERVE)
        page = _encrypt_page(2, self.keys, content)
        self.assertEqual(len(page), sqlcipher.PAGE_SIZE)
        self.assertTrue(sqlcipher.verify_page(page, 2, self.keys.hmac_key))
        plain = sqlcipher.decrypt_page(page, 2, self.keys.enc_key)
        self.assertEqual(plain[: len(content)], content)
        self.assertEqual(plain[len(content) :], bytes(sqlcipher.RESERVE))

    def test_page_hmac_is_bound_to_page_number(self):
        content = os.urandom(sqlcipher.PAGE_SIZE - sqlcipher.RESERVE)
        page = _encrypt_page(5, self.keys, content)
        self.assertTrue(sqlcipher.verify_page(page, 5, self.keys.hmac_key))
        self.assertFalse(sqlcipher.verify_page(page, 6, self.keys.hmac_key))

    def test_wrong_key_fails(self):
        content = os.urandom(sqlcipher.PAGE_SIZE - sqlcipher.RESERVE)
        page = _encrypt_page(3, self.keys, content)
        other = sqlcipher.keys_for(b"fedcba9876543210", bytes(range(16)))
        self.assertFalse(sqlcipher.verify_page(page, 3, other.hmac_key))

    def test_decrypt_wal(self):
        # 一个最小化的 WAL，仅含一个已提交帧，保存第 2 页。
        content = os.urandom(sqlcipher.PAGE_SIZE - sqlcipher.RESERVE)
        page = _encrypt_page(2, self.keys, content)
        wal_header = struct.pack(
            ">IIIIIIII",
            sqlcipher.WAL_MAGIC_BE,
            3007000,
            sqlcipher.PAGE_SIZE,
            1,
            1,
            2,
            0,
            0,
        )
        frame_header = struct.pack(">IIIIII", 2, 7, 1, 2, 0, 0)
        wal = wal_header + frame_header + page

        with tempfile.NamedTemporaryFile(suffix=".db-wal", delete=False) as handle:
            handle.write(wal)
            wal_path = handle.name
        try:
            pages, db_size = sqlcipher.decrypt_wal(wal_path, self.keys)
        finally:
            os.unlink(wal_path)
        self.assertEqual(db_size, 7)
        self.assertIn(2, pages)
        self.assertEqual(pages[2][: len(content)], content)

    def test_decrypt_wal_ignores_stale_generations(self):
        def frame(pgno, db_size, salt, content):
            page = _encrypt_page(pgno, self.keys, content)
            return struct.pack(">IIIIII", pgno, db_size, salt[0], salt[1], 0, 0) + page

        content = os.urandom(sqlcipher.PAGE_SIZE - sqlcipher.RESERVE)
        wal_header = struct.pack(
            ">IIIIIIII",
            sqlcipher.WAL_MAGIC_BE,
            3007000,
            sqlcipher.PAGE_SIZE,
            1,
            1,
            2,
            0,
            0,
        )
        wal = (
            wal_header
            + frame(2, 0, (1, 2), content)
            + frame(3, 5, (1, 2), content)
            + frame(4, 0, (9, 9), content)  # 过期代次：必须被忽略
        )
        with tempfile.NamedTemporaryFile(suffix=".db-wal", delete=False) as handle:
            handle.write(wal)
            wal_path = handle.name
        try:
            pages, db_size = sqlcipher.decrypt_wal(wal_path, self.keys)
        finally:
            os.unlink(wal_path)
        self.assertEqual(db_size, 5)
        self.assertEqual(set(pages), {2, 3})

    def test_apply_wal_truncates_to_committed_size(self):
        header = bytearray(sqlcipher.PAGE_SIZE)
        header[0:16] = sqlcipher.SQLITE_MAGIC
        header[28:32] = struct.pack(">I", 3)
        stale = bytes([0xAA]) * sqlcipher.PAGE_SIZE
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(bytes(header) + stale * 3)  # 共 4 页，头部声明 3 页
            path = handle.name
        try:
            new_page = bytes([0xBB]) * sqlcipher.PAGE_SIZE
            sqlcipher.apply_wal(path, {2: new_page}, db_size=3)
            data = Path(path).read_bytes()
            self.assertEqual(len(data), 3 * sqlcipher.PAGE_SIZE)
            self.assertEqual(data[28:32], struct.pack(">I", 3))
            self.assertEqual(data[sqlcipher.PAGE_SIZE : 2 * sqlcipher.PAGE_SIZE], new_page)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# 加密配置检测
# ---------------------------------------------------------------------------


def _build_container_header() -> bytes:
    body = _field_len(2, b"ab" * 64) + _field_len(3, b"1.1.0.1") + _field_len(4, b"HMAC_SHA1")
    raw = bytearray(header_mod.HEADER_SIZE)
    raw[0:16] = header_mod.MAGIC
    raw[16:32] = bytes.fromhex("04001000" + "00" * 12)
    raw[32:40] = header_mod.MARKER
    struct.pack_into("<I", raw, 40, len(body))
    raw[44 : 44 + len(body)] = body
    return bytes(raw)


def _encrypt_page_cfg(
    pgno: int, keys: sqlcipher.Keys, content: bytes, config: sqlcipher.CipherConfig
) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv = bytes(range(16))
    encryptor = Cipher(algorithms.AES(keys.enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(content) + encryptor.finalize()
    mac = hmac_mod.new(
        keys.hmac_key, ciphertext + iv + struct.pack("<I", pgno), config.hmac_prf
    ).digest()
    padding = bytes(config.reserve - sqlcipher.IV_SIZE - config.hmac_size)
    return ciphertext + iv + mac + padding


class CipherConfigTests(unittest.TestCase):
    PASSPHRASE = b"0123456789abcdef"

    def _build_db(self, config: sqlcipher.CipherConfig, pages: int = 2) -> bytes:
        salt = bytes(range(16, 32))
        keys = sqlcipher.keys_for(self.PASSPHRASE, salt, config)
        out = bytearray(_build_container_header())
        for pgno in range(1, pages + 1):
            skip = sqlcipher.SALT_SIZE if pgno == 1 else 0
            content = os.urandom(config.page_size - config.reserve - skip)
            page = _encrypt_page_cfg(pgno, keys, content, config)
            if pgno == 1:
                page = salt + page
            self.assertEqual(len(page), config.page_size)
            out += page
        return bytes(out)

    def test_reserve_is_derived_from_the_hmac_algorithm(self):
        self.assertEqual(sqlcipher.CipherConfig(hmac_prf="sha1").reserve, 48)
        self.assertEqual(sqlcipher.CipherConfig(hmac_prf="sha256").reserve, 48)
        self.assertEqual(sqlcipher.CipherConfig(hmac_prf="sha512").reserve, 80)
        self.assertEqual(sqlcipher.CipherConfig(hmac_prf="sha512").hmac_size, 64)

    def _detect(self, config: sqlcipher.CipherConfig):
        data = self._build_db(config)
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(data)
            path = handle.name
        try:
            return sqlcipher.detect_config(path, self.PASSPHRASE)
        finally:
            os.unlink(path)

    def test_detect_default_sha1(self):
        found = self._detect(sqlcipher.DEFAULT_CONFIG)
        self.assertIsNotNone(found)
        self.assertEqual(found.hmac_prf, "sha1")

    def test_detect_sha512(self):
        found = self._detect(sqlcipher.CipherConfig(hmac_prf="sha512"))
        self.assertIsNotNone(found)
        self.assertEqual(found.hmac_prf, "sha512")
        self.assertEqual(found.reserve, 80)

    def test_detect_rejects_wrong_key(self):
        data = self._build_db(sqlcipher.DEFAULT_CONFIG)
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(data)
            path = handle.name
        try:
            self.assertIsNone(sqlcipher.detect_config(path, b"wrong-passphrase"))
        finally:
            os.unlink(path)

    def test_sha512_page_round_trip(self):
        config = sqlcipher.CipherConfig(hmac_prf="sha512")
        salt = bytes(range(16, 32))
        keys = sqlcipher.keys_for(self.PASSPHRASE, salt, config)
        content = os.urandom(config.page_size - config.reserve)
        page = _encrypt_page_cfg(2, keys, content, config)
        self.assertEqual(len(page), config.page_size)
        self.assertTrue(sqlcipher.verify_page(page, 2, keys.hmac_key, config))
        plain = sqlcipher.decrypt_page(page, 2, keys.enc_key, config)
        self.assertEqual(plain[: len(content)], content)
        self.assertEqual(plain[len(content) :], bytes(config.reserve))


# ---------------------------------------------------------------------------
# reader 辅助函数
# ---------------------------------------------------------------------------


class ReaderTests(unittest.TestCase):
    def test_unwrap_column(self):
        inner = b"\x08\x01"
        wrapped = _field_len(40800, inner)
        self.assertEqual(unwrap_column(wrapped, 40800), inner)

    def test_unwrap_columns_returns_every_segment(self):
        """一条记录可以有多个同号字段（消息的正文/图片各占一个 40800）。"""
        wrapped = _field_len(40800, b"one") + _field_len(40800, b"two")
        self.assertEqual(unwrap_columns(wrapped, 40800), [b"one", b"two"])
        # 只取第一段的旧接口行为不变
        self.assertEqual(unwrap_column(wrapped, 40800), b"one")

    def test_decode_message_bodies_merges_segments(self):
        """多段消息体应合并为一个 MessageBody，元素不能只留第一段。"""
        first = protobuf.encode_varint((45002 << 3) | 0) + protobuf.encode_varint(1)
        first += _field_len(45101, "正文".encode())
        second = protobuf.encode_varint((45002 << 3) | 0) + protobuf.encode_varint(2)
        second += _field_len(45402, b"a.png")
        body = decode_message_bodies([first, second])
        kinds = sorted(element.kind for element in body.elements)
        self.assertEqual(kinds, ["media", "text"])
        self.assertIn("正文", body.text())

    def test_unwrap_column_falls_back(self):
        raw = b"not-a-wrapper"
        self.assertEqual(unwrap_column(raw, 40800), raw)
        self.assertIsNone(unwrap_column(None, 40800))


# ---------------------------------------------------------------------------
# 包级公开接口
# ---------------------------------------------------------------------------


class PublicApiTests(unittest.TestCase):
    """``__all__`` 里出现的每个名字都必须真实存在。

    否则 ``from ntqq import *`` 会抛 AttributeError（历史上就因为把一条
    分组注释误当成名字而踩过这个坑）。
    """

    def test_all_names_exist(self):
        import ntqq

        missing = [name for name in ntqq.__all__ if not hasattr(ntqq, name)]
        self.assertEqual(missing, [], "这些 __all__ 条目并不存在，请修正")

    def test_all_has_no_duplicates(self):
        import ntqq

        self.assertEqual(len(ntqq.__all__), len(set(ntqq.__all__)))

    def test_wildcard_import_works(self):
        namespace: dict[str, object] = {}
        # 这里就是要真的执行这条语句，验证它不会抛错
        exec("from ntqq import *", namespace)
        self.assertIn("QQNT", namespace)


if __name__ == "__main__":
    unittest.main(verbosity=2)
