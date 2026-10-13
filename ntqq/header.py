"""QQ NT 数据库容器头的解析。

QQ NT 生成的每个 ``nt_msg.db`` 风格文件都以一个固定的 1024 字节
*明文* 容器头开头，后面紧跟一个普通的 SQLCipher 数据库。
头部结构如下::

    0000  16  "SQLite header 3\\x00"        改写的 SQLite magic
    0010  16  flags                        (04 00 10 00 ...)
    0020   8  "QQ_NT DB"                   标记
    0028   4  后续 protobuf 的小端长度
    002c  ..  protobuf:
                field 2: 随机十六进制字符串（"rand"）
                field 3: 格式版本（例如 "1.1.0.1"）
                field 4: HMAC 算法（例如 "HMAC_SHA1"）
                field 5: varint 标志

SQLCipher 数据库从偏移 1024 处开始。它的前 16 字节是
KDF salt（同样镜像在 ``*-first.material`` /
``*-last.material`` 附属文件的起始处）。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from . import protobuf

HEADER_SIZE = 1024
MAGIC = b"SQLite header 3\x00"
MARKER = b"QQ_NT DB"


@dataclass
class QQHeader:
    raw: bytes
    flags: bytes
    rand: str
    version: str
    hmac_algorithm: str
    marker_length: int
    extra: list[protobuf.Field]

    @property
    def rand_bytes(self) -> bytes:
        try:
            return bytes.fromhex(self.rand)
        except ValueError:
            return b""


def parse_header(data: bytes) -> QQHeader:
    """解析 1024 字节的 QQ 容器头。"""
    if len(data) < HEADER_SIZE:
        raise ValueError("file is smaller than the 1024-byte QQ header")
    raw = data[:HEADER_SIZE]
    if raw[:16] != MAGIC:
        raise ValueError("not a QQ NT database: bad magic")
    marker_at = raw.find(MARKER)
    if marker_at < 0:
        raise ValueError("not a QQ NT database: missing QQ_NT DB marker")

    flags = raw[16:32]
    cursor = marker_at + len(MARKER)
    (marker_length,) = struct.unpack_from("<I", raw, cursor)
    cursor += 4

    body = raw[cursor : cursor + marker_length] if marker_length else raw[cursor:]
    fields: list[protobuf.Field] = []
    try:
        fields = protobuf.parse(body)
    except protobuf.ProtobufError:
        fields = []

    rand = ""
    version = ""
    hmac_algorithm = ""
    for fld in fields:
        text = protobuf.try_decode_utf8(fld.value) if fld.wire_type == 2 else None
        if fld.number == 2 and text is not None:
            rand = text
        elif fld.number == 3 and text is not None:
            version = text
        elif fld.number == 4 and text is not None:
            hmac_algorithm = text

    return QQHeader(
        raw=raw,
        flags=flags,
        rand=rand,
        version=version,
        hmac_algorithm=hmac_algorithm,
        marker_length=marker_length,
        extra=fields,
    )


def material_salt(path: str) -> bytes:
    """从 ``*-first.material`` 文件读取 16 字节的 SQLCipher salt。"""
    with open(path, "rb") as handle:
        return handle.read(16)
